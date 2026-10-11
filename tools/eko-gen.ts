// EKO fixture generator (docs/FORMAT.md, version 1, aarch64 Mach-O).
//
// Reads a linked image of the fixture program, takes every public function
// whose name starts with the prefix, and derives its EKO record from the
// standard tables the public rustc emitted for it:
//   frame word  from the __unwind_info FRAME-mode encoding (x19..x28 and
//               d8..d15 pairs below the frame record become an FP record,
//               first save slot 3, descending); other modes are skipped and
//               listed, they stay on the standard tables
//   handlers    one row per bl/blr in the function, keyed by return address,
//               decided exactly as Rust personality (gcc.rs) decides from the
//               LSDA call-site and action tables: no entry = terminate,
//               landing pad 0 = no row, action 0 or type filter 0 = cleanup,
//               any other filter = catch
// and writes them as one EKO chunk in assembly for global_asm!.
//
// Planted defects (tools/eh.ts uses them):
//   --plant wrong-pad   give each call the pad of the nearest call site with a
//                       different pad, so it lands in the wrong call site pad
//   --plant no-restore  clear the highest saved-register bit of every FP
//                       record, so that register is not restored
//
// Usage: bun tools/eko-gen.ts IMAGE OUT.s [--prefix _eh_] [--plant NAME]

export type Row = { ret: number; pad: number; action: number };
export type Rec = { name: string; start: bigint; length: number; frame: number; rows: Row[] };

const sysroot = Bun.spawnSync({ cmd: ["rustc", "--print", "sysroot"], stdout: "pipe" }).stdout.toString().trim();
export const llvm = `${sysroot}/lib/rustlib/aarch64-apple-darwin/bin`;
const BASE = 0x100000000n;

function out(cmd: string[]): string {
  const r = Bun.spawnSync({ cmd, stdout: "pipe", stderr: "pipe" });
  if (r.exitCode !== 0) throw new Error(`${cmd.join(" ")}: ${r.stderr.toString()}`);
  return r.stdout.toString();
}

/** Bytes of one section, with the address of the first byte. */
export function section(img: string, name: string): { addr: bigint; bytes: number[] } {
  let addr = -1n;
  const bytes: number[] = [];
  for (const l of out([`${llvm}/llvm-objdump`, "-s", `--section=${name}`, img]).split("\n")) {
    const m = l.match(/^ ([0-9a-f]+) ((?:[0-9a-f]{2,8} ?){1,4})/);
    if (!m) continue;
    if (addr < 0n) addr = BigInt(`0x${m[1]}`);
    for (const w of m[2].trim().split(" ")) for (let i = 0; i < w.length; i += 2) bytes.push(parseInt(w.slice(i, i + 2), 16));
  }
  return { addr, bytes };
}

/** Function start -> compact encoding, and the set of LSDA (function, lsda) pairs. */
export function unwindInfo(img: string) {
  const enc = new Map<bigint, number>();
  const lsda = new Map<bigint, bigint>();
  let inLsda = false;
  for (const l of out([`${llvm}/llvm-objdump`, "--unwind-info", img]).split("\n")) {
    if (/LSDA descriptors:/.test(l)) inLsda = true;
    else if (/Second level indices:/.test(l)) inLsda = false;
    const e = l.match(/function offset=0x([0-9a-f]+), encoding(?:\[\d+\])?=0x([0-9a-f]+)/);
    if (e) enc.set(BASE + BigInt(`0x${e[1]}`), parseInt(e[2], 16));
    const d = inLsda && l.match(/function offset=0x([0-9a-f]+), LSDA offset=0x([0-9a-f]+)$/);
    if (d) lsda.set(BASE + BigInt(`0x${d[1]}`), BASE + BigInt(`0x${d[2]}`));
  }
  return { enc, lsda };
}

/** Public text symbols with the prefix, by address. */
export function symbols(img: string, prefix: string): Map<string, bigint> {
  const m = new Map<string, bigint>();
  for (const l of out(["nm", img]).split("\n")) {
    const s = l.match(/^([0-9a-f]+) T (\S+)$/);
    if (s && s[2].startsWith(prefix)) m.set(s[2], BigInt(`0x${s[1]}`));
  }
  return m;
}

/** Instruction addresses of each function, and which of them are calls. */
function disasm(img: string, names: string[]) {
  const fns = new Map<string, { last: bigint; calls: bigint[] }>();
  let cur = "";
  const text = out([`${llvm}/llvm-objdump`, "-d", "--no-show-raw-insn", `--disassemble-symbols=${names.join(",")}`, img]);
  for (const l of text.split("\n")) {
    const h = l.match(/^[0-9a-f]+ <(\S+)>:$/);
    if (h) { cur = h[1]; fns.set(cur, { last: 0n, calls: [] }); continue; }
    const i = l.match(/^\s*([0-9a-f]+):\s+(\S+)/);
    if (!i || !cur) continue;
    const a = BigInt(`0x${i[1]}`);
    const f = fns.get(cur)!;
    f.last = a;
    if (i[2] === "bl" || i[2] === "blr") f.calls.push(a);
  }
  return fns;
}

function uleb(b: number[], p: { o: number }): number {
  let v = 0, s = 0, x = 0;
  do { x = b[p.o++]; v += (x & 0x7f) * 2 ** s; s += 7; } while (x & 0x80);
  return v;
}
function sleb(b: number[], p: { o: number }): number {
  let v = 0, s = 0, x = 0;
  do { x = b[p.o++]; v += (x & 0x7f) * 2 ** s; s += 7; } while (x & 0x80);
  if (x & 0x40) v -= 2 ** s;
  return v;
}
function encoded(b: number[], p: { o: number }, enc: number): number {
  if (enc === 0x01) return uleb(b, p);
  if (enc === 0x03) { const v = b[p.o] | (b[p.o + 1] << 8) | (b[p.o + 2] << 16) | (b[p.o + 3] * 2 ** 24); p.o += 4; return v >>> 0; }
  throw new Error(`call-site encoding 0x${enc.toString(16)} not handled`);
}

/** LSDA call-site entries and the action each landing pad gets (0 cleanup, 1 catch). */
export function lsdaSites(tab: { addr: bigint; bytes: number[] }, at: bigint) {
  const b = tab.bytes;
  const p = { o: Number(at - tab.addr) };
  const start = p.o;
  const lpEnc = b[p.o++];
  if (lpEnc !== 0xff) throw new Error("LSDA with an explicit lpstart");
  const ttEnc = b[p.o++];
  if (ttEnc !== 0xff) uleb(b, p);
  const csEnc = b[p.o++];
  const csLen = uleb(b, p);
  const csEnd = p.o + csLen;
  const sites: { start: number; len: number; pad: number; action: number }[] = [];
  while (p.o < csEnd) {
    const s = encoded(b, p, csEnc), len = encoded(b, p, csEnc), pad = encoded(b, p, csEnc);
    const ae = uleb(b, p);
    let action = 0;
    if (ae !== 0) action = sleb(b, { o: csEnd + ae - 1 }) === 0 ? 0 : 1;
    sites.push({ start: s, len, pad, action });
  }
  return { sites, offset: start };
}

/** Rows for one function, as Rust personality would decide each call. */
function rows(calls: bigint[], fn: bigint, sites: ReturnType<typeof lsdaSites>["sites"]): Row[] {
  const r: Row[] = [];
  for (const c of calls) {
    const ret = Number(c - fn) + 4;
    const ip = ret - 1;
    const s = sites.find((x) => x.start <= ip && ip < x.start + x.len);
    if (!s) r.push({ ret, pad: 0, action: 2 });
    else if (s.pad !== 0) r.push({ ret, pad: s.pad, action: s.action });
  }
  return r;
}

/** Compact FRAME encoding to an FP frame word; null for any other mode. */
export function frameWord(enc: number): number | null {
  if (((enc >>> 24) & 0xf) !== 4) return null;
  let mask = 0;
  for (let k = 0; k < 5; k++) if (enc & (1 << k)) mask |= 3 << (2 * k);
  for (let j = 0; j < 4; j++) if (enc & (0x100 << j)) mask |= 3 << (10 + 2 * j);
  return (1 | (mask << 3) | (3 << 21)) >>> 0;
}

type Fde = { start: bigint; end: bigint; lsda: bigint | null; rows: { at: bigint; cfa: string; regs: Map<number, number> }[] };

/** FDEs of __eh_frame with their unwind row tables, by function start. */
export function fdes(img: string): Map<bigint, Fde> {
  const m = new Map<bigint, Fde>();
  let cur: Fde | null = null;
  for (const l of out([`${llvm}/llvm-objdump`, "--dwarf=frames", img]).split("\n")) {
    const h = l.match(/^[0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8} (FDE|CIE)(?: cie=[0-9a-f]+ pc=([0-9a-f]+)\.\.\.([0-9a-f]+))?/);
    if (h) {
      cur = h[1] === "FDE" ? { start: BigInt(`0x${h[2]}`), end: BigInt(`0x${h[3]}`), lsda: null, rows: [] } : null;
      if (cur) m.set(cur.start, cur);
      continue;
    }
    if (!cur) continue;
    const a = l.match(/LSDA Address: ([0-9a-f]+)/);
    if (a) cur.lsda = BigInt(`0x${a[1]}`);
    const r = l.match(/^\s+0x([0-9a-f]+): CFA=(\S+?)(?::|$)(.*)/);
    if (r) {
      const regs = new Map<number, number>();
      for (const x of r[3].matchAll(/reg(\d+)=\[CFA([+-]\d+)\]/g)) regs.set(Number(x[1]), Number(x[2]));
      cur.rows.push({ at: BigInt(`0x${r[1]}`), cfa: r[2], regs });
    }
  }
  return m;
}

/**
 * FP frame word from the CFI row in effect at every call, or a reason why
 * none fits: the CFA must be x29 + 16 with x29 and x30 in slots 2 and 1, the
 * other saved registers (x19..x28, d8..d15 as DWARF 72..79) in consecutive
 * slots from 3 in mask-bit order or its reverse, and every call must see the
 * same row.
 */
export function frameFromCfi(f: Fde, calls: bigint[]): number | string {
  let key = "";
  let word = 0;
  for (const c of calls) {
    const row = [...f.rows].reverse().find((r) => r.at <= c);
    if (!row) return "no CFI row at a call";
    if (row.cfa !== "reg29+16") return `CFA ${row.cfa} at a call`;
    if (row.regs.get(29) !== -16 || row.regs.get(30) !== -8) return "frame record not at CFA-16";
    const saved: [number, number][] = [];
    for (const [reg, off] of row.regs) {
      if (reg === 29 || reg === 30) continue;
      const bit = reg >= 19 && reg <= 28 ? reg - 19 : reg >= 72 && reg <= 79 ? reg - 62 : -1;
      if (bit < 0) return `reg${reg} saved`;
      saved.push([bit, -off / 8]);
    }
    saved.sort((x, y) => x[0] - y[0]);
    const slots = saved.map((s) => s[1]);
    const asc = slots.every((s, i) => s === 3 + i);
    const desc = slots.every((s, i) => s === 3 + slots.length - 1 - i);
    if (slots.length && !asc && !desc) return `saved slots ${slots.join(",")}`;
    let mask = 0;
    for (const [bit] of saved) mask |= 1 << bit;
    const order = slots.length && !asc ? 1 : 0;
    const w = (1 | (order << 2) | (mask << 3) | (3 << 21)) >>> 0;
    const k = w.toString(16);
    if (key && key !== k) return "different rows at different calls";
    key = k;
    word = w;
  }
  return key ? word : "no calls";
}

export function derive(img: string, prefix = "_eh_") {
  const syms = symbols(img, prefix);
  const { enc, lsda } = unwindInfo(img);
  const tab = section(img, "__gcc_except_tab");
  const code = disasm(img, [...syms.keys()]);
  const fde = fdes(img);
  const recs: Rec[] = [];
  const skipped: string[] = [];
  for (const [name, start] of syms) {
    const e = enc.get(start);
    const c = code.get(name);
    const f = fde.get(start);
    if (!c || e === undefined) { skipped.push(`${name}: no __unwind_info entry`); continue; }
    // Compact FRAME mode, else the DWARF FDE the compact entry points to.
    let fw: number | string = frameWord(e) ?? "not FRAME mode";
    if (typeof fw === "string" && ((e >>> 24) & 0xf) === 3 && f) fw = frameFromCfi(f, c.calls);
    if (typeof fw === "string") { skipped.push(`${name}: ${fw} (encoding 0x${e.toString(16)})`); continue; }
    const l = f?.lsda ?? lsda.get(start);
    const rs = l == null ? [] : rows(c.calls, start, lsdaSites(tab, l).sites);
    const length = f ? Number(f.end - f.start) : Number(c.last - start) + 4;
    recs.push({ name, start, length, frame: fw, rows: rs });
  }
  recs.sort((a, b) => (a.start < b.start ? -1 : 1));
  return { recs, skipped };
}

export function plant(recs: Rec[], name: string): string {
  if (name === "wrong-pad") {
    let n = 0;
    for (const r of recs) {
      const live = r.rows.filter((x) => x.pad !== 0);
      const pads = live.map((x) => x.pad);
      if (new Set(pads).size < 2) continue;
      // Each call takes the pad of the nearest call site (before it, else
      // after it) whose pad differs: the pad of the wrong call site.
      const orig = live.map((x) => ({ pad: x.pad, action: x.action }));
      live.forEach((x, i) => {
        let j = -1;
        for (let k = i - 1; k >= 0 && j < 0; k--) if (orig[k].pad !== orig[i].pad) j = k;
        for (let k = i + 1; k < live.length && j < 0; k++) if (orig[k].pad !== orig[i].pad) j = k;
        x.pad = orig[j].pad;
        x.action = orig[j].action;
      });
      n++;
    }
    return `wrong-pad: each call given the pad of another call site in ${n} functions`;
  }
  if (name === "no-restore") {
    let n = 0;
    for (const r of recs) {
      const mask = (r.frame >>> 3) & 0x3ffff;
      if (!mask) continue;
      const top = 31 - Math.clz32(mask);
      r.frame = (r.frame & ~(1 << (3 + top))) >>> 0;
      n++;
    }
    return `no-restore: highest saved register dropped from ${n} FP records`;
  }
  throw new Error(`unknown plant ${name}`);
}

export function emit(recs: Rec[]): string {
  const s: string[] = [
    "// Generated by tools/eko-gen.ts. EKO chunk, version 1, aarch64.",
    "    .section __TEXT,__eko_unwind,regular,no_dead_strip",
    "    .p2align 2",
    "Lk_chunk:",
    "    .long 0x57554b45",
    "    .byte 1",
    "    .byte 1",
    "    .short 1",
    `    .long ${recs.length}`,
    "    .long Lk_end - Lk_chunk",
  ];
  recs.forEach((r, i) => {
    s.push(`Lk_r${i}:`, `    .long ${r.name} - Lk_r${i}`, `    .long ${r.length}`, `    .long 0x${r.frame.toString(16).padStart(8, "0")}`);
    s.push(r.rows.length ? `    .long Lk_h${i} - Lk_chunk` : "    .long 0");
  });
  recs.forEach((r, i) => {
    if (!r.rows.length) return;
    s.push(`Lk_h${i}:`, `    .long ${r.rows.length}`);
    for (const x of [...r.rows].sort((a, b) => a.ret - b.ret)) s.push(`    .long ${x.ret}, ${x.pad}, ${x.action}`);
  });
  s.push("Lk_end:", "");
  return s.join("\n");
}

/** Decode the __eko_unwind chunks of a linked image into records. */
export function decode(img: string): Rec[] {
  const { addr, bytes } = section(img, "__eko_unwind");
  const u32 = (o: number) => (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0;
  const recs: Rec[] = [];
  for (let c = 0; c + 16 <= bytes.length; ) {
    if (u32(c) === 0) { c += 4; continue; }
    if (u32(c) !== 0x57554b45) throw new Error(`bad EKO header at +${c}`);
    const count = u32(c + 8), size = u32(c + 12);
    for (let i = 0; i < count; i++) {
      const r = c + 16 + 16 * i;
      const start = addr + BigInt(r) + BigInt(u32(r) | 0);
      const h = u32(r + 12);
      const rs: Row[] = [];
      if (h) for (let k = 0, n = u32(c + h); k < n; k++) { const o = c + h + 4 + 12 * k; rs.push({ ret: u32(o), pad: u32(o + 4), action: u32(o + 8) }); }
      recs.push({ name: "", start, length: u32(r + 4), frame: u32(r + 8), rows: rs });
    }
    c += size;
  }
  return recs;
}

/** Bytes the chunk takes: header, records, handler tables. */
export const ekoBytes = (recs: Rec[]) => 16 + recs.reduce((n, r) => n + 16 + (r.rows.length ? 4 + 12 * r.rows.length : 0), 0);

if (import.meta.main) {
  const [img, dst] = process.argv.slice(2);
  const pi = process.argv.indexOf("--prefix");
  const pl = process.argv.indexOf("--plant");
  const { recs, skipped } = derive(img, pi > 0 ? process.argv[pi + 1] : "_eh_");
  if (pl > 0) console.log(plant(recs, process.argv[pl + 1]));
  await Bun.write(dst, emit(recs));
  const rows = recs.reduce((n, r) => n + r.rows.length, 0);
  console.log(`eko-gen: ${recs.length} records, ${rows} handler rows, ${ekoBytes(recs)} bytes -> ${dst}`);
  for (const s of skipped) console.log(`  skipped, stays on the standard tables: ${s}`);
}
