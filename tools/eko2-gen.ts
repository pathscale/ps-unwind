// EKO version 2 generator (docs/FORMAT.md, "Version 2"). Reads a linked
// image (Mach-O arm64, ELF aarch64 or ELF x86_64) and derives, for each
// function it selects, the v2 state program from the function .eh_frame
// FDE rows and the handler rows from its LSDA, decided exactly as Rust
// personality decides (the rules of tools/eko-gen.ts):
//   state program  every CFI row of the FDE, at every instruction: CFA rule,
//                  return address and saved registers. Rows the format does
//                  not express (a CFA on another register, a rule that is not
//                  [CFA-8n], undefined or expression rules, GNU ops other
//                  than DW_CFA_GNU_args_size, args_size together with
//                  remember_state, an op llvm-objdump prints without a
//                  name that the raw bytes do not show to be args_size)
//                  leave the function
//                  on the standard tables; it is listed as skipped
//   handlers       one row per call, keyed by return address: no LSDA entry
//                  = terminate, landing pad 0 = no row, action 0 or type
//                  filter 0 = cleanup, any other filter = catch
//
// Output: assembly for global_asm! (Mach-O section __TEXT,__eko_unwind or an
// ELF note in .note.eko_unwind), or with --blob a raw chunk for a table-only
// check of every FDE in the image (records relative to a chosen address).
//
// Planted defects (tools/eko2.ts and tools/signal-check.ts use them):
//   wrong-cfa[:FN]   the first state change after the entry of FN (default:
//                    the first function with one) gets CFA + 16
//   drop-state[:FN]  the first state change after the entry of FN is dropped
//   wrong-args[:FN]  the first state of FN with a DW_CFA_GNU_args_size > 0
//                    gets 8 more bytes
//   wrong-pad        each call gets the pad of another call site
//   no-restore       the highest callee-saved register is never saved
//
// Usage: bun tools/eko2-gen.ts IMAGE OUT [--prefix eh_] [--all] [--blob]
//                              [--plant NAME]
import { lsdaSites, unwindInfo } from "./eko-gen.ts";

const sysroot = Bun.spawnSync({ cmd: ["rustc", "--print", "sysroot"], stdout: "pipe" }).stdout.toString().trim();
export const llvm = `${sysroot}/lib/rustlib/aarch64-apple-darwin/bin`;

function out(cmd: string[]): string {
  const r = Bun.spawnSync({ cmd, stdout: "pipe", stderr: "pipe", maxBuffer: 1 << 30 });
  if (r.exitCode !== 0) throw new Error(`${cmd.join(" ")}: ${r.stderr.toString()}`);
  return r.stdout.toString();
}

export type Arch = { code: number; unit: number; sp: number; fp: number; ra: number; entryCfa: number; entryRaSlot: number; calls: RegExp };
export const AARCH64: Arch = { code: 1, unit: 4, sp: 31, fp: 29, ra: 30, entryCfa: 0, entryRaSlot: 0, calls: /^(bl|blr)$/ };
export const X86_64: Arch = { code: 2, unit: 1, sp: 7, fp: 6, ra: 16, entryCfa: 1, entryRaSlot: 1, calls: /^call/ };

export type Img = { path: string; macho: boolean; arch: Arch; prefix: string };
export function image(path: string): Img {
  const h = out([`${llvm}/llvm-objdump`, "-h", path]);
  const f = h.match(/file format (\S+ ?\S*)/)?.[1] ?? "";
  if (f.startsWith("mach-o arm64")) return { path, macho: true, arch: AARCH64, prefix: "_" };
  if (f.startsWith("elf64-littleaarch64")) return { path, macho: false, arch: AARCH64, prefix: "" };
  if (f.startsWith("elf64-x86-64")) return { path, macho: false, arch: X86_64, prefix: "" };
  throw new Error(`${path}: unsupported format ${f}`);
}

/** Bytes of one section and the address of its first byte. */
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

/** An unwind state: CFA = (fp ? FP : SP) + 8 * units, reg at CFA - 8 * slot,
 * args = DW_CFA_GNU_args_size in bytes (0 when none). */
export type St = { fp: boolean; units: number; regs: Map<number, number>; args: number };
export const entry = (a: Arch): St => ({ fp: false, units: a.entryCfa, regs: a.entryRaSlot ? new Map([[a.ra, a.entryRaSlot]]) : new Map(), args: 0 });
export const show = (a: Arch, s: St) => {
  const r = [...s.regs].sort((x, y) => x[0] - y[0]).map(([k, v]) => `reg${k}=[CFA-${8 * v}]`);
  return `CFA=reg${s.fp ? a.fp : a.sp}+${8 * s.units}${r.length ? `: ${r.join(", ")}` : ""}${s.args ? ` args=${s.args}` : ""}`;
};
const same = (a: St, b: St) => a.fp === b.fp && a.units === b.units && a.args === b.args && a.regs.size === b.regs.size && [...a.regs].every(([k, v]) => b.regs.get(k) === v);

export type Fde = { start: bigint; end: bigint; lsda: bigint | null; len: number; rows: { at: bigint; text: string }[]; ops: string[]; args: { at: bigint; n: number }[] };

/** FDEs of .eh_frame / __eh_frame (not .debug_frame), by function start. */
export function fdes(img: string): Map<bigint, Fde> {
  const m = new Map<bigint, Fde>();
  let cur: Fde | null = null;
  let inEh = false;
  let pc = 0n;
  // CIE augmentation by section offset; FDE section offset and CIE offset;
  // ops llvm-objdump prints without a name, by FDE.
  const cies = new Map<number, { aug: string; data: number[] }>();
  let cie: { aug: string; data: number[] } | null = null;
  const where = new Map<Fde, { off: number; cie: number }>();
  const unnamed = new Map<Fde, { idx: number; at: bigint; text: string }[]>();
  for (const l of out([`${llvm}/llvm-objdump`, "--dwarf=frames", img]).split("\n")) {
    if (/^\.(\S+) contents:$/.test(l)) { inEh = l.startsWith(".eh_frame"); cur = null; continue; }
    if (!inEh) continue;
    const h = l.match(/^([0-9a-f]{8}) ([0-9a-f]{8}) [0-9a-f]{8} (FDE|CIE)(?: cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.\.([0-9a-f]+))?/);
    if (h) {
      cur = h[3] === "FDE" ? { start: BigInt(`0x${h[5]}`), end: BigInt(`0x${h[6]}`), lsda: null, len: parseInt(h[2], 16) + 4, rows: [], ops: [], args: [] } : null;
      cie = null;
      if (cur) { m.set(cur.start, cur); where.set(cur, { off: parseInt(h[1], 16), cie: parseInt(h[4], 16) }); }
      else { cie = { aug: "", data: [] }; cies.set(parseInt(h[1], 16), cie); }
      if (cur) pc = cur.start;
      continue;
    }
    if (cie) {
      const s = l.match(/^\s+Augmentation:\s+"(.*)"$/);
      if (s) cie.aug = s[1];
      const d = l.match(/^\s+Augmentation data:\s+((?:[0-9A-Fa-f]{2} ?)*)$/);
      if (d) cie.data = d[1].trim().split(" ").filter((x) => x).map((x) => parseInt(x, 16));
      continue;
    }
    if (!cur) continue;
    const a = l.match(/LSDA Address: ([0-9a-f]+)/);
    if (a) cur.lsda = BigInt(`0x${a[1]}`);
    const o = l.match(/^\s+(DW_CFA_\w+)/);
    if (o) cur.ops.push(o[1]);
    // An op the printer has no name for on this architecture (aarch64
    // prints DW_CFA_GNU_args_size as ": +N"): resolved from the raw bytes
    // below, refused by states() if it is not args_size.
    const u = l.match(/^\s+: (.*)$/);
    if (u) {
      if (!unnamed.has(cur)) unnamed.set(cur, []);
      unnamed.get(cur)!.push({ idx: cur.ops.length, at: pc, text: u[1] });
      cur.ops.push("unnamed");
    }
    const to = l.match(/^\s+DW_CFA_\w+: .* to 0x([0-9a-f]+)$/);
    if (to) pc = BigInt(`0x${to[1]}`);
    const g = l.match(/^\s+DW_CFA_GNU_args_size: \+?(\d+)$/);
    if (g) cur.args.push({ at: pc, n: Number(g[1]) });
    const r = l.match(/^\s+0x([0-9a-f]+): (CFA=.*)$/);
    if (r) cur.rows.push({ at: BigInt(`0x${r[1]}`), text: r[2] });
  }
  if (unnamed.size) {
    const eh = section(img, image(img).macho ? "__eh_frame" : ".eh_frame").bytes;
    for (const [f, list] of unnamed) {
      const w = where.get(f)!;
      const ops = rawOps(eh, w.off, cies.get(w.cie));
      for (const x of list) {
        const op = ops?.[x.idx];
        if (op && op.code === 0x2e && x.text === `+${op.arg}`) {
          f.ops[x.idx] = "DW_CFA_GNU_args_size";
          f.args.push({ at: x.at, n: op.arg });
        }
      }
      f.args.sort((p, q) => (p.at < q.at ? -1 : p.at > q.at ? 1 : 0));
    }
  }
  return m;
}

/** The CFA instructions of the FDE at section offset `off` as opcode and
 * first operand (uleb operands only), in order, nops included; null when
 * the CIE augmentation or an op is not understood. */
function rawOps(eh: number[], off: number, cie: { aug: string; data: number[] } | undefined): { code: number; arg: number }[] | null {
  if (!cie || !cie.aug.startsWith("z")) return null;
  let r = 0;
  let k = 0;
  for (const c of cie.aug.slice(1)) {
    if (c === "P") { const e = cie.data[k++]; k += encSize(e) ?? 99; }
    else if (c === "L") k++;
    else if (c === "R") r = cie.data[k++];
    else if (c !== "S" && c !== "B") return null;
  }
  const ptr = encSize(r);
  if (ptr === null) return null;
  const u32 = (i: number) => (eh[i] | (eh[i + 1] << 8) | (eh[i + 2] << 16) | (eh[i + 3] << 24)) >>> 0;
  const end = off + 4 + u32(off);
  let p = off + 8 + 2 * ptr;
  const uleb = () => { let v = 0, s = 0, b; do { b = eh[p++]; v += (b & 0x7f) * 2 ** s; s += 7; } while (b & 0x80); return v; };
  const augLen = uleb();
  p += augLen;
  const skip = (n: number) => { p += n; return 0; };
  const res: { code: number; arg: number }[] = [];
  const size: Record<number, string> = { 0x00: "", 0x02: "1", 0x03: "2", 0x04: "4", 0x05: "uu", 0x06: "u", 0x07: "u", 0x08: "u", 0x09: "uu", 0x0a: "", 0x0b: "", 0x0c: "uu", 0x0d: "u", 0x0e: "u", 0x0f: "b", 0x10: "ub", 0x11: "uu", 0x12: "uu", 0x13: "u", 0x14: "uu", 0x15: "uu", 0x16: "ub", 0x2d: "", 0x2e: "u", 0x2f: "uu" };
  while (p < end) {
    const c = eh[p++];
    if (c & 0xc0) { res.push({ code: c & 0xc0, arg: 0 }); if ((c & 0xc0) === 0x80) uleb(); continue; }
    const form = size[c];
    if (form === undefined) return null;
    let first = -1;
    for (const f of form) {
      // sleb operands are skipped as ulebs: only the length matters here.
      const v = f === "u" ? uleb() : f === "b" ? skip(uleb()) : skip(Number(f));
      if (first < 0) first = v;
    }
    res.push({ code: c, arg: first });
  }
  return res;
}

/** Bytes of a DW_EH_PE value of this encoding, or null. */
function encSize(e: number): number | null {
  const s: Record<number, number> = { 0x00: 8, 0x02: 2, 0x03: 4, 0x04: 8, 0x0a: 2, 0x0b: 4, 0x0c: 8 };
  return s[e & 0x0f] ?? null;
}

/** Parse one llvm-objdump row into a state, or the reason it is not expressible. */
export function parseRow(a: Arch, text: string): St | string {
  const m = text.match(/^CFA=reg(\d+)([+-]\d+)?(?::\s*(.*))?$/);
  if (!m) return `CFA rule ${text}`;
  const base = Number(m[1]), off = Number(m[2] ?? "0");
  if (base !== a.sp && base !== a.fp) return `CFA on reg${base}`;
  if (off < 0 || off % 8) return `CFA offset ${off}`;
  const s: St = { fp: base === a.fp && base !== a.sp, units: off / 8, regs: new Map(), args: 0 };
  for (const part of (m[3] ?? "").split(", ").filter((x) => x)) {
    const sv = part.match(/^reg(\d+)=same$/);
    if (sv) continue;
    const p = part.match(/^reg(\d+)=\[CFA-(\d+)\]$/);
    if (!p) return `rule ${part}`;
    const k = Number(p[2]);
    if (k === 0 || k % 8) return `rule ${part}`;
    s.regs.set(Number(p[1]), k / 8);
  }
  return s;
}

/** States of an FDE as [offset, state], merged, or the reason none fits. */
export function states(a: Arch, f: Fde): [number, St][] | string {
  for (const op of f.ops) if (/negate_ra|expression|val_|^DW_CFA_register$|^DW_CFA_GNU_(?!args_size$)|undefined|^unnamed$/.test(op)) return op === "unnamed" ? "an op llvm-objdump does not name" : op;
  if (f.args.length && f.ops.some((op) => /remember_state|restore_state/.test(op))) return "DW_CFA_GNU_args_size with DW_CFA_remember_state";
  const rows: [number, St][] = [];
  for (const r of f.rows) {
    const at = Number(r.at - f.start);
    if (at % a.unit) return `row at +0x${at.toString(16)} not on a code unit`;
    const s = parseRow(a, r.text);
    if (typeof s === "string") return s;
    if (rows.length && same(rows[rows.length - 1][1], s)) continue;
    if (rows.length && rows[rows.length - 1][0] === at) rows.pop();
    rows.push([at, s]);
  }
  for (const x of f.args) if (Number(x.at - f.start) % a.unit) return `args_size at +0x${(x.at - f.start).toString(16)} not on a code unit`;
  return withArgs(a, f, rows);
}

/** Rows with the DW_CFA_GNU_args_size in effect at each offset folded into
 * the state (it changes without a new CFI row), merged again. */
export function withArgs(a: Arch, f: Fde, rows: [number, St][]): [number, St][] {
  if (!f.args.length) return rows;
  const args = f.args.map((x) => [Number(x.at - f.start), x.n] as [number, number]);
  const pts = [...new Set([...rows.map(([o]) => o), ...args.map(([o]) => o)])].sort((x, y) => x - y);
  const res: [number, St][] = [];
  for (const p of pts) {
    let s = entry(a);
    for (const [o, x] of rows) if (o <= p) s = x;
    let n = 0;
    for (const [o, v] of args) if (o <= p) n = v;
    const st = { ...s, args: n };
    if (res.length && same(res[res.length - 1][1], st)) continue;
    if (res.length && res[res.length - 1][0] === p) res.pop();
    res.push([p, st]);
  }
  return res;
}

const uleb = (v: number): number[] => {
  const b: number[] = [];
  do { let x = v % 128; v = Math.floor(v / 128); if (v) x |= 0x80; b.push(x); } while (v);
  return b;
};

/** Ops that take state a to state b: the shortest of a plain delta and a
 * delta after FRAME or FRAME_REGS when those fit b. */
function delta(arch: Arch, a: St, b: St): number[] {
  const best = [plain(arch, a, b)];
  if (b.regs.get(arch.fp) === 2 && b.regs.get(arch.ra) === 1) {
    const regs = new Map(a.regs).set(arch.fp, 2).set(arch.ra, 1);
    best.push([0xca, ...plain(arch, { ...a, regs }, b)]);
    if (b.fp && b.units === 2) best.push([0xc9, ...plain(arch, { fp: true, units: 2, regs, args: a.args }, b)]);
  }
  return best.reduce((x, y) => (y.length < x.length ? y : x));
}

function plain(arch: Arch, a: St, b: St): number[] {
  const o: number[] = [];
  if (a.args !== b.args) o.push(0xcb, ...uleb(b.args));
  if (a.fp !== b.fp) o.push(b.fp ? 0xc1 : 0xc0, ...uleb(b.units));
  else if (a.units !== b.units) o.push(...(b.units <= 63 ? [0x40 | b.units] : [0xc2, ...uleb(b.units)]));
  const cur = new Map(a.regs);
  const regs = [...new Set([...a.regs.keys(), ...b.regs.keys()])].sort((x, y) => x - y);
  for (const r of regs) {
    if (cur.has(r) && !b.regs.has(r)) {
      o.push(...(r < 32 ? [0xe0 | r] : [0xc5, ...uleb(r)]));
      cur.delete(r);
      if (r === arch.ra && arch.entryRaSlot) cur.set(r, arch.entryRaSlot);
    }
  }
  for (const r of regs) {
    if (b.regs.has(r) && cur.get(r) !== b.regs.get(r)) o.push(...(r < 64 ? [0x80 | r, ...uleb(b.regs.get(r)!)] : [0xc4, ...uleb(r), ...uleb(b.regs.get(r)!)]));
  }
  return o;
}

/** State program for the merged rows, END included. */
export function program(arch: Arch, rows: [number, St][]): number[] {
  const o: number[] = [];
  let cur = entry(arch), at = 0;
  const stack: St[] = [];
  rows.forEach(([off, s], i) => {
    if (off > at) {
      let n = (off - at) / arch.unit;
      o.push(...(n <= 63 ? [n] : [0xc3, ...uleb(n)]));
      at = off;
    }
    if (same(cur, s)) return;
    // Remember the state being left when the program comes back to it right
    // after a return (the entry state), as after an epilogue in the middle
    // of a function, and a plain delta back would cost more than one byte.
    const back = rows.findIndex(([, x], j) => j > i && same(x, cur) && same(rows[j - 1][1], entry(arch)));
    if (back > 0 && !(stack.length && same(stack[stack.length - 1], cur)) && delta(arch, entry(arch), cur).length > 1 && stack.length < 4) {
      o.push(0xc7);
      stack.push(cur);
    }
    const options: number[][] = [delta(arch, cur, s), [0xc6, ...delta(arch, entry(arch), s)]];
    const top = stack[stack.length - 1];
    if (top) options.push([0xc8, ...delta(arch, top, s)]);
    let best = 0;
    options.forEach((x, k) => { if (x.length < options[best].length) best = k; });
    if (best === 2) stack.pop();
    o.push(...options[best]);
    cur = s;
  });
  o.push(0);
  return o;
}

export type Row = { ret: number; pad: number; action: number };
export const table = (rows: Row[]): number[] => {
  const o = uleb(rows.length);
  let prev = 0;
  for (const r of [...rows].sort((x, y) => x.ret - y.ret)) { o.push(...uleb(r.ret - prev), ...uleb(r.pad * 4 + r.action)); prev = r.ret; }
  return o;
};

export type Fn2 = { name: string; start: bigint; length: number; rows: [number, St][]; handlers: Row[]; fde: Fde };

/** Return addresses of the calls in each function, by function start. */
function calls(img: Img, starts: Map<bigint, bigint>, symbolsOnly: string[] | null): Map<bigint, bigint[]> {
  const res = new Map<bigint, bigint[]>();
  const cmd = [`${llvm}/llvm-objdump`, "-d", "--no-show-raw-insn"];
  if (symbolsOnly) cmd.push(`--disassemble-symbols=${symbolsOnly.join(",")}`);
  const lines = out([...cmd, img.path]).split("\n");
  const ends = [...starts].sort((x, y) => (x[0] < y[0] ? -1 : 1));
  let fi = 0;
  let pending: { fn: bigint; at: bigint } | null = null;
  for (const l of lines) {
    const i = l.match(/^\s*([0-9a-f]+):\s+(\S+)/);
    if (!i) continue;
    const a = BigInt(`0x${i[1]}`);
    if (pending) { res.get(pending.fn)!.push(a); pending = null; }
    while (fi < ends.length && ends[fi][1] <= a) fi++;
    if (fi >= ends.length || a < ends[fi][0]) continue;
    const fn = ends[fi][0];
    if (!res.has(fn)) res.set(fn, []);
    if (img.arch.calls.test(i[2])) {
      if (img.arch.unit === 4) res.get(fn)!.push(a + 4n);
      else pending = { fn, at: a };
    }
  }
  if (pending) res.get(pending.fn)!.push(starts.get(pending.fn)!);
  return res;
}

function handlerRows(rets: bigint[], fn: bigint, sites: ReturnType<typeof lsdaSites>["sites"]): Row[] {
  const r: Row[] = [];
  for (const c of rets) {
    const ret = Number(c - fn);
    const ip = ret - 1;
    const s = sites.find((x) => x.start <= ip && ip < x.start + x.len);
    if (!s) r.push({ ret, pad: 0, action: 2 });
    else if (s.pad !== 0) r.push({ ret, pad: s.pad, action: s.action });
  }
  return r;
}

/** Symbols defined in text, address to name and name to address. */
export function names(img: Img): Map<bigint, string> {
  const m = new Map<bigint, string>();
  for (const l of out([`${llvm}/llvm-nm`, "--defined-only", img.path]).split("\n")) {
    const s = l.match(/^([0-9a-f]+) [Tt] (\S+)$/);
    if (s && !m.has(BigInt(`0x${s[1]}`))) m.set(BigInt(`0x${s[1]}`), s[2]);
  }
  return m;
}

/** Derive v2 functions: global text symbols with the prefix, or every FDE (all). */
export function derive(img: Img, prefix: string, all = false) {
  const f = fdes(img.path);
  const syms = names(img);
  const pick: [bigint, string][] = all
    ? [...f.keys()].map((s) => [s, syms.get(s) ?? `fde@0x${s.toString(16)}`])
    : [...syms].filter(([a, n]) => n.startsWith(img.prefix + prefix) && f.has(a));
  const lsdaMap = img.macho ? unwindInfo(img.path).lsda : new Map<bigint, bigint>();
  const tab = section(img.path, img.macho ? "__gcc_except_tab" : ".gcc_except_table");
  const starts = new Map(pick.map(([a]) => [a, f.get(a)!.end]));
  const rets = calls(img, starts, all ? null : pick.map(([, n]) => n));
  const fns: Fn2[] = [];
  const skipped: string[] = [];
  for (const [start, name] of pick) {
    const fde = f.get(start)!;
    const rows = states(img.arch, fde);
    if (typeof rows === "string") { skipped.push(`${name}: ${rows}`); continue; }
    const l = fde.lsda ?? lsdaMap.get(start) ?? null;
    let handlers: Row[] = [];
    if (l !== null) {
      try { handlers = handlerRows(rets.get(start) ?? [], start, lsdaSites(tab, l).sites); }
      catch (e) { skipped.push(`${name}: LSDA ${(e as Error).message}`); continue; }
    }
    fns.push({ name, start, length: Number(fde.end - fde.start), rows, handlers, fde });
  }
  fns.sort((a, b) => (a.start < b.start ? -1 : 1));
  return { fns, skipped };
}

export function plant(arch: Arch, fns: Fn2[], spec: string): string {
  const [what, target] = spec.split(":");
  const pickFn = () => fns.find((f) => (!target || f.name === target || f.name === `_${target}`) && f.rows.some(([o]) => o > 0));
  if (what === "wrong-cfa" || what === "drop-state") {
    const f = pickFn();
    if (!f) throw new Error(`plant ${spec}: no function`);
    const i = f.rows.findIndex(([o]) => o > 0);
    const [off, s] = f.rows[i];
    if (what === "wrong-cfa") {
      f.rows[i] = [off, { ...s, units: s.units + 2 }];
      return `wrong-cfa: ${f.name} +0x${off.toString(16)}: ${show(arch, s)} planted as ${show(arch, f.rows[i][1])}`;
    }
    f.rows.splice(i, 1);
    return `drop-state: ${f.name} +0x${off.toString(16)}: state ${show(arch, s)} dropped`;
  }
  if (what === "wrong-args") {
    const f = fns.find((x) => (!target || x.name === target || x.name === `_${target}`) && x.rows.some(([, s]) => s.args > 0));
    if (!f) throw new Error(`plant ${spec}: no function with DW_CFA_GNU_args_size > 0`);
    const i = f.rows.findIndex(([, s]) => s.args > 0);
    const [off, s] = f.rows[i];
    f.rows[i] = [off, { ...s, args: s.args + 8 }];
    return `wrong-args: ${f.name} +0x${off.toString(16)}: ${show(arch, s)} planted as ${show(arch, f.rows[i][1])}`;
  }
  if (what === "wrong-pad") {
    let n = 0;
    for (const f of fns) {
      const live = f.handlers.filter((x) => x.pad !== 0);
      if (new Set(live.map((x) => x.pad)).size < 2) continue;
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
  if (what === "no-restore") {
    let n = 0;
    for (const f of fns) {
      const regs = new Set(f.rows.flatMap(([, s]) => [...s.regs.keys()]).filter((r) => r !== arch.fp && r !== arch.ra));
      if (!regs.size) continue;
      const top = Math.max(...regs);
      for (const [, s] of f.rows) s.regs.delete(top);
      n++;
    }
    return `no-restore: highest callee-saved register never saved in ${n} functions`;
  }
  throw new Error(`unknown plant ${spec}`);
}

/** Chunk layout: header, 12-byte records, then each description. */
export function layout(arch: Arch, fns: Fn2[]) {
  let off = 16 + 12 * fns.length;
  const descs = fns.map((f) => {
    const prog = program(arch, f.rows);
    const tab = f.handlers.length ? table(f.handlers) : [];
    const bytes = prog.length === 1 && !tab.length ? [] : [...prog, ...tab];
    const data = bytes.length ? (off | (tab.length ? 0x80000000 : 0)) >>> 0 : 0;
    off += bytes.length;
    return { bytes, data, prog: prog.length, tab: tab.length };
  });
  const size = Math.ceil(off / 4) * 4;
  return { descs, size };
}

/** Bytes per function: record, program and table; chunk header and padding apart. */
export const fnBytes = (d: { bytes: number[] }) => 12 + d.bytes.length;

export function emit(img: Img, fns: Fn2[]): string {
  const { descs, size } = layout(img.arch, fns);
  const L = img.macho ? "L" : ".L";
  const s: string[] = [];
  if (img.macho) s.push("    .section __TEXT,__eko_unwind,regular,no_dead_strip", "    .p2align 2");
  else s.push("    .section .note.eko_unwind,\"a\",%note", "    .p2align 2", "    .long 5", `    .long ${size}`, "    .long 1", "    .asciz \"EKUW\"", "    .p2align 2");
  s.push(`${L}k2_chunk:`, "    .long 0x57554b45", `    .byte 2, ${img.arch.code}`, "    .short 1", `    .long ${fns.length}`, `    .long ${size}`);
  fns.forEach((f, i) => s.push(`${L}k2_r${i}:`, `    .long ${f.name} - ${L}k2_r${i}`, `    .long ${f.length}`, `    .long 0x${descs[i].data.toString(16)}`));
  const all = descs.flatMap((d) => d.bytes);
  const used = 16 + 12 * fns.length + all.length;
  for (let k = used; k < size; k++) all.push(0);
  for (let k = 0; k < all.length; k += 16) s.push(`    .byte ${all.slice(k, k + 16).join(", ")}`);
  s.push("");
  return s.join("\n");
}

/** Raw chunk whose records are relative to address vm (table-only checks). */
export function blob(img: Img, fns: Fn2[], vm: bigint): Uint8Array {
  const { descs, size } = layout(img.arch, fns);
  const b = new Uint8Array(size);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, 0x57554b45, true); b[4] = 2; b[5] = img.arch.code; dv.setUint16(6, 1, true);
  dv.setUint32(8, fns.length, true); dv.setUint32(12, size, true);
  let off = 16 + 12 * fns.length;
  fns.forEach((f, i) => {
    const at = 16 + 12 * i;
    const rel = f.start - (vm + BigInt(at));
    if (rel < -(2n ** 31n) || rel >= 2n ** 31n) throw new Error(`${f.name} out of i32 range`);
    dv.setInt32(at, Number(rel), true); dv.setUint32(at + 4, f.length, true); dv.setUint32(at + 8, descs[i].data, true);
    b.set(descs[i].bytes, off);
    off += descs[i].bytes.length;
  });
  return b;
}

if (import.meta.main) {
  const [path, dst] = process.argv.slice(2);
  const arg = (n: string) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : undefined; };
  const img = image(path);
  const { fns, skipped } = derive(img, arg("--prefix") ?? "eh_", process.argv.includes("--all"));
  const p = arg("--plant");
  if (p) console.log(plant(img.arch, fns, p));
  if (process.argv.includes("--blob")) {
    const vm = section(path, img.macho ? "__eh_frame" : ".eh_frame").addr;
    await Bun.write(dst, blob(img, fns, vm));
    console.log(`blob at 0x${vm.toString(16)}`);
  } else await Bun.write(dst, emit(img, fns));
  const { descs, size } = layout(img.arch, fns);
  console.log(`eko2-gen: ${fns.length} functions, ${fns.reduce((n, f) => n + f.handlers.length, 0)} handler rows, ${size} bytes (${descs.reduce((n, d) => n + d.prog, 0)} program, ${descs.reduce((n, d) => n + d.tab, 0)} table) -> ${dst}`);
  for (const s of skipped.slice(0, 20)) console.log(`  skipped, stays on .eh_frame: ${s}`);
  if (skipped.length > 20) console.log(`  ... ${skipped.length - 20} more skipped`);
}

// Reading a table back through the reader, and comparing it with .eh_frame.
export type Dumped = { start: bigint; length: number; states: [number, string][]; rows: string[]; errors: string[] };
/** Dump a table with tools/eko-dump.rs (built at dumpBin). */
export function dump(dumpBin: string, path: string, vm: bigint, mode: "raw" | "note"): Dumped[] {
  const p = Bun.spawnSync({ cmd: [dumpBin, path, vm.toString(16), mode], stdout: "pipe", stderr: "pipe", maxBuffer: 1 << 30 });
  const r = { out: p.stdout.toString(), err: p.stderr.toString(), code: p.exitCode };
  if (r.code !== 0) throw new Error(`eko-dump: ${r.err}`);
  const fns: Dumped[] = [];
  for (const l of r.out.split("\n")) {
    const f = l.match(/^fn 0x([0-9a-f]+) (\d+) v(\d+)$/);
    if (f) { fns.push({ start: BigInt(`0x${f[1]}`), length: Number(f[2]), states: [], rows: [], errors: [] }); continue; }
    const cur = fns[fns.length - 1];
    if (!cur) continue;
    const s = l.match(/^\+0x([0-9a-f]+) (.*)$/);
    if (s) cur.states.push([parseInt(s[1], 16), s[2]]);
    else if (l.startsWith("row ")) cur.rows.push(l.slice(4));
    else if (l.startsWith("error")) cur.errors.push(l);
  }
  return fns;
}

/** Compare decoded v2 states with the image .eh_frame, per code unit. */
export function equiv(img: Img, d: Dumped[], name: (a: bigint) => string) {
  const f = fdes(img.path);
  const fails: string[] = [];
  let units = 0;
  for (const x of d) {
    const n = name(x.start);
    const fde = f.get(x.start);
    if (x.errors.length) { fails.push(`${n}: reader ${x.errors[0]}`); continue; }
    if (!fde) { fails.push(`${n}: no .eh_frame FDE at 0x${x.start.toString(16)}`); continue; }
    if (Number(fde.end - fde.start) !== x.length) { fails.push(`${n}: v2 length ${x.length}, FDE ${fde.end - fde.start}`); continue; }
    const parsed: [number, St][] = [];
    let bad = "";
    for (const r of fde.rows) {
      const s = parseRow(img.arch, r.text);
      if (typeof s === "string") { bad = `.eh_frame row ${r.text}`; break; }
      parsed.push([Number(r.at - fde.start), s]);
    }
    if (bad) { fails.push(`${n}: ${bad}`); continue; }
    const oracle: [number, string][] = withArgs(img.arch, fde, parsed).map(([o, s]) => [o, show(img.arch, s)]);
    const at = (rows: [number, string][], off: number) => { let s = "(none)"; for (const [o, t] of rows) if (o <= off) s = t; return s; };
    for (let off = 0; off < x.length; off += img.arch.unit) {
      units++;
      const a = at(x.states, off), b = at(oracle, off);
      if (a !== b) { fails.push(`${n} +0x${off.toString(16)}: v2 ${a}; .eh_frame ${b}`); break; }
    }
  }
  return { fails, units };
}

