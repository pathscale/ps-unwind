// Darwin rule: the EKO table supplements the standard tables, never replaces
// them (docs/DESIGN.md, "Two unwinders on Darwin"). For a linked Mach-O image:
//   D1 every function with an EKO record is covered by an __unwind_info entry
//      whose mode is not 0 (FRAME, FRAMELESS or DWARF)
//   D2 every EKO function with a landing pad has an __unwind_info LSDA
//      descriptor at its start
// An image without __eko_unwind or __unwind_info fails (nothing checked is
// not a pass).
//   D3 (--no-eko) the image has no __eko_unwind at all and has __unwind_info:
//      the rule for shipped Darwin images, since the EKO table is not emitted
// Usage: bun tools/check-darwin-tables.ts IMAGE [--build] [--no-eko]
//   --build first links fixtures/darwin-tables/both.rs into IMAGE.
import { existsSync, mkdirSync } from "fs";
import { dirname, resolve } from "path";

const root = resolve(import.meta.dir, "..");
const img = resolve(process.argv[2] ?? "");
const env = { ...process.env, TMPDIR: `${root}/target/tmp` };
function run(cmd: string[]) {
  const r = Bun.spawnSync({ cmd, cwd: root, env, stdout: "pipe", stderr: "pipe" });
  return { ok: r.exitCode === 0, out: r.stdout.toString(), err: r.stderr.toString() };
}
const sysroot = run(["rustc", "--print", "sysroot"]).out.trim();
const bin = `${sysroot}/lib/rustlib/${run(["rustc", "--print", "host-tuple"]).out.trim()}/bin`;
if (process.argv.includes("--build")) {
  mkdirSync(dirname(img), { recursive: true });
  const b = run(["rustc", "--edition", "2021", "-O", "-C", "panic=unwind", "fixtures/darwin-tables/both.rs", "-o", img]);
  if (!b.ok) { console.log(`FAIL build\n${b.err}`); process.exit(1); }
}
if (!existsSync(img)) { console.log(`FAIL no image ${img}`); process.exit(1); }

const fails: string[] = [];
const base = 0x100000000n;
const names = new Map<bigint, string>();
for (const l of run(["nm", img]).out.split("\n")) {
  const m = l.match(/^([0-9a-f]+) [Tt] (\S+)/);
  if (m) names.set(BigInt(`0x${m[1]}`), m[2]);
}
const name = (a: bigint) => names.get(a) ?? `0x${a.toString(16)}`;

// __eko_unwind bytes with their addresses
const dump = run([`${bin}/llvm-objdump`, "-s", "--section=__eko_unwind", img]).out;
let start = -1n;
const bytes: number[] = [];
for (const l of dump.split("\n")) {
  const m = l.match(/^ ([0-9a-f]+) ((?:[0-9a-f]{2,8} ?){1,4})/);
  if (!m) continue;
  if (start < 0n) start = BigInt(`0x${m[1]}`);
  for (const w of m[2].trim().split(" ")) for (let i = 0; i < w.length; i += 2) bytes.push(parseInt(w.slice(i, i + 2), 16));
}
// D3 (--no-eko): a compiler emits no EKO table on Darwin (docs/FORMAT.md,
// "Darwin: not emitted"). A Darwin image that carries one pays its size for
// nothing the standard tables cannot do. Fixtures carry it on purpose, to run
// the reader; a shipped image must not.
if (process.argv.includes("--no-eko")) {
  const ui0 = run([`${bin}/llvm-objdump`, "--unwind-info", img]).out;
  const has = /function offset=/.test(ui0);
  if (bytes.length > 0) console.log(`FAIL D3 Darwin image carries __eko_unwind (${bytes.length} B): ${img}`);
  if (!has) console.log("FAIL D0 no __unwind_info entries");
  const ok = bytes.length === 0 && has;
  console.log(`check-darwin-tables --no-eko: ${ok ? "PASS" : "FAIL"}`);
  process.exit(ok ? 0 : 1);
}
if (bytes.length === 0) { console.log("FAIL D0 no __eko_unwind section"); process.exit(1); }
const u32 = (o: number) => (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0;
const funcs: { start: bigint; pads: number }[] = [];
for (let c = 0; c + 16 <= bytes.length; ) {
  if (u32(c) === 0) { c += 4; continue; }
  if (u32(c) !== 0x57554b45) { fails.push(`D0 bad EKO header at +${c}`); break; }
  const count = u32(c + 8), size = u32(c + 12);
  if (bytes[c + 4] === 2) {
    // Version 2: 12-byte records; landing pads are in the table after the
    // state program (docs/FORMAT.md, "Version 2").
    const uleb = (p: { o: number }) => { let v = 0, s = 0, x = 0; do { x = bytes[p.o++]; v += (x & 0x7f) * 2 ** s; s += 7; } while (x & 0x80); return v; };
    for (let i = 0; i < count; i++) {
      const r = c + 16 + 12 * i;
      const s = start + BigInt(r) + BigInt(u32(r) | 0);
      const data = u32(r + 8);
      let pads = 0;
      if (data & 0x80000000) {
        const p = { o: c + (data & 0x7fffffff) };
        for (let op = bytes[p.o++]; op !== 0; op = bytes[p.o++]) {
          if ((op >= 0x80 && op <= 0xc3) || op === 0xc5 || op === 0xcb) uleb(p);
          else if (op === 0xc4) { uleb(p); uleb(p); }
        }
        for (let k = 0, n = uleb(p); k < n; k++) { uleb(p); if (uleb(p) >= 4) pads++; }
      }
      funcs.push({ start: s, pads });
    }
    c += size;
    continue;
  }
  for (let i = 0; i < count; i++) {
    const r = c + 16 + 16 * i;
    const s = start + BigInt(r) + BigInt(u32(r) | 0);
    const h = u32(r + 12);
    let pads = 0;
    if (h) for (let k = 0, n = u32(c + h); k < n; k++) if (u32(c + h + 4 + 12 * k + 4) !== 0) pads++;
    funcs.push({ start: s, pads });
  }
  c += size;
}

// __unwind_info entries (function offset -> encoding) and LSDA descriptors
const ui = run([`${bin}/llvm-objdump`, "--unwind-info", img]).out;
const entries: [bigint, number][] = [];
const lsda = new Set<bigint>();
let inLsda = false;
for (const l of ui.split("\n")) {
  if (/LSDA descriptors:/.test(l)) inLsda = true;
  else if (/Second level indices:/.test(l)) inLsda = false;
  const m = l.match(/function offset=0x([0-9a-f]+), (?:encoding(?:\[\d+\])?=0x([0-9a-f]+)|LSDA offset=0x[0-9a-f]+$)/);
  if (!m) continue;
  if (m[2]) entries.push([base + BigInt(`0x${m[1]}`), parseInt(m[2], 16)]);
  else if (inLsda) lsda.add(base + BigInt(`0x${m[1]}`));
}
if (entries.length === 0) { console.log("FAIL D0 no __unwind_info entries"); process.exit(1); }
entries.sort((a, b) => (a[0] < b[0] ? -1 : 1));
const modes = ["none", "?", "FRAMELESS", "DWARF", "FRAME"];
for (const f of funcs) {
  let enc = -1;
  for (const [o, e] of entries) if (o <= f.start) enc = e;
  const mode = enc < 0 ? 0 : (enc >>> 24) & 0x0f;
  const line = `${name(f.start)}: __unwind_info mode ${modes[mode] ?? mode}, ${f.pads} EKO landing pads, LSDA ${lsda.has(f.start) ? "yes" : "no"}`;
  console.log(`  ${line}`);
  if (mode === 0) fails.push(`D1 EKO function without standard unwind info: ${name(f.start)}`);
  if (f.pads > 0 && !lsda.has(f.start)) fails.push(`D2 EKO function with landing pads but no LSDA: ${name(f.start)}`);
}
if (funcs.length === 0) fails.push("D0 __eko_unwind has no records");
for (const f of fails) console.log(`FAIL ${f}`);
console.log(`check-darwin-tables: ${funcs.length} EKO functions, ${fails.length ? `FAIL (${fails.length})` : "PASS"}`);
process.exit(fails.length ? 1 : 0);
