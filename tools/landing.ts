// Decode-level check of DW_CFA_GNU_args_size at landing-pad install, on
// x86_64 Linux musl (linked here, never run: x86_64 Linux cannot run on this
// host). The image is the one tools/eko2.ts measures: fixtures/eh/eh.rs
// linked with ps-unwind for x86_64-unknown-linux-musl, the whole program
// (std and musl included), with the eh_* v2 table linked in.
//
// Sites: every call with a landing pad, from the LSDAs of the image
// (tools/eko2-gen.ts, the rules Rust personality uses). For each site the
// expected stack pointer adjustment is derived from the llvm-objdump decode
// of .eh_frame alone: the last DW_CFA_GNU_args_size at or before the call
// (return address - 1), 0 when there is none. Installed SP = SP at the call
// + args_size (the callee CFA plus the bytes the caller pushed for it).
// tools/landing-sp.rs installs the landing pad through Cursor::
// set_landing_ip_for, the code _Unwind_SetIP runs, once with the frame from
// .eh_frame (src/cfi.rs) and once with the record of a v2 table derived for
// every FDE of the image (src/eko.rs), and prints how far SP moved.
//   L1 dwarf        the DWARF reader installs the expected SP at every site
//   L2 v2           the v2 reader installs the expected SP at every site
//   L3 coverage     at least one site has a nonzero args_size, so L1 and L2
//                   compare an adjustment and not only zeros
// A mismatch names the function and the return offset of the call.
// Usage: bun tools/landing.ts
import { mkdirSync, writeFileSync } from "fs";
import { join, resolve } from "path";
import { blob, derive, emit, image, section } from "./eko2-gen.ts";

const root = resolve(import.meta.dir, "..");
const out = join(root, "target/landing");
const tmp = join(root, "target/tmp");
mkdirSync(out, { recursive: true });
mkdirSync(tmp, { recursive: true });
const env: Record<string, string> = { PATH: process.env.PATH!, HOME: process.env.HOME!, TMPDIR: tmp };
function run(cmd: string[], extra: Record<string, string> = {}) {
  const r = Bun.spawnSync({ cmd, cwd: root, env: { ...env, ...extra }, stdout: "pipe", stderr: "pipe", maxBuffer: 1 << 30, timeout: 600000 });
  return { out: r.stdout.toString(), err: r.stderr.toString(), code: r.exitCode };
}
function must(r: ReturnType<typeof run>, what: string) {
  if (r.code !== 0) { console.log(`FAIL build ${what}\n${r.out}${r.err}`); process.exit(1); }
}
const results: [string, boolean][] = [];
function report(name: string, ok: boolean, detail: string) {
  results.push([name, ok]);
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: ${detail}`);
}

const t = "x86_64-unknown-linux-musl";
must(run(["sh", "tools/build.sh", t]), `tools/build.sh ${t}`);
must(run(["cargo", "build", "--release", "--example", "landing-sp"]), "landing-sp");
const flags = ["--target", t, "-C", "linker=rust-lld", "-C", "linker-flavor=ld.lld", "-L", `native=${root}/target/dist/${t}`, "-l", "static:+whole-archive=ps_unwind"];
const base = ["rustc", "--edition", "2024", "-O", "-C", "panic=unwind", "-C", "debuginfo=1", "--check-cfg", "cfg(eko)", "fixtures/eh/eh.rs"];
// Pass 1, then the image with the eh_* v2 table linked in, as tools/eko2.ts
// builds it.
const p1 = join(out, `pass1-${t}`), elf = join(out, `ps2-${t}`), s = join(out, `eko2-${t}.s`);
must(run([...base, ...flags, "-o", p1]), `pass1 ${t}`);
writeFileSync(s, emit(image(p1), derive(image(p1), "eh_").fns));
must(run([...base, ...flags, "--cfg", "eko", "-o", elf], { PS_EKO_S: s }), `ps2 ${t}`);

const img = image(elf);
const all = derive(img, "", true);
const eh = section(elf, ".eh_frame");
const v2 = join(out, `all-${t}.bin`);
writeFileSync(v2, blob(img, all.fns, eh.addr));

type Site = { name: string; start: bigint; ret: number; pad: number; want: number };
const sites: Site[] = [];
for (const f of all.fns) {
  for (const h of f.handlers) {
    if (h.pad === 0) continue;
    const call = f.start + BigInt(h.ret - 1);
    let want = 0;
    for (const a of f.fde.args) if (a.at <= call) want = a.n;
    sites.push({ name: f.name, start: f.start, ret: h.ret, pad: h.pad, want });
  }
}
const sitesFile = join(out, `sites-${t}.txt`);
const hex = (n: number | bigint) => n.toString(16);
writeFileSync(sitesFile, sites.map((s) => `${hex(s.start)} ${hex(s.ret)} ${hex(s.pad)}\n`).join(""));
const r = run([join(root, "target/release/examples/landing-sp"), elf, hex(eh.addr), hex(eh.bytes.length), v2, hex(eh.addr), sitesFile]);
must(r, "landing-sp run");
const got = r.out.trim().split("\n").filter((l) => l.startsWith("site "));
if (got.length !== sites.length) { console.log(`FAIL landing-sp: ${got.length} lines for ${sites.length} sites`); process.exit(1); }

const withArgs = all.fns.filter((f) => f.fde.args.some((a) => a.n > 0));
console.log(`${t}: ${all.fns.length} functions, ${all.skipped.length} on .eh_frame only; ${sites.length} landing-pad install sites; functions with DW_CFA_GNU_args_size > 0: ${withArgs.map((f) => `${f.name} (${f.fde.args.filter((a) => a.n > 0).map((a) => `args_size ${a.n} from +0x${hex(a.at - f.start)}`).join(", ")}, ${sites.filter((s) => s.start === f.start).length} sites)`).join("; ") || "none"}`);
const bad: Record<"dwarf" | "v2", string[]> = { dwarf: [], v2: [] };
const nonzero: string[] = [];
got.forEach((l, i) => {
  const s = sites[i];
  const m = l.match(/^site 0x([0-9a-f]+) \+0x([0-9a-f]+) \+0x([0-9a-f]+) dwarf=(\S+) v2=(\S+)$/);
  const at = `${s.name}+0x${hex(s.ret)}`;
  if (!m || BigInt(`0x${m[1]}`) !== s.start || parseInt(m[2], 16) !== s.ret) { bad.dwarf.push(`${at}: bad line ${l}`); return; }
  if (s.want !== 0) nonzero.push(`${at} pad +0x${hex(s.pad)}: want SP+${s.want}, dwarf SP+${m[4]}, v2 SP+${m[5]}`);
  if (m[4] !== String(s.want)) bad.dwarf.push(`${at} (pad +0x${hex(s.pad)}): installed SP at call + ${m[4]}, want + ${s.want}`);
  if (m[5] !== String(s.want)) bad.v2.push(`${at} (pad +0x${hex(s.pad)}): installed SP at call + ${m[5]}, want + ${s.want}`);
});
const list = (x: string[]) => (x.length ? `\n    ${x.slice(0, 8).join("\n    ")}` : "");
report(`L1 dwarf ${t}`, bad.dwarf.length === 0, `${sites.length} sites, ${bad.dwarf.length} differ from .eh_frame${list(bad.dwarf)}`);
report(`L2 v2 ${t}`, bad.v2.length === 0, `${sites.length} sites, ${bad.v2.length} differ from .eh_frame${list(bad.v2)}`);
report(`L3 coverage ${t}`, nonzero.length > 0, `${nonzero.length} sites with args_size > 0${list(nonzero)}`);
const fail = results.filter((x) => !x[1]);
console.log(`landing: ${results.length - fail.length} pass, ${fail.length} fail${fail.length ? `; failed: ${fail.map((x) => x[0]).join(", ")}` : ""}`);
process.exit(fail.length ? 1 : 0);
