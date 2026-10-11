// DW_CFA_GNU_args_size at landing-pad install, executed on this host
// (aarch64 Darwin). fixtures/args/args.rs with fixtures/args/args.s is built
// three times: against the system unwinder, against ps-unwind (target/dist,
// _ax_args read from its DWARF FDE by src/cfi.rs), and against ps-unwind
// with an EKO version 2 table for _ax_args derived by tools/eko2-gen.ts from
// the FDE (read by src/eko.rs). Named checks:
//   A1 dwarf-fde      __unwind_info sends _ax_args to a DWARF FDE whose ops
//                     include DW_CFA_GNU_args_size 32 before the call
//   A2 v2-table       the v2 table in the third image decodes (eko-dump) to
//                     args=32 at the call of _ax_args
//   R1 system         the system unwinder build prints caught=true
//                     pad_sp=fp+0 (the landing pad sees the 32-byte area
//                     popped)
//   R2 ps-dwarf       the same line from the ps-unwind build (DWARF path)
//   R3 ps-v2          the same line from the ps-unwind build with the v2
//                     table (version 2 path)
// Usage: bun tools/args-run.ts
import { writeFileSync, mkdirSync } from "fs";
import { join, resolve } from "path";
import { derive, dump, emit, fdes, image, section } from "./eko2-gen.ts";
import { unwindInfo } from "./eko-gen.ts";

const root = resolve(import.meta.dir, "..");
const out = join(root, "target/args");
const tmp = join(root, "target/tmp");
mkdirSync(out, { recursive: true });
mkdirSync(tmp, { recursive: true });
const env: Record<string, string> = { PATH: process.env.PATH!, HOME: process.env.HOME!, TMPDIR: tmp };
function run(cmd: string[], extra: Record<string, string> = {}) {
  const r = Bun.spawnSync({ cmd, cwd: root, env: { ...env, ...extra }, stdout: "pipe", stderr: "pipe", timeout: 120000 });
  return { code: r.exitCode, out: r.stdout.toString(), err: r.stderr.toString() };
}
function must(r: ReturnType<typeof run>, what: string) {
  if (r.code !== 0) { console.log(`FAIL build: ${what}\n${r.out}${r.err}`); process.exit(1); }
}
const results: [string, boolean][] = [];
function report(name: string, ok: boolean, detail: string) {
  results.push([name, ok]);
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: ${detail}`);
}

must(run(["sh", "tools/build.sh"]), "tools/build.sh");
must(run(["cargo", "build", "--release", "--example", "eko-dump"]), "eko-dump");
const lib = join(root, "target/dist/libps_unwind.a");
const base = ["rustc", "--edition", "2021", "-O", "-C", "panic=unwind", "--check-cfg", "cfg(v2)", "fixtures/args/args.rs"];
const sys = join(out, "args-sys"), ps = join(out, "args-ps"), psv2 = join(out, "args-ps-v2");
must(run([...base, "-o", sys]), "system build");
must(run([...base, "-C", `link-arg=-Wl,-force_load,${lib}`, "-o", ps]), "ps-unwind build");
const v2 = derive(image(sys), "ax_");
if (v2.fns.length !== 1) { console.log(`FAIL build: eko2-gen found ${v2.fns.length} ax_* functions, skipped: ${v2.skipped.join("; ")}`); process.exit(1); }
const s = join(out, "eko2-args.s");
writeFileSync(s, emit(image(sys), v2.fns));
must(run([...base, "--cfg", "v2", "-C", `link-arg=-Wl,-force_load,${lib}`, "-o", psv2], { PS_EKO2_S: s }), "ps-unwind v2 build");

// A1: compact entry mode and the FDE ops of _ax_args in the system image.
{
  const img = image(sys);
  const start = [...derive(img, "ax_").fns][0].start;
  const mode = ((unwindInfo(sys).enc.get(start) ?? 0) >>> 24) & 0xf;
  const fde = fdes(sys).get(start);
  const args = fde ? fde.args.map((a) => `${a.n} at +0x${(a.at - start).toString(16)}`) : [];
  const ok = mode === 3 && !!fde && fde.args.some((a) => a.n === 32);
  report("A1 dwarf-fde", ok, `_ax_args compact mode ${mode} (3 = DWARF), FDE ${fde ? "found" : "missing"}, DW_CFA_GNU_args_size: ${args.join(", ") || "none"}`);
}

// A2: the v2 table of the third image, read back by the ps-unwind reader.
{
  const img = image(psv2);
  const sec = section(psv2, "__eko_unwind");
  const bin = join(out, "eko2-args.bin");
  writeFileSync(bin, new Uint8Array(sec.bytes));
  const d = dump(join(root, "target/release/examples/eko-dump"), bin, sec.addr, "raw");
  const start = derive(img, "ax_").fns[0].start;
  const rec = d.find((x) => x.start === start);
  const states = rec ? rec.states.map(([o, st]) => `+0x${o.toString(16)} ${st}`) : [];
  const ok = !!rec && rec.errors.length === 0 && rec.states.some(([, st]) => / args=32$/.test(st));
  report("A2 v2-table", ok, `${d.length} v2 records; _ax_args: ${states.join(" | ") || "no record"}`);
}

const want = "caught=true pad_sp=fp+0";
for (const [name, bin] of [["R1 system", sys], ["R2 ps-dwarf", ps], ["R3 ps-v2", psv2]] as const) {
  const r = run([bin]);
  const got = r.out.trim();
  report(name, r.code === 0 && got === want, `exit ${r.code}${r.sig ? ` signal ${r.sig}` : ""}, printed "${got}"${r.err.trim() ? `, stderr ${JSON.stringify(r.err.trim().slice(0, 200))}` : ""}; want "${want}"`);
}
const fail = results.filter((x) => !x[1]);
console.log(`args-run: ${results.length - fail.length} pass, ${fail.length} fail${fail.length ? `; failed: ${fail.map((x) => x[0]).join(", ")}` : ""}`);
process.exit(fail.length ? 1 : 0);
