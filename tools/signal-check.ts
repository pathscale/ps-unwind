// Signal-frame verifier (aarch64 Darwin runs; Linux compiled only). Builds
// fixtures/signal/sig.rs against the system unwinder and against ps-unwind
// (target/dist, stable rustc), faults in each fixture function and compares.
//   SG1 sigtramp        _Unwind_Backtrace from the SIGILL handler through
//                       _sigtramp: ps-unwind frames, ip_before_insn and stack
//                       pointers (relative to _sigtramp) equal the system ones
//                       from _sigtramp on, for every mode
//   FL1 frameless-leaf  ps_unwind_backtrace_ucontext, fault at the first
//                       instruction of a frameless leaf (stack 0): frame 0 is
//                       sg_fault_first+0x0 with ip_before_insn 1, the caller
//                       has the same sp, and the callers match the system walk
//   FL2 frameless-32    same for a frameless function with 32 bytes of stack:
//                       sg_frameless32+0x4, caller sp = sp + 32
//   EA1 eko-async       an FP-kind EKO function interrupted before its prologue
//                       is refused by name: one frame, last failure
//                       EkoAsyncFrame (25) at sg_eko_fp+0x0
//   V1 eko-v1-refusal   the uc walk of EA1, byte for byte equal to the output
//                       the version 1 reader gave before version 2 existed
//                       (fixtures/signal/expected/v1-refusal.txt)
//   SG2 v2-prologue-epilogue  sg_v2_fp, described by an EKO version 2 table
//                       (tools/eko2-gen.ts from its CFI), faults before its
//                       prologue, after every prologue step and around every
//                       epilogue step (one udf each); at every fault the uc
//                       walk must give frame 0 = that udf (ip_before_insn 1)
//                       and a caller frame equal to the hardware state at
//                       entry (return address, sp, x19, x20, x29, d8), with
//                       the same callers after it and the same end
//   FL3 v2-frameless    the same for sg_v2_leaf (frameless, 32 bytes, x19)
//   E3 v2-equivalence   the v2 table in the ps image decodes (eko-dump) to
//                       the state its .eh_frame gives at every instruction
//   LX1 linux-sigreturn aarch64 Linux __kernel_rt_sigreturn: NOT RUN, compiled
//                       only (no Linux machine)
// --plant NAME builds the v2 table with eko2-gen --plant NAME (drop-state:
// the first prologue state of sg_v2_fp is dropped); SG2 must fail by name.
// Exit 0 all ran and passed, 1 a check failed, 2 nothing failed but
// something did not run.
// Usage: bun tools/signal-check.ts [--plant NAME]
import { mkdirSync, readFileSync, writeFileSync } from "fs";
import { resolve } from "path";
import { derive, dump, emit, equiv, image, llvm, plant, section } from "./eko2-gen.ts";

const root = resolve(import.meta.dir, "..");
const out = `${root}/target/signal`;
mkdirSync(out, { recursive: true });
mkdirSync(`${root}/target/tmp`, { recursive: true });
const env = { ...process.env, TMPDIR: `${root}/target/tmp` };
function run(cmd: string[], extra: Record<string, string> = {}) {
  const r = Bun.spawnSync({ cmd, cwd: root, env: { ...env, ...extra }, stdout: "pipe", stderr: "pipe", timeout: 120000 });
  return { code: r.exitCode, sig: r.signalCode, out: r.stdout.toString(), err: r.stderr.toString() };
}
function must(r: ReturnType<typeof run>, what: string) {
  if (r.code !== 0) {
    console.log(`FAIL build: ${what}\n${r.out}${r.err}`);
    process.exit(1);
  }
}
must(run(["sh", "tools/build.sh"]), "tools/build.sh");
const sys = `${out}/sig-sys`, ps = `${out}/sig-ps`;
const base = ["rustc", "--edition", "2021", "-O", "-C", "panic=unwind", "fixtures/signal/sig.rs"];
must(run([...base, "-o", sys]), "system build");
const pi = process.argv.indexOf("--plant");
const planted = pi > 0 ? process.argv[pi + 1] : undefined;
const v2 = derive(image(sys), "sg_v2_");
if (planted) console.log(`plant ${plant(image(sys).arch, v2.fns, planted)}`);
if (v2.fns.length !== 2) {
  console.log(`FAIL build: eko2-gen found ${v2.fns.length} sg_v2_* functions, skipped: ${v2.skipped.join("; ")}`);
  process.exit(1);
}
const eko2 = `${out}/eko2-sig.s`;
writeFileSync(eko2, emit(image(sys), v2.fns));
must(run([...base, "--cfg", "ps", "--cfg", "v2", "-C", `link-arg=-Wl,-force_load,${root}/target/dist/libps_unwind.a`, "-o", ps], { PS_EKO2_S: eko2 }), "ps-unwind build");
must(run(["cargo", "build", "--release", "--example", "eko-dump"]), "eko-dump");

type Frame = { name: string; before: string; sp: number };
function frames(text: string, tag: string): Frame[] {
  return text.split("\n").flatMap((l) => {
    const m = l.match(new RegExp(`^${tag} #\\d+ (\\S+) before_insn=(\\d) sp=([+-]\\d+)$`));
    return m ? [{ name: m[1], before: m[2], sp: Number(m[3]) }] : [];
  });
}
const show = (f: Frame[]) => f.map((x) => `${x.name} b=${x.before} sp=${x.sp}`).join(" | ");
const results: { name: string; status: string; detail: string }[] = [];
function report(name: string, ok: boolean, detail: string) {
  results.push({ name, status: ok ? "PASS" : "FAIL", detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: ${detail}`);
}

const runs: Record<string, { sys: ReturnType<typeof run>; ps: ReturnType<typeof run> }> = {};
for (const mode of ["first", "frameless", "eko"]) runs[mode] = { sys: run([sys, mode]), ps: run([ps, mode]) };

const sg: string[] = [];
let sgOk = true;
for (const [mode, r] of Object.entries(runs)) {
  const a = frames(r.sys.out, "tramp").slice(1), b = frames(r.ps.out, "tramp").slice(1);
  const endA = r.sys.out.match(/tramp end rc=\d+/)?.[0], endB = r.ps.out.match(/tramp end rc=\d+/)?.[0];
  const ok = r.sys.code === 0 && r.ps.code === 0 && a.length > 1 && a[0].name.startsWith("_sigtramp+") && show(a) === show(b) && endA === endB;
  sgOk &&= ok;
  sg.push(`${mode}: ${ok ? "equal" : "DIFFER"} (${a.length} frames from _sigtramp, ${endA})${ok ? "" : `\n    system: ${show(a)}\n    ps:     ${show(b)}`}`);
}
report("SG1 sigtramp", sgOk, `\n  ${sg.join("\n  ")}`);

function frameless(name: string, mode: string, fn: string, off: string, delta: number) {
  const r = runs[mode];
  const uc = frames(r.ps.out, "uc");
  const callers = frames(r.sys.out, "tramp").slice(2).map((f) => f.name);
  const ok = r.ps.code === 0 && uc.length >= 2 && uc[0].name === `${fn}+${off}` && uc[0].before === "1" && uc[1].sp - uc[0].sp === delta && uc.slice(1).map((f) => f.name).join(" ") === callers.join(" ");
  report(name, ok, `uc walk: ${show(uc.slice(0, 3))} ...; want ${fn}+${off} b=1, caller sp delta ${delta}, callers equal to the system walk after _sigtramp (${callers.length})`);
}
frameless("FL1 frameless-leaf", "first", "sg_fault_first", "0x0", 0);
frameless("FL2 frameless-32", "frameless", "sg_frameless32", "0x4", 32);

{
  const r = runs.eko;
  const uc = frames(r.ps.out, "uc");
  const end = r.ps.out.match(/uc end rc=(\d+) last_failure=(\d+) at=(\S+)/);
  const ok = r.ps.code === 0 && uc.length === 1 && uc[0].name === "sg_eko_fp+0x0" && uc[0].before === "1" && !!end && end[2] === "25" && end[3] === "sg_eko_fp+0x0";
  report("EA1 eko-async", ok, `uc walk: ${show(uc)}; ${end ? end[0] : "no end line"} (25 = EkoAsyncFrame)`);
}

{
  const r = runs.eko;
  const got = r.ps.out.split("\n").filter((l) => l.startsWith("uc ")).join("\n") + "\n";
  const want = readFileSync(`${root}/fixtures/signal/expected/v1-refusal.txt`, "utf8");
  report("V1 eko-v1-refusal", got === want, `uc walk output ${got === want ? "byte-identical to" : "DIFFERS from"} fixtures/signal/expected/v1-refusal.txt (${want.length} bytes): ${JSON.stringify(got)}`);
}

// Offsets of the udf instructions of a fixture function in the ps image.
function udfs(fn: string): string[] {
  const d = run([`${llvm}/llvm-objdump`, "-d", "--no-show-raw-insn", `--disassemble-symbols=_${fn}`, ps]).out;
  let start = -1;
  const offs: string[] = [];
  for (const l of d.split("\n")) {
    const i = l.match(/^\s*([0-9a-f]+):\s+(\S+)/);
    if (!i) continue;
    const a = parseInt(i[1], 16);
    if (start < 0) start = a;
    if (i[2] === "udf") offs.push(`${fn}+0x${(a - start).toString(16)}`);
  }
  return offs;
}
function v2check(name: string, mode: string, fn: string) {
  const r = run([ps, mode]);
  const lines = r.out.split("\n").filter((l) => l.startsWith(`v2 ${fn} #`));
  const want = udfs(fn);
  const bad: string[] = [];
  lines.forEach((l, i) => {
    const m = l.match(/^v2 \S+ #\d+ (\S+) b=(\d) (.*) rc=\d+ failure=\d+$/);
    if (!m || m[1] !== want[i] || m[2] !== "1" || /BAD/.test(m[3])) bad.push(l.replace(/^v2 \S+ /, ""));
  });
  if (lines.length !== want.length) bad.push(`${lines.length} faults recorded, ${want.length} udf in ${fn}`);
  const ok = r.code === 0 && bad.length === 0;
  report(name, ok, `${lines.length} faults at ${want.join(" ")}; caller frame equal to the entry state at every one: ${bad.length ? `NO\n    ${bad.join("\n    ")}` : "yes"}${r.code !== 0 ? `; exit ${r.code} ${r.err.slice(0, 200)}` : ""}`);
}
v2check("SG2 v2-prologue-epilogue", "v2fp", "sg_v2_fp");
v2check("FL3 v2-frameless", "v2leaf", "sg_v2_leaf");
{
  const sec = section(ps, "__eko_unwind");
  const bin = `${out}/eko-sig.bin`;
  writeFileSync(bin, new Uint8Array(sec.bytes));
  const d = dump(`${root}/target/release/examples/eko-dump`, bin, sec.addr, "raw").filter((x) => x.states.length || x.errors.length);
  const names = new Map(derive(image(ps), "sg_v2_").fns.map((f) => [f.start, f.name]));
  const e = equiv(image(ps), d, (a) => names.get(a) ?? `0x${a.toString(16)}`);
  report("E3 v2-equivalence", e.fails.length === 0 && d.length === 2, `${d.length} v2 functions, ${e.units} instructions compared with .eh_frame${e.fails.length ? `; differ: ${e.fails.join("; ")}` : ""}`);
}

results.push({ name: "LX1 linux-sigreturn", status: "NOT RUN", detail: "" });
console.log("NOT RUN LX1 linux-sigreturn: aarch64 Linux __kernel_rt_sigreturn decoding (Regs::is_sigreturn, sigreturn_caller) is compiled only; needs an aarch64 Linux machine");
const failed = results.filter((r) => r.status === "FAIL").length;
const notRun = results.filter((r) => r.status === "NOT RUN").length;
console.log(`signal-check: ${results.length - failed - notRun} pass, ${failed} fail, ${notRun} not run`);
process.exit(failed ? 1 : notRun ? 2 : 0);
