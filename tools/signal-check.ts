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
//   LX1 linux-sigreturn aarch64 Linux __kernel_rt_sigreturn: NOT RUN, compiled
//                       only (no Linux machine)
// Exit 0 all ran and passed, 1 a check failed, 2 nothing failed but
// something did not run.
// Usage: bun tools/signal-check.ts
import { mkdirSync } from "fs";
import { resolve } from "path";

const root = resolve(import.meta.dir, "..");
const out = `${root}/target/signal`;
mkdirSync(out, { recursive: true });
mkdirSync(`${root}/target/tmp`, { recursive: true });
const env = { ...process.env, TMPDIR: `${root}/target/tmp` };
function run(cmd: string[]) {
  const r = Bun.spawnSync({ cmd, cwd: root, env, stdout: "pipe", stderr: "pipe", timeout: 60000 });
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
must(run([...base, "--cfg", "ps", "-C", `link-arg=-Wl,-force_load,${root}/target/dist/libps_unwind.a`, "-o", ps]), "ps-unwind build");

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

results.push({ name: "LX1 linux-sigreturn", status: "NOT RUN", detail: "" });
console.log("NOT RUN LX1 linux-sigreturn: aarch64 Linux __kernel_rt_sigreturn decoding (Regs::is_sigreturn, sigreturn_caller) is compiled only; needs an aarch64 Linux machine");
const failed = results.filter((r) => r.status === "FAIL").length;
const notRun = results.filter((r) => r.status === "NOT RUN").length;
console.log(`signal-check: ${results.length - failed - notRun} pass, ${failed} fail, ${notRun} not run`);
process.exit(failed ? 1 : notRun ? 2 : 0);
