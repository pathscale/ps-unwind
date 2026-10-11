// crt checks (docs/CRT.md). Each fails by name:
//   C1  no crtbegin*/crtend*/crtfastmath.o but ours on the link line (tools/crt-ld.ts)
//   C2  no libgcc or libgcc_s in NEEDED
//   C3  no undefined __register_frame_info / __deregister_frame_info
//   C4  musl: the std program links with no duplicate definition
//   C5  __dso_handle defined and hidden, 0 in an executable, self-pointing in a
//       shared object; the TLS destructor run needs Linux and is NOT RUN here
// Plants: PS_UNWIND_CRT_PLANT=c1 (rust's compiler-rt crtbegin.o on the line, standing
// in for gcc's), c2 (-lgcc_s against a stub libgcc_s.so), c3 (an object calling
// __register_frame_info), c4 (that crtbegin.o alongside ours, C1 bypassed).
// The C5 plant is a source edit of crt/lib.rs (see the commit).
// Exit 0 all ran and passed, 1 a check failed, 2 nothing failed but something did not run.
// Usage: bun tools/check-crt.ts [triple...]
import { existsSync, mkdirSync, rmSync } from "fs";
import { resolve } from "path";

const root = resolve(import.meta.dir, "..");
const work = `${root}/target/crt-check`;
const tmp = `${root}/target/tmp`;
mkdirSync(work, { recursive: true });
mkdirSync(tmp, { recursive: true });
const plant = process.env.PS_UNWIND_CRT_PLANT ?? "";
const rustc = process.env.PS_RUSTC ?? "rustc";
const baseEnv = { ...process.env, TMPDIR: tmp };
function run(cmd: string[], env: Record<string, string | undefined> = {}) {
  const r = Bun.spawnSync({ cmd, cwd: root, env: { ...baseEnv, ...env }, stdout: "pipe", stderr: "pipe" });
  return { ok: r.exitCode === 0, out: r.stdout.toString(), err: r.stderr.toString() };
}
const sysroot = run([rustc, "--print", "sysroot"]).out.trim();
const host = run([rustc, "--print", "host-tuple"]).out.trim();
const bin = `${sysroot}/lib/rustlib/${host}/bin`;
const nm = `${bin}/llvm-nm`, readobj = `${bin}/llvm-readobj`, objdump = `${bin}/llvm-objdump`, lld = `${bin}/rust-lld`;

type Status = "PASS" | "FAIL" | "NOT RUN";
const results: Status[] = [];
function report(name: string, status: Status, detail: string[] = []) {
  results.push(status);
  console.log(`${status} ${name}`);
  for (const d of detail) if (d.trim()) console.log(`    ${d.trim()}`);
}
function syms(file: string, flag: string) {
  return run([nm, flag, "-P", file]).out.split("\n").map((l) => l.trim().split(/\s+/)).filter((f) => f.length >= 2 && f[1].length === 1);
}
const frameReg = /^__(de)?register_frame_info$/;

// C5 on the objects themselves: hidden, and the right relocation.
function objectC5(t: string, crt: string) {
  const bad: string[] = [];
  for (const [o, self] of [["crtbegin.o", false], ["crtbeginS.o", true]] as const) {
    const f = `${crt}/${o}`;
    const r = run([readobj, "--symbols", "--relocs", "--elf-output-style=GNU", f]).out;
    const sym = r.split("\n").find((l) => / __dso_handle$/.test(l));
    if (!sym) { bad.push(`${o}: __dso_handle not defined`); continue; }
    if (!/ HIDDEN /.test(sym) || / UND /.test(sym)) bad.push(`${o}: __dso_handle not a hidden definition: ${sym.trim()}`);
    const rel = r.split("\n").filter((l) => /R_(AARCH64_ABS64|X86_64_64) .* __dso_handle \+ 0$/.test(l));
    if (self && rel.length !== 1) bad.push(`${o}: no self relocation for __dso_handle`);
    if (!self && /R_[A-Z0-9_]+/.test(r)) bad.push(`${o}: has a relocation, value is not a link-time 0`);
  }
  for (const o of ["crtbegin.o", "crtbeginS.o", "crtend.o", "crtendS.o"]) {
    for (const [n] of syms(`${crt}/${o}`, "-u")) if (frameReg.test(n)) bad.push(`${o}: undefined ${n}`);
  }
  return bad;
}

const all = ["aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"];
const triples = process.argv.length > 2 ? process.argv.slice(2) : all;
for (const t of triples) {
  const sc = `${sysroot}/lib/rustlib/${t}/lib/self-contained`;
  const crt = `${root}/target/crt/${t}`;
  const b = run(["sh", "tools/crt-build.sh", t]);
  if (!b.ok) { report(`build ${t}`, "FAIL", b.err.split("\n").slice(-6)); continue; }
  const o5 = objectC5(t, crt);
  report(`C5-objects ${t}`, o5.length ? "FAIL" : "PASS", o5.length ? o5 : ["crtbegin.o: hidden, no relocation; crtbeginS.o: hidden, self relocation; no register_frame reference in any of the four"]);
  if (t.endsWith("-gnu")) {
    for (const c of ["C1", "C2", "C3", "C5-link"]) report(`${c} ${t}`, "NOT RUN", ["no glibc crt1.o/crti.o/crtn.o/libc.so on this machine (docs/CRT.md)"]);
    report(`C5-tls ${t}`, "NOT RUN", ["needs a Linux host to execute"]);
    continue;
  }
  const ub = run(["sh", "tools/build.sh", t]);
  if (!ub.ok) { report(`ps_unwind build ${t}`, "FAIL", ub.err.split("\n").slice(-6)); continue; }
  const drv = { PS_UNWIND_CRT_DIR: crt, PS_UNWIND_CRT_LIBC_DIR: sc, PS_UNWIND_CRT_LLD: lld } as Record<string, string>;
  const extra: string[] = [];
  if (plant === "c1" || plant === "c4") extra.push("-C", `link-arg=${sc}/crtbegin.o`);
  if (plant === "c4") drv.PS_UNWIND_CRT_ALLOW_FOREIGN = "1";
  const exe = `${work}/std-${t}`;
  rmSync(exe, { force: true });
  const l = run([rustc, "--target", t, "-C", `linker=${root}/tools/crt-ld.sh`, "-C", "linker-flavor=ld.lld", "-C", "link-self-contained=no", "-C", "panic=unwind", "-L", `native=${sc}`, "-L", `native=${root}/target/dist/${t}`, "-l", "static:+whole-archive=ps_unwind", ...extra, "fixtures/linux/std.rs", "-o", exe], drv);
  const lerr = (l.out + l.err).split("\n");
  const c1 = lerr.filter((x) => /FAIL C1/.test(x));
  report(`C1 ${t}`, c1.length ? "FAIL" : l.ok || lerr.some((x) => /duplicate symbol/.test(x)) ? "PASS" : "FAIL", c1.length ? c1 : l.ok ? ["link line: libc crt1/rcrt1, crti, crtn; ours crtbegin.o, crtend.o; nothing else"] : []);
  const dups = lerr.filter((x) => /duplicate symbol/.test(x));
  if (c1.length) report(`C4 ${t}`, "NOT RUN", ["C1 stopped the link"]);
  else if (!l.ok) report(`C4 ${t}`, "FAIL", dups.length ? dups.map((x) => x.replace(/^.*error: /, "")) : ["link failed", ...lerr.filter((x) => /error/.test(x)).slice(0, 8)]);
  else {
    const defs = syms(exe, "--defined-only").filter(([, ty]) => /[A-Z]/.test(ty)).map(([n]) => n);
    const twice = [...new Set(defs.filter((n, i) => defs.indexOf(n) !== i))];
    report(`C4 ${t}`, twice.length ? "FAIL" : "PASS", twice.length ? twice.map((n) => `duplicate symbol: ${n}`) : ["static musl link, no duplicate symbol"]);
  }

  // Shared object: probe.o (+ plant objects) linked by the same driver.
  const probe = `${work}/probe-${t}.o`;
  run([rustc, "--edition", "2024", "--crate-type", "lib", "--emit", "obj", "--target", t, "-C", "panic=abort", "-C", "relocation-model=pic", "fixtures/crt/probe.rs", "-o", probe]);
  const soIn = [probe];
  if (plant === "c3") {
    const p3 = `${work}/plant-register-${t}.o`;
    run([rustc, "--edition", "2024", "--crate-type", "lib", "--emit", "obj", "--target", t, "-C", "panic=abort", "-C", "relocation-model=pic", "fixtures/crt/plant-register.rs", "-o", p3]);
    soIn.push(p3);
  }
  if (plant === "c2") {
    mkdirSync(`${work}/stub-${t}`, { recursive: true });
    run([lld, "-flavor", "gnu", "-shared", "-soname", "libgcc_s.so.1", "-o", `${work}/stub-${t}/libgcc_s.so`, `${crt}/crtend.o`]);
    soIn.push(`-L${work}/stub-${t}`, "--no-as-needed", "-lgcc_s");
  }
  const so = `${work}/probe-${t}.so`;
  rmSync(so, { force: true });
  const s = run(["sh", "tools/crt-ld.sh", "-shared", "-o", so, ...soIn], drv);
  if (!s.ok) { report(`shared link ${t}`, "FAIL", (s.out + s.err).split("\n").slice(0, 8)); continue; }

  const libs = run([readobj, "--needed-libs", so]).out.split("\n").map((x) => x.trim()).filter((x) => /^lib/.test(x));
  const gcc = libs.filter((x) => /^libgcc/.test(x));
  report(`C2 ${t}`, gcc.length ? "FAIL" : "PASS", gcc.length ? gcc.map((x) => `NEEDED has ${x}`) : [`shared object NEEDED: ${libs.join(" ") || "none"}; executable is static, no NEEDED`]);

  const c3: string[] = [];
  for (const f of l.ok ? [exe, so] : [so]) for (const [n, ty] of syms(f, "-u")) if (frameReg.test(n)) c3.push(`undefined ${n} (${ty}) in ${f.replace(`${work}/`, "")}`);
  report(`C3 ${t}`, c3.length ? "FAIL" : "PASS", c3.length ? c3 : ["no __register_frame_info / __deregister_frame_info reference in the program or the shared object"]);

  // C5 in the linked images.
  const c5: string[] = [];
  const ok5: string[] = [];
  if (l.ok) {
    const d = syms(exe, "-a").find(([n]) => n === "__dso_handle");
    if (!d || /[UwvV]/.test(d[1])) c5.push(`__dso_handle not defined in the executable (std's weak reference left it ${d ? d[1] : "absent"})`);
    else if (/[A-Z]/.test(d[1])) c5.push(`__dso_handle is global (${d[1]}) in the executable, not hidden`);
    else {
      const addr = parseInt(d[2], 16);
      const dump = run([objdump, "-s", `--start-address=0x${addr.toString(16)}`, `--stop-address=0x${(addr + 8).toString(16)}`, exe]).out;
      const line = dump.split("\n").find((x) => new RegExp(`^ *0*${addr.toString(16)} `).test(x));
      const bytes = line ? line.trim().split(/\s+/).slice(1, 3).join("") : d[1] === "b" ? "0000000000000000" : "";
      const relocs = run([readobj, "-r", "--elf-output-style=GNU", exe]).out.split("\n").filter((x) => new RegExp(`^0*${addr.toString(16)} `).test(x.trim()));
      if (bytes !== "0000000000000000" || relocs.length) c5.push(`__dso_handle in the executable is not 0 (bytes ${bytes || "unread"}, relocs ${relocs.length}): not crtbegin.o's; lld synthesizes a hidden __dso_handle at the image start when no object defines one`);
      else ok5.push(`executable: __dso_handle local (${d[1]}) at 0x${addr.toString(16)}, value 0, no relocation`);
    }
  }
  const ds = syms(so, "-a").find(([n]) => n === "__dso_handle");
  if (!ds || /[UwvV]/.test(ds[1])) c5.push("__dso_handle not defined in the shared object");
  else if (/[A-Z]/.test(ds[1])) c5.push(`__dso_handle is global (${ds[1]}) in the shared object, not hidden`);
  else {
    const addr = parseInt(ds[2], 16);
    const rel = run([readobj, "-r", "--elf-output-style=GNU", so]).out.split("\n").map((x) => x.trim().split(/\s+/)).find((f) => parseInt(f[0], 16) === addr);
    if (!rel || !/RELATIVE/.test(rel[2] ?? "") || parseInt(rel[rel.length - 1], 16) !== addr) c5.push(`__dso_handle in the shared object is not self-pointing: ${rel ? rel.join(" ") : "no dynamic relocation"}`);
    else ok5.push(`shared object: __dso_handle local at 0x${addr.toString(16)}, ${rel[2]} addend 0x${addr.toString(16)} (self)`);
  }
  report(`C5-link ${t}`, c5.length ? "FAIL" : "PASS", c5.length ? c5 : ok5);
  report(`C5-tls ${t}`, "NOT RUN", ["linked, not executed: needs a Linux host; on musl std does not use __dso_handle (no __cxa_thread_atexit_impl)"]);
}
const failed = results.filter((r) => r === "FAIL").length;
const notRun = results.filter((r) => r === "NOT RUN").length;
console.log(`${results.length} checks: ${results.length - failed - notRun} pass, ${failed} fail, ${notRun} not run`);
process.exit(failed ? 1 : notRun ? 2 : 0);
