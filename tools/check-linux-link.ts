// Linux link-boundary verifier. The needed set comes from what rustc links
// for a std program (fixtures/linux/std.rs), not from a list.
//   L1 <triple>  every strong undefined _Unwind_* or *register_frame* in the
//                link inputs (crt objects, the program object, std rlibs) is
//                defined by ps_unwind.o. Weak refs are listed, not required:
//                an unresolved weak ref is 0 and never makes an --as-needed
//                library NEEDED (crtbegin weakly calls __register_frame_info
//                and __deregister_frame_info only when they are non-null).
//   L2 <musl>    the program links (rust-lld, static) with the documented line
//                (-l static:+whole-archive=ps_unwind): no duplicate, the map shows
//                ps_unwind.o and no libunwind.a member.
//   L3 <gnu>     the program links against glibc with that line and
//                llvm-readobj --needed-libs (readelf -d NEEDED) has no
//                libgcc_s. Needs a glibc cross toolchain; NOT RUN without it.
// Exit 0: everything ran and passed. 1: a check failed. 2: nothing failed but
// something did not run (unknown is not success).
// Usage: bun tools/check-linux-link.ts [triple...]   (PS_RUSTC overrides rustc)
import { existsSync, mkdirSync, readFileSync, rmSync } from "fs";
import { basename, resolve } from "path";

const root = resolve(import.meta.dir, "..");
const tmp = `${root}/target/tmp`;
const work = `${root}/target/linux-link`;
mkdirSync(tmp, { recursive: true });
mkdirSync(work, { recursive: true });
const env = { ...process.env, TMPDIR: tmp };
const rustc = process.env.PS_RUSTC ?? "rustc";

function run(cmd: string[], cwd = root) {
  const r = Bun.spawnSync({ cmd, cwd, env, stdout: "pipe", stderr: "pipe" });
  return { ok: r.exitCode === 0, out: r.stdout.toString(), err: r.stderr.toString() };
}
const sysroot = run([rustc, "--print", "sysroot"]).out.trim();
const host = run([rustc, "--print", "host-tuple"]).out.trim();
const bin = `${sysroot}/lib/rustlib/${host}/bin`;
const nm = `${bin}/llvm-nm`;
const readobj = `${bin}/llvm-readobj`;
const prog = `${root}/fixtures/linux/std.rs`;
const interesting = /^(_Unwind_|__.*register_frame)/;

type Status = "PASS" | "FAIL" | "NOT RUN";
const results: { name: string; status: Status; detail: string[] }[] = [];
function report(name: string, status: Status, detail: string[] = []) {
  results.push({ name, status, detail });
  console.log(`${status} ${name}`);
  for (const d of detail) console.log(`    ${d}`);
}

const all = ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"];
const triples = process.argv.length > 2 ? process.argv.slice(2) : all;
if (!existsSync(nm) || !existsSync(readobj)) {
  report("tools", "NOT RUN", [`missing ${nm} or ${readobj}`, "install: rustup component add llvm-tools"]);
  process.exit(2);
}

// name -> type letter for every symbol line of llvm-nm -P, per input file
function symbols(file: string, flag: string) {
  const r = run([nm, flag, "-P", file]);
  const m: [string, string][] = [];
  for (const l of r.out.split("\n")) {
    const f = l.trim().split(/\s+/);
    if (f.length >= 2 && f[1].length === 1) m.push([f[0], f[1]]);
  }
  return m;
}

// Quoted words of the linker command printed by --print link-args.
function linkWords(text: string) {
  const line = text.split("\n").find((l) => l.includes("\"-flavor\"")) ?? "";
  return [...line.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
}

for (const t of triples) {
  const gnu = t.endsWith("-gnu");
  if (!existsSync(`${sysroot}/lib/rustlib/${t}/lib`)) {
    report(`L1 ${t}`, "NOT RUN", [`no std for ${t}`, `install: rustup target add ${t}`]);
    continue;
  }
  const b = run(["sh", "tools/build.sh", t]);
  const obj = `${root}/target/dist/${t}/ps_unwind.o`;
  if (!b.ok || !existsSync(obj)) {
    report(`L1 ${t}`, "FAIL", ["tools/build.sh failed", ...b.err.split("\n").slice(-8)]);
    continue;
  }
  const exports = new Set(symbols(obj, "--defined-only").filter(([, ty]) => /[A-Z]/.test(ty)).map(([n]) => n));

  // Inputs: the link line with the probe link (it may fail on gnu: no libc),
  // plus the program object, which the link line names only as a temp file.
  const probe = `${work}/probe-${t}`;
  const p = run([rustc, "--target", t, "-C", "linker=rust-lld", "-C", "linker-flavor=ld.lld", "-C", "panic=unwind", "--print", "link-args", prog, "-o", probe], work);
  rmSync(probe, { force: true });
  // a failed link leaves its rcgu objects behind
  for (const f of new Bun.Glob(`probe-${t}*`).scanSync(work)) rmSync(`${work}/${f}`, { force: true });
  const words = linkWords(p.out + p.err);
  const progObj = `${work}/std-${t}.o`;
  const e = run([rustc, "--target", t, "--emit=obj", "-C", "panic=unwind", prog, "-o", progObj], work);
  const inputs = words.filter((w) => (w.endsWith(".rlib") || w.endsWith(".o")) && w.startsWith("/") && existsSync(w));
  if (e.ok) inputs.push(progObj);
  if (inputs.filter((w) => w.endsWith(".rlib")).length === 0 || !e.ok) {
    report(`L1 ${t}`, "FAIL", ["could not derive the link inputs", ...(p.out + p.err + e.err).split("\n").slice(0, 6)]);
    continue;
  }
  const strong = new Map<string, Set<string>>();
  const weak = new Map<string, Set<string>>();
  for (const f of inputs) {
    for (const [n, ty] of symbols(f, "-u")) {
      if (!interesting.test(n)) continue;
      const into = ty === "U" ? strong : weak;
      if (!into.has(n)) into.set(n, new Set());
      into.get(n)!.add(basename(f).replace(/-[0-9a-f]{16}\.rlib$/, ".rlib"));
    }
  }
  const crt = inputs.filter((w) => /\/crt[^/]*\.o$/.test(w)).map((w) => basename(w));
  const detail = [`inputs: ${inputs.length} (crt: ${crt.length ? crt.join(" ") : "none on this link line"})`];
  for (const [n, from] of [...strong].sort()) detail.push(`needs ${n} <- ${[...from].join(" ")}`);
  for (const [n, from] of [...weak].sort()) detail.push(`weak ${n} <- ${[...from].join(" ")}${exports.has(n) ? " (defined)" : " (left 0)"}`);
  const missing = [...strong.keys()].filter((n) => !exports.has(n)).sort();
  if (strong.size === 0) report(`L1 ${t}`, "FAIL", ["no strong _Unwind_ import found: the probe is broken", ...detail]);
  else if (missing.length) report(`L1 ${t}`, "FAIL", [...missing.map((n) => `missing export ${n}`), ...detail]);
  else report(`L1 ${t}`, "PASS", detail);

  if (!gnu) {
    const out = `${work}/std-ps-${t}`;
    const map = `${work}/std-ps-${t}.map`;
    rmSync(map, { force: true });
    const l = run([rustc, "--target", t, "-C", "linker=rust-lld", "-C", "linker-flavor=ld.lld", "-C", "panic=unwind", "-L", `native=${root}/target/dist/${t}`, "-l", "static:+whole-archive=ps_unwind", "-C", `link-arg=-Map=${map}`, prog, "-o", out], work);
    if (!l.ok) {
      const lines = (l.out + l.err).split("\n").filter((x) => /duplicate symbol|undefined symbol|error/.test(x));
      report(`L2 ${t}`, "FAIL", ["link with ps_unwind.o failed", ...lines.slice(0, 12)]);
      continue;
    }
    const m = existsSync(map) ? readFileSync(map, "utf8") : "";
    const members = [...new Set(m.split("\n").map((x) => x.match(/libunwind\.a\(([^)]*)\)/)?.[1]).filter((x) => x))];
    const usesPs = m.includes("ps_unwind.o");
    const defs = symbols(out, "--defined-only").map(([n]) => n);
    const twice = [...new Set(defs.filter((n) => interesting.test(n) && defs.indexOf(n) !== defs.lastIndexOf(n)))];
    if (!m) report(`L2 ${t}`, "FAIL", ["no link map written"]);
    else if (members.length || !usesPs || twice.length)
      report(`L2 ${t}`, "FAIL", [...members.map((x) => `libunwind.a member loaded: ${x}`), ...(usesPs ? [] : ["ps_unwind.o not in the link map"]), ...twice.map((n) => `defined twice: ${n}`)]);
    else report(`L2 ${t}`, "PASS", ["linked, ps_unwind.o in the map, no libunwind.a member, each _Unwind_ symbol defined once"]);
    continue;
  }

  // L3: needs a real glibc link. The cross gcc is the linker driver; it
  // brings crt1.o, crtbegin.o and libc.
  const gcc = `${t}-gcc`;
  const which = run(["sh", "-c", `command -v ${gcc}`]);
  if (!which.ok) {
    const tap = "messense/macos-cross-toolchains";
    report(`L3 ${t}`, "NOT RUN", [`no ${gcc} (glibc sysroot, crtbegin.o, libgcc_s) on this machine`, `rust-lld probe: ${(p.out + p.err).split("\n").find((x) => /unable to find library/.test(x))?.trim() ?? "n/a"}`, `install: brew tap ${tap} && brew install ${t}`]);
    continue;
  }
  const out = `${work}/std-ps-${t}`;
  const l = run([rustc, "--target", t, "-C", `linker=${gcc}`, "-C", "panic=unwind", "-L", `native=${root}/target/dist/${t}`, "-l", "static:+whole-archive=ps_unwind", prog, "-o", out], work);
  if (!l.ok) {
    report(`L3 ${t}`, "FAIL", ["glibc link with ps_unwind.o failed", ...(l.out + l.err).split("\n").filter((x) => /duplicate|undefined|error/.test(x)).slice(0, 12)]);
    continue;
  }
  const needed = run([readobj, "--needed-libs", out]);
  const libs = needed.out.split("\n").map((x) => x.trim()).filter((x) => /^lib/.test(x));
  if (!needed.ok || libs.length === 0) report(`L3 ${t}`, "FAIL", ["llvm-readobj --needed-libs gave nothing", needed.err]);
  else if (libs.some((x) => x.startsWith("libgcc_s"))) report(`L3 ${t}`, "FAIL", [`NEEDED has libgcc_s: ${libs.join(" ")}`]);
  else report(`L3 ${t}`, "PASS", [`NEEDED: ${libs.join(" ")}`]);
}

const failed = results.filter((r) => r.status === "FAIL").length;
const notRun = results.filter((r) => r.status === "NOT RUN").length;
console.log(`${results.length} checks: ${results.length - failed - notRun} pass, ${failed} fail, ${notRun} not run`);
process.exit(failed ? 1 : notRun ? 2 : 0);
