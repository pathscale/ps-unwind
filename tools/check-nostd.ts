// no_std verifier. Fails, naming the rule, when:
//   R1 src/lib.rs lacks #![no_std]
//   R2 any non-comment source line names a std:: path or extern crate std
//   R3 nm on the cargo staticlib or the dist archive shows a std symbol
//   R4 the dist object imports anything outside the libc allow list
//   R5 the dist object exports anything other than the 14 _Unwind_ names and
//      the 5 ps_unwind_ names
//   R6 the dist object imports pthread_*: the ps-reclaim pin (thread
//      registration) path is linked, so some reader pins
// Usage: bun tools/check-nostd.ts [target-triple]
import { readdirSync, readFileSync, statSync } from "fs";
import { join, resolve } from "path";

const root = resolve(import.meta.dir, "..");
const triple = process.argv[2] ?? "";
const fails: string[] = [];
const sysroot = Bun.spawnSync({ cmd: ["rustc", "--print", "sysroot"], stdout: "pipe" }).stdout.toString().trim();
const host = Bun.spawnSync({ cmd: ["rustc", "--print", "host-tuple"], stdout: "pipe" }).stdout.toString().trim();
const llvmNm = `${sysroot}/lib/rustlib/${host}/bin/llvm-nm`;

const lib = readFileSync(join(root, "src/lib.rs"), "utf8");
if (!/^#!\[no_std\]$/m.test(lib)) fails.push("R1 src/lib.rs has no #![no_std]");

function walk(d: string): string[] {
  return readdirSync(d).flatMap((n) => {
    const p = join(d, n);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith(".rs") ? [p] : [];
  });
}
for (const f of walk(join(root, "src"))) {
  readFileSync(f, "utf8").split("\n").forEach((l, i) => {
    const code = l.replace(/\/\/.*$/, "");
    if (/\bstd::/.test(code) || /extern\s+crate\s+std\b/.test(code)) fails.push(`R2 ${f.slice(root.length + 1)}:${i + 1}: ${l.trim()}`);
  });
}

function nm(args: string[]) {
  const r = Bun.spawnSync({ cmd: [llvmNm, ...args], stdout: "pipe", stderr: "pipe" });
  if (r.exitCode !== 0) {
    fails.push(`nm ${args.join(" ")} failed: ${r.stderr}`);
    return [];
  }
  return r.stdout.toString().split("\n").filter((l) => l.trim() !== "");
}
const rel = triple ? `target/${triple}/release` : "target/release";
const dist = triple ? `target/dist/${triple}` : "target/dist";
const stdSym = /(_ZN3std|_ZN\d+std|[A-Za-z_]3std\d|std\.\w+-[0-9a-f]{16}|libstd-)/;
for (const a of [join(root, rel, "libps_unwind.a"), join(root, dist, "libps_unwind.a")]) {
  const lines = nm(["-a", a]);
  const hits = lines.filter((l) => stdSym.test(l));
  console.log(`nm -a ${a.slice(root.length + 1)}: ${lines.length} lines, ${hits.length} std symbols`);
  for (const h of hits.slice(0, 5)) fails.push(`R3 ${a.slice(root.length + 1)}: ${h.trim()}`);
}

const obj = join(root, dist, "ps_unwind.o");
const allowImports = new Set(["_dyld_register_func_for_add_image", "_dyld_register_func_for_remove_image", "getauxval", "malloc", "free", "posix_memalign", "abort", "memcpy", "memmove", "memset", "memcmp", "bcmp", "write", "dl_iterate_phdr", "_GLOBAL_OFFSET_TABLE_"]);
const strip = (s: string) => (triple.includes("linux") ? s : s.replace(/^_/, ""));
const imports = nm(["-u", obj]).map((l) => strip(l.trim().split(/\s+/).pop()!));
console.log(`imports: ${imports.join(" ")}`);
// aarch64 Linux: outline atomics (LSE or LL/SC, lock-free), defined by the
// compiler_builtins every Rust program links; build.sh drops our copy.
const outlineAtomic = /^__aarch64_(cas|swp|ldadd|ldclr|ldeor|ldset)\d+_(relax|acq|rel|acq_rel|sync)$/;
for (const s of imports) if (!allowImports.has(s) && !(triple.startsWith("aarch64") && triple.includes("linux") && outlineAtomic.test(s))) fails.push(`R4 unexpected import ${s}`);
for (const s of imports) if (s.startsWith("pthread_")) fails.push(`R6 reader pin path linked: imports ${s}`);

const want = ["RaiseException", "Resume", "DeleteException", "GetIP", "GetIPInfo", "GetLanguageSpecificData", "GetRegionStart", "SetGR", "SetIP", "GetDataRelBase", "GetTextRelBase", "Backtrace", "GetCFA", "FindEnclosingFunction"].map((n) => `_Unwind_${n}`).concat(["ps_unwind_signal_enter", "ps_unwind_signal_leave", "ps_unwind_last_failure", "ps_unwind_cache_stats", "ps_unwind_backtrace_ucontext"]);
const exports = nm(["-g", "--defined-only", obj]).map((l) => strip(l.trim().split(/\s+/).pop()!));
console.log(`exports: ${exports.length}`);
for (const s of exports) if (!want.includes(s)) fails.push(`R5 unexpected export ${s}`);
for (const s of want) if (!exports.includes(s)) fails.push(`R5 missing export ${s}`);

for (const f of fails) console.log(`FAIL ${f}`);
console.log(fails.length === 0 ? "check-nostd: PASS" : `check-nostd: FAIL (${fails.length})`);
process.exit(fails.length === 0 ? 0 : 1);
