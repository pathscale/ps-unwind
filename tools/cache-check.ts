// Image cache verifier (Darwin, runs). Builds target/dist with tools/build.sh,
// links fixtures/cache/cache.rs with it (stable rustc, -force_load), and a
// no_std plug dylib. Fails by name:
//   C1 ctor-built    before main the cache holds exactly _dyld_image_count()
//                    images and was published (the constructor ran)
//   C2 add-image     after dlopen the plug is an entry and
//                    _Unwind_FindEnclosingFunction(plug_fn) == plug_fn
//   C3 remove-image  after dlclose the entry is gone, the lookup fails with
//                    NoImage and the old snapshots were freed
//   C4 grace-period  3 readers look up while the main thread loads and
//                    unloads 3000 times under MallocScribble=1, 3 runs: no
//                    wrong result, no crash
// Linux (SignalContextMiss, AT_PHDR, refresh on miss) is compiled only.
// Usage: bun tools/cache-check.ts
import { mkdirSync } from "fs";
import { resolve } from "path";

const root = resolve(import.meta.dir, "..");
const out = `${root}/target/cache`;
mkdirSync(out, { recursive: true });
mkdirSync(`${root}/target/tmp`, { recursive: true });
const env = { ...process.env, TMPDIR: `${root}/target/tmp` };
function run(cmd: string[], extra: Record<string, string> = {}) {
  const r = Bun.spawnSync({ cmd, cwd: root, env: { ...env, ...extra }, stdout: "pipe", stderr: "pipe", timeout: 120000 });
  return { code: r.exitCode, sig: r.signalCode, out: r.stdout.toString(), err: r.stderr.toString() };
}
const fails: string[] = [];
function check(name: string, ok: boolean, detail: string) {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: ${detail}`);
  if (!ok) fails.push(name);
}
function must(r: ReturnType<typeof run>, what: string) {
  if (r.code !== 0) {
    console.log(`FAIL build: ${what}\n${r.out}${r.err}`);
    process.exit(1);
  }
}
must(run(["sh", "tools/build.sh"]), "tools/build.sh");
const plug = `${out}/libplug.dylib`;
const bin = `${out}/cache`;
must(run(["rustc", "--edition", "2021", "--crate-type", "cdylib", "-C", "panic=abort", "-O", "-C", "force-unwind-tables=yes", "-C", "link-arg=-lSystem", "fixtures/cache/plug.rs", "-o", plug]), "plug");
must(run(["rustc", "--edition", "2021", "-O", "-C", "panic=unwind", "fixtures/cache/cache.rs", "-C", `link-arg=-Wl,-force_load,${root}/target/dist/libps_unwind.a`, "-o", bin]), "fixture");

const r = run([bin, plug]);
console.log(r.out.trimEnd());

const line = (prefix: string) => Object.fromEntries([...(r.out.split("\n").find((l) => l.startsWith(prefix)) ?? "").matchAll(/(\w+)=(\S+)/g)].map((m) => [m[1], m[2]]));
const start = line("start entries="), opened = line("opened entries="), openedFn = line("opened fn="), closed = line("closed entries="), closedFn = line("closed fn=");

check("C1 ctor-built", Number(start.publishes) >= 1 && start.entries === start.dyld_images, `before main: entries ${start.entries}, dyld images ${start.dyld_images}, publishes ${start.publishes}`);
check("C2 add-image", opened.entries === opened.dyld_images && openedFn.fn !== undefined && openedFn.enclosing === openedFn.fn, `after dlopen: entries ${opened.entries}, dyld images ${opened.dyld_images}, plug_fn ${openedFn.fn}, enclosing ${openedFn.enclosing}`);
check("C3 remove-image", r.code === 0 && closed.entries === closed.dyld_images && closedFn.enclosing === "0x0" && closedFn.last_failure === "1" && Number(closed.freed) >= 1, `fixture exit ${r.code ?? r.sig}; after dlclose: entries ${closed.entries}, dyld images ${closed.dyld_images}, enclosing ${closedFn.enclosing}, last failure ${closedFn.last_failure} (1 = NoImage), freed ${closed.freed}`);

const runs: string[] = [];
let graceOk = true;
for (let i = 0; i < 3; i++) {
  const s = run([bin, plug, "3000"], { MallocScribble: "1" });
  const m = s.out.match(/lookups=(\d+) wrong=(\d+)/);
  const st = s.out.match(/stressed .*/)?.[0] ?? "";
  const ok = s.code === 0 && !!m && m[2] === "0" && Number(m[1]) > 0;
  graceOk &&= ok;
  runs.push(`run ${i + 1}: exit ${s.code ?? s.sig} ${m ? `lookups ${m[1]} wrong ${m[2]}` : "no result line"} ${st.replace(/^stressed /, "")}`);
}
check("C4 grace-period", graceOk, `\n  ${runs.join("\n  ")}`);
console.log("not run: Linux SignalContextMiss, AT_PHDR exe entry, refresh on miss (compiled only)");
console.log(fails.length ? `cache-check: FAIL (${fails.join(", ")})` : "cache-check: PASS");
process.exit(fails.length ? 1 : 0);
