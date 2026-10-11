// EKO version 2 checks: a v2 table and the .eh_frame it replaces decode to
// the same unwind state at every instruction of every function.
//
// For each target, fixtures/eh/eh.rs is built (pass 1), tools/eko2-gen.ts
// derives a v2 table for every eh_* function from that image, and the image
// is rebuilt with the table linked in (Mach-O __TEXT,__eko_unwind on Darwin,
// an ELF .note.eko_unwind on Linux). Then:
//   E1 <target>  the table is read back out of the rebuilt image and decoded
//                by the ps-unwind reader (tools/eko-dump.rs: eko::lookup_arch
//                and eko::run at every code unit); the image .eh_frame FDE
//                of the same function is decoded by llvm-objdump; the two
//                states must be equal at every instruction. A mismatch names
//                the function and the instruction offset.
//   H1 <target>  every handler row eko::handler2 finds equals the row the
//                generator derived from the LSDA, and no other row is found
//   E2 <target>  table-only: a v2 table for every FDE of the rebuilt image
//                (the whole program, std and libc included), decoded by the
//                reader and compared the same way; functions the format
//                does not express are counted and stay on .eh_frame
//   Z1 <target>  bytes for the eh_* functions: FDE + LSDA vs v2 vs v1
//   Z2 <target>  the same for every function E2 covered
// Targets: aarch64-apple-darwin (host), aarch64-unknown-linux-musl and
// x86_64-unknown-linux-musl (linked with rust-lld, never run: decoding only
// reads the image file).
//
// --plant NAME regenerates the eh_* tables with eko2-gen --plant NAME and
// reruns E1 and H1, which must fail by name (wrong-cfa: function + offset).
// --plant wrong-args plants into the E2 whole-image table instead; E2 must
// fail on x86_64 musl naming the function and offset.
// Usage: bun tools/eko2.ts [--plant NAME]
import { mkdirSync, writeFileSync } from "fs";
import { join, resolve } from "path";
import { blob, derive, dump as dumpWith, emit, equiv, fdes, fnBytes, image, layout, plant, section, type Fn2, type Img } from "./eko2-gen.ts";
import { unwindInfo } from "./eko-gen.ts";

const root = resolve(import.meta.dir, "..");
const out = join(root, "target/eko2");
const tmp = join(root, "target/tmp");
mkdirSync(out, { recursive: true });
mkdirSync(tmp, { recursive: true });
const arg = (n: string) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : undefined; };
const planted = arg("--plant");
// wrong-args plants into the whole-image tables of E2 (the eh_* fixtures
// have no DW_CFA_GNU_args_size); every other plant into the eh_* tables.
const allPlant = !!planted && planted.startsWith("wrong-args");
const env: Record<string, string> = { PATH: process.env.PATH!, HOME: process.env.HOME!, TMPDIR: tmp };
function run(cmd: string[], extra: Record<string, string> = {}) {
  const r = Bun.spawnSync({ cmd, cwd: root, env: { ...env, ...extra }, stdout: "pipe", stderr: "pipe", maxBuffer: 1 << 30, timeout: 600000 });
  return { out: r.stdout.toString(), err: r.stderr.toString(), code: r.exitCode };
}
const results: [string, string][] = [];
function report(name: string, status: "PASS" | "FAIL" | "NOT RUN", detail: string) {
  results.push([name, status]);
  console.log(`${status} ${name}: ${detail}`);
}
function must(r: ReturnType<typeof run>, what: string) {
  if (r.code !== 0) { console.log(`FAIL build ${what}\n${r.out}${r.err}`); process.exit(1); }
}

const dumpBin = join(root, "target/release/examples/eko-dump");
must(run(["cargo", "build", "--release", "--example", "eko-dump"]), "eko-dump");
const dump = (path: string, vm: bigint, mode: "raw" | "note") => dumpWith(dumpBin, path, vm, mode);

function ekoSection(img: Img) {
  return section(img.path, img.macho ? "__eko_unwind" : ".note.eko_unwind");
}

/** LSDA bytes per function: from its LSDA to the next one in the image. */
function lsdaBytes(img: Img) {
  const f = fdes(img.path);
  const map = img.macho ? unwindInfo(img.path).lsda : new Map<bigint, bigint>();
  const of = (s: bigint) => f.get(s)?.lsda ?? map.get(s) ?? null;
  const tab = section(img.path, img.macho ? "__gcc_except_tab" : ".gcc_except_table");
  const starts = [...new Set([...[...f.values()].map((x) => x.lsda), ...map.values()].filter((x): x is bigint => x !== null))].sort((a, b) => (a < b ? -1 : 1));
  const end = tab.addr + BigInt(tab.bytes.length);
  return (s: bigint) => { const l = of(s); return l === null ? 0 : Number((starts.find((x) => x > l) ?? end) - l); };
}

function sizes(img: Img, fns: Fn2[], label: string) {
  const lsda = lsdaBytes(img);
  const { descs, size } = layout(img.arch, fns);
  let eh = 0, ex = 0, v2 = 0, v1 = 0;
  const lines: string[] = [];
  fns.forEach((f, i) => {
    const e = f.fde.len, g = lsda(f.start), k = fnBytes(descs[i]), o = 16 + (f.handlers.length ? 4 + 12 * f.handlers.length : 0);
    eh += e; ex += g; v2 += k; v1 += o;
    lines.push(`  ${f.name.slice(0, 40).padEnd(40)} FDE ${String(e).padStart(4)}  LSDA ${String(g).padStart(4)}  v2 ${String(k).padStart(4)} (program ${descs[i].prog}, table ${descs[i].tab})  v1 ${String(o).padStart(4)}`);
  });
  const n = fns.length;
  const per = (b: number) => (b / n).toFixed(1);
  const head = `${n} functions: FDE ${eh} B + LSDA ${ex} B = ${eh + ex} B (${per(eh + ex)} B/fn); v2 ${v2} B (${per(v2)} B/fn, chunk ${size} B with header and padding); ratio v2/(FDE+LSDA) ${(v2 / (eh + ex)).toFixed(3)}, v2 is ${(100 * (1 - v2 / (eh + ex))).toFixed(1)}% smaller; v1 ${v1} B (${per(v1)} B/fn, call sites only); CIEs not counted${img.macho ? "" : `; .eh_frame_hdr adds 8 B/fn more that v2 also replaces (${8 * n} B)`}`;
  writeFileSync(join(out, `sizes-${label}.txt`), `${head}\n${lines.join("\n")}\n`);
  return { head, lines };
}

const targets = [
  { t: "aarch64-apple-darwin", flags: (lib: string) => ["-C", `link-arg=-Wl,-force_load,${lib}`] },
  { t: "aarch64-unknown-linux-musl", flags: () => ["--target", "aarch64-unknown-linux-musl", "-C", "linker=rust-lld", "-C", "linker-flavor=ld.lld", "-L", `native=${root}/target/dist/aarch64-unknown-linux-musl`, "-l", "static:+whole-archive=ps_unwind"] },
  { t: "x86_64-unknown-linux-musl", flags: () => ["--target", "x86_64-unknown-linux-musl", "-C", "linker=rust-lld", "-C", "linker-flavor=ld.lld", "-L", `native=${root}/target/dist/x86_64-unknown-linux-musl`, "-l", "static:+whole-archive=ps_unwind"] },
];
must(run(["sh", "tools/build.sh"]), "tools/build.sh");
for (const t of targets.slice(1)) must(run(["sh", "tools/build.sh", t.t]), `tools/build.sh ${t.t}`);

const base = ["rustc", "--edition", "2024", "-O", "-C", "panic=unwind", "-C", "debuginfo=1", "--check-cfg", "cfg(eko)", "fixtures/eh/eh.rs"];
const tag = planted ? `-${planted.replace(/[^a-z0-9-]/g, "_")}` : "";
for (const t of targets) {
  const lib = join(root, "target/dist/libps_unwind.a");
  const p1 = join(out, `pass1-${t.t}`), ps = join(out, `ps2-${t.t}${tag}`), s = join(out, `eko2-${t.t}${tag}.s`);
  must(run([...base, ...t.flags(lib), "-o", p1]), `pass1 ${t.t}`);
  const g = derive(image(p1), "eh_");
  if (planted && !allPlant) console.log(`plant ${t.t}: ${plant(image(p1).arch, g.fns, planted)}`);
  writeFileSync(s, emit(image(p1), g.fns));
  must(run([...base, ...t.flags(lib), "--cfg", "eko", "-o", ps], { PS_EKO_S: s }), `ps2 ${t.t}`);
  const img = image(ps);
  const names = new Map(derive(img, "eh_").fns.map((f) => [f.start, f.name]));
  const sec = ekoSection(img);
  const bin = join(out, `eko2-${t.t}${tag}.bin`);
  writeFileSync(bin, new Uint8Array(sec.bytes));
  const d = dump(bin, sec.addr, img.macho ? "raw" : "note");
  const r = equiv(img, d, (a) => names.get(a) ?? `0x${a.toString(16)}`);
  const ok = r.fails.length === 0 && d.length === g.fns.length;
  if (d.length !== g.fns.length) r.fails.push(`${d.length} records in the image, ${g.fns.length} generated`);
  report(`E1 ${t.t}`, ok ? "PASS" : "FAIL", `${d.length} functions (${g.fns.length} generated, skipped: ${g.skipped.join("; ") || "none"}), ${r.units} code units compared (every instruction; on x86_64 every byte), ${r.fails.length} differ${r.fails.length ? `\n    ${r.fails.slice(0, 5).join("\n    ")}` : ""}`);
  const fresh = derive(img, "eh_").fns;
  const want = new Map(fresh.map((f) => [f.start, [...f.handlers].sort((a, b) => a.ret - b.ret).map((x) => `${x.ret} ${x.pad} ${x.action}`).join(",")]));
  const hdiff = d.filter((x) => (want.get(x.start) ?? "") !== x.rows.join(",")).map((x) => names.get(x.start) ?? "?");
  const nrows = d.reduce((n, x) => n + x.rows.length, 0);
  report(`H1 ${t.t}`, hdiff.length === 0 ? "PASS" : "FAIL", `${nrows} handler rows found by eko::handler2 at every return offset, ${hdiff.length} functions differ from the LSDA derivation${hdiff.length ? `: ${hdiff.slice(0, 5).join(", ")}` : ""}`);
  if (planted && !allPlant) continue;
  const z = sizes(img, fresh, `eh-${t.t}`);
  report(`Z1 ${t.t}`, "PASS", `eh_* ${z.head}`);
  const all = derive(img, "", true);
  if (allPlant) {
    let msg: string;
    try { msg = plant(img.arch, all.fns, planted!); } catch (e) { msg = (e as Error).message; }
    console.log(`plant ${t.t}: ${msg}`);
  }
  const vm = section(img.path, img.macho ? "__eh_frame" : ".eh_frame").addr;
  const allBin = join(out, `all-${t.t}.bin`);
  writeFileSync(allBin, blob(img, all.fns, vm));
  const da = dump(allBin, vm, "raw");
  const allNames = new Map(all.fns.map((f) => [f.start, f.name]));
  const ra = equiv(img, da, (a) => allNames.get(a) ?? `0x${a.toString(16)}`);
  const total = all.fns.length + all.skipped.length;
  const why = new Map<string, number>();
  for (const k of all.skipped) { const w = k.replace(/^.*?: /, "").replace(/reg\d+/g, "regN").replace(/[+-]?0x[0-9a-f]+|-?\d+/g, "N"); why.set(w, (why.get(w) ?? 0) + 1); }
  report(`E2 ${t.t}`, ra.fails.length === 0 && da.length === all.fns.length ? "PASS" : "FAIL", `${da.length} of ${total} FDEs expressed and equal at all ${ra.units} code units, ${ra.fails.length} differ; ${all.skipped.length} stay on .eh_frame (${[...why].map(([k, v]) => `${v} ${k}`).join(", ") || "none"})${ra.fails.length ? `\n    ${ra.fails.slice(0, 5).join("\n    ")}` : ""}`);
  const za = sizes(img, all.fns, `all-${t.t}`);
  report(`Z2 ${t.t}`, "PASS", `whole image, ${za.head}`);
}
const fail = results.filter((r) => r[1] === "FAIL");
console.log(`eko2: ${results.length - fail.length} pass, ${fail.length} fail${planted ? `, plant ${planted}` : ""}${fail.length ? `; failed: ${fail.map((r) => r[0]).join(", ")}` : ""}`);
process.exit(fail.length ? 1 : 0);
