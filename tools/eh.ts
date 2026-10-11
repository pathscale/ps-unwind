// Landing-pad fixture suite: public rustc only, EKO frames from tools/eko-gen.ts.
//
// 1. Build fixtures/eh/eh.rs (pass 1), derive an EKO record for every eh_*
//    function from its standard tables (tools/eko-gen.ts), and rebuild with
//    that chunk linked in, once on the system unwinder (sys) and once with
//    ps-unwind force-loaded (ps). Same objects, same tables in both.
// 2. Named checks:
//    G1 build         pass 1, sys and ps build
//    G2 eko-records   at least one record, at least one row of each action
//    G3 eko-roundtrip the chunk read back from the ps image equals a fresh
//                     derivation from that image (layout did not move)
//    G4 darwin-tables tools/check-darwin-tables.ts D1/D2 on the ps image
//    G5 binding       ps defines _Unwind_RaiseException, sys binds libSystem
//    Cnn <case>       stdout, stderr and exit status byte-identical, sys vs ps
//    B1 bt-vs-lldb    _Unwind_Backtrace ips under ps-unwind equal lldb bt
//    S1 sizes         __eh_frame + __gcc_except_tab vs EKO bytes, same functions
//    Lx <triple>      Linux: compile (gnu) or link (musl) only, never run
// 3. --plant NAME rebuilds ps with a planted EKO defect (eko-gen --plant) and
//    reruns the C checks; the run must fail by name. NAME: wrong-pad,
//    no-restore.
//
// What the Darwin run proves: ps-unwind takes the EKO record before the
// standard tables (src/find/darwin.rs), so in the ps run every eh_* frame is
// stepped and its landing pads chosen from EKO; the sys run uses the
// standard tables of the same functions. Equal output means the EKO path
// reproduces the platform result for these cases. The plants show the EKO
// path is the one taken. It does not show an image without standard tables
// works: on Darwin those stay (docs/DESIGN.md), on Linux nothing runs here.
//
// --format 2 runs all of it with EKO version 2 tables (tools/eko2-gen.ts):
// G3 then also requires the v2 states to equal .eh_frame at every
// instruction, and the plants are eko2-gen plants (wrong-pad, no-restore).
//
// Usage: bun tools/eh.ts [--format 2] [--plant NAME] [--lib path] [--no-lldb] [--no-linux]
import { mkdirSync, readFileSync, writeFileSync } from "fs";
import { join, resolve } from "path";
import { decode, derive, ekoBytes, emit, fdes, llvm, plant, section } from "./eko-gen.ts";
import { derive as derive2, dump, emit as emit2, equiv, fnBytes, image, layout, plant as plant2, type Fn2 } from "./eko2-gen.ts";

const root = resolve(import.meta.dir, "..");
// --format 2: the same suite with EKO version 2 tables (tools/eko2-gen.ts).
const v2 = process.argv.includes("--format") && process.argv[process.argv.indexOf("--format") + 1] === "2";
const out = join(root, v2 ? "target/eh2" : "target/eh");
const tmp = join(root, "target/tmp");
mkdirSync(out, { recursive: true });
mkdirSync(tmp, { recursive: true });
const arg = (n: string) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : undefined; };
const planted = arg("--plant");
const lib = resolve(arg("--lib") ?? join(root, "target/dist/libps_unwind.a"));
const env: Record<string, string> = { PATH: process.env.PATH!, HOME: process.env.HOME!, TMPDIR: tmp };

function run(cmd: string[], extra: Record<string, string> = {}, timeout = 120000) {
  const r = Bun.spawnSync({ cmd, cwd: root, env: { ...env, ...extra }, stdout: "pipe", stderr: "pipe", timeout });
  return { out: r.stdout.toString(), err: r.stderr.toString(), raw: [r.stdout, r.stderr], code: r.exitCode, sig: r.signalCode ?? "" };
}
const results: [string, string][] = [];
function report(name: string, status: "PASS" | "FAIL" | "NOT RUN", detail: string) {
  results.push([name, status]);
  console.log(`${status} ${name}: ${detail}`);
}

const src = "fixtures/eh/eh.rs";
const base = ["rustc", "--edition", "2024", "-O", "-C", "panic=unwind", "-C", "debuginfo=1", "--check-cfg", "cfg(eko)", src];
function build(o: string, eko: string | null, ps: boolean) {
  const cmd = [...base, ...(eko ? ["--cfg", "eko"] : []), ...(ps ? ["-C", `link-arg=-Wl,-force_load,${lib}`] : []), "-o", o];
  const r = run(cmd, eko ? { PS_EKO_S: eko } : {});
  return r.code === 0 ? "" : `${cmd.join(" ")}\n${r.err}`;
}

const p1 = join(out, "pass1"), sys = join(out, "sys"), ps = join(out, "ps"), ekoS = join(out, "eko.s");
let berr = build(p1, null, false);
const asRecs = (fns: Fn2[]) => fns.map((f) => ({ name: f.name, start: f.start, length: f.length, frame: 0, rows: f.handlers }));
const d1 = berr ? null : derive(p1);
const g2 = !d1 || !v2 ? null : derive2(image(p1), "eh_");
const d = !d1 ? null : g2 ? { recs: asRecs(g2.fns), skipped: g2.skipped } : d1;
if (d) writeFileSync(ekoS, g2 ? emit2(image(p1), g2.fns) : emit(d.recs));
berr ||= build(sys, ekoS, false) || build(ps, ekoS, true);
report("G1 build", berr ? "FAIL" : "PASS", berr || "pass1, sys and ps built with the public rustc");
if (berr || !d) process.exit(1);

// The comparison means something only if each binary uses the unwinder it
// claims to: ps defines _Unwind_RaiseException in its own text, sys binds it
// from libSystem.
const defined = / \(__TEXT,__text\) external __Unwind_RaiseException$/m.test(run(["nm", "-m", ps]).out);
const bound = /\(undefined\) external __Unwind_RaiseException \(from libSystem\)$/m.test(run(["nm", "-m", sys]).out);
report("G5 binding", defined && bound ? "PASS" : "FAIL", `ps defines _Unwind_RaiseException in __TEXT,__text: ${defined}; sys binds it from libSystem: ${bound}`);

const actions = [0, 1, 2].map((a) => d.recs.reduce((n, r) => n + r.rows.filter((x) => x.action === a).length, 0));
report("G2 eko-records", d.recs.length > 0 && actions.every((n) => n > 0) ? "PASS" : "FAIL",
  `${d.recs.length} records, rows: ${actions[0]} cleanup, ${actions[1]} catch, ${actions[2]} terminate; ${g2 ? layout(image(p1).arch, g2.fns).size : ekoBytes(d.recs)} bytes${v2 ? " (version 2)" : ""}; skipped: ${d.skipped.join("; ") || "none"}`);

const freshFns = v2 ? derive2(image(ps), "eh_").fns : [];
const fresh = v2 ? asRecs(freshFns) : derive(ps).recs;
// Version 2: read the table back through the reader (tools/eko-dump.rs) and
// also require its states to equal .eh_frame at every instruction.
const v2fails: string[] = [];
function back2() {
  const b = run(["cargo", "build", "--release", "--example", "eko-dump"]);
  if (b.code !== 0) { v2fails.push(`eko-dump build: ${b.err}`); return []; }
  const sec = section(ps, "__eko_unwind");
  const bin = join(out, "eko2.bin");
  writeFileSync(bin, new Uint8Array(sec.bytes));
  const dd = dump(join(root, "target/release/examples/eko-dump"), bin, sec.addr, "raw");
  const names = new Map(freshFns.map((f) => [f.start, f.name]));
  v2fails.push(...equiv(image(ps), dd, (a) => names.get(a) ?? `0x${a.toString(16)}`).fails);
  return dd.map((x) => ({ name: "", start: x.start, length: x.length, frame: 0, rows: x.rows.map((r) => r.split(" ").map(Number)).map(([ret, pad, action]) => ({ ret, pad, action })) }));
}
const back = v2 ? back2() : decode(ps);
const key = (r: { start: bigint; length: number; frame: number; rows: { ret: number; pad: number; action: number }[] }) =>
  `${r.start.toString(16)} ${r.length} ${r.frame.toString(16)} ${[...r.rows].sort((a, b) => a.ret - b.ret).map((x) => `${x.ret}:${x.pad}:${x.action}`).join(",")}`;
const diff = fresh.map(key).filter((k, i) => k !== (back[i] ? key(back[i]) : ""));
diff.push(...v2fails);
report("G3 eko-roundtrip", !planted && fresh.length === back.length && diff.length === 0 ? "PASS" : planted ? "NOT RUN" : "FAIL",
  planted ? "plant run" : `${back.length} records in the ps image, ${diff.length} differ from a fresh derivation${diff.length ? `: ${diff.slice(0, 3).join(" | ")}` : ""}`);

const dt = run(["bun", "tools/check-darwin-tables.ts", ps]);
report("G4 darwin-tables", dt.code === 0 ? "PASS" : "FAIL", dt.out.trim().split("\n").pop() ?? "");

let psBin = ps;
if (planted) {
  const recs = derive(p1).recs;
  const p2 = v2 ? derive2(image(p1), "eh_").fns : [];
  const what = v2 ? plant2(image(p1).arch, p2, planted) : plant(recs, planted);
  const s = join(out, `eko-${planted}.s`);
  writeFileSync(s, v2 ? emit2(image(p1), p2) : emit(recs));
  psBin = join(out, `ps-${planted}`);
  const e = build(psBin, s, true);
  console.log(`plant ${what}${e ? `\nFAIL build ${e}` : ""}`);
  if (e) process.exit(1);
}

// A planted defect can make a case loop or print without end. Bound it: 10 s
// of CPU, 128 KiB per stream, 20 s wall; exec so the timeout kills the case
// itself and its status reaches us unchanged.
function runCase(bin: string, c: string, tag: string) {
  const o = join(out, `run.${tag}.out`), e = join(out, `run.${tag}.err`);
  const r = Bun.spawnSync({ cmd: ["sh", "-c", "ulimit -t 10 -f 256; exec \"$0\" \"$1\" >\"$2\" 2>\"$3\"", bin, c, o, e], cwd: root, env, timeout: 20000 });
  const raw = [Buffer.from(readFileSync(o)), Buffer.from(readFileSync(e))];
  return { out: raw[0].toString(), err: raw[1].toString(), raw, code: r.exitCode, sig: r.signalCode ?? "" };
}

const cases = run([sys, "list"]).out.split("\n")[1].split(" ");
cases.forEach((c, i) => {
  const a = runCase(sys, c, "sys"), b = runCase(psBin, c, "ps");
  const st = (r: typeof a) => (r.sig ? `signal ${r.sig}` : `exit ${r.code}`);
  const text = (r: typeof a) => `stdout:\n${r.out}stderr:\n${r.err}status: ${st(r)}\n`;
  const name = `C${String(i + 1).padStart(2, "0")} ${c}`;
  writeFileSync(join(out, `${c}.sys.txt`), text(a));
  writeFileSync(join(out, `${c}.ps.txt`), text(b));
  const same = Buffer.compare(a.raw[0], b.raw[0]) === 0 && Buffer.compare(a.raw[1], b.raw[1]) === 0 && st(a) === st(b);
  if (same) report(name, "PASS", `identical, ${a.raw[0].length + a.raw[1].length} bytes, ${st(a)}`);
  else {
    const la = text(a).split("\n"), lb = text(b).split("\n");
    const k = la.findIndex((l, j) => l !== lb[j]);
    const show = (s: string | undefined) => JSON.stringify((s ?? "").replace(/[^ -~]/g, "?").slice(0, 80));
    report(name, "FAIL", `differs at line ${k + 1}: sys ${show(la[k])} ps ${show(lb[k])}; sys ${st(a)}, ps ${st(b)}`);
  }
});

if (!planted && !process.argv.includes("--no-lldb")) {
  const l = run(["lldb", "--batch", "-o", "b eh_trace_cb", "-o", "run bt-abs", "-o", "bt", "-o", "breakpoint delete -f", "-o", "continue", "--", ps], {}, 180000);
  writeFileSync(join(out, "lldb.txt"), l.out + l.err);
  const frames: { ip: bigint; name: string }[] = [];
  let group: bigint | null = null;
  for (const line of l.out.split("\n")) {
    const m = line.match(/frame #\d+: 0x([0-9a-f]+) (\S+)/);
    if (!m) continue;
    if (group === null) group = BigInt(`0x${m[1]}`);
    if (line.includes("[inlined]")) continue;
    frames.push({ ip: group, name: m[2] });
    group = null;
  }
  const uw = [...l.out.matchAll(/^uw ip 0x([0-9a-f]+)$/gm)].map((m) => BigInt(`0x${m[1]}`));
  const start = frames.findIndex((f) => uw.length > 0 && f.ip === uw[0]);
  let same = start >= 0;
  const rows: string[] = [];
  for (let i = 0; start >= 0 && i < Math.max(uw.length, frames.length - start); i++) {
    const f = frames[start + i], u = uw[i];
    if (u !== undefined && (!f || f.ip !== u)) same = false;
    rows.push(`  ${String(i).padStart(2)} uw ${u !== undefined ? `0x${u.toString(16)}` : "(stop)     "} lldb ${f ? `0x${f.ip.toString(16)} ${f.name}` : "-"}`);
  }
  report("B1 bt-vs-lldb", same && uw.length > 0 ? "PASS" : "FAIL", `${uw.length} ps-unwind frames equal to lldb from eh_bt_leaf on\n${rows.join("\n")}`);
}

if (!planted) {
  // Same functions, three encodings: the DWARF FDE in __eh_frame, the LSDA in
  // __gcc_except_tab (to the next LSDA), and the EKO record plus its rows.
  const f = fdes(ps);
  const fr = run([`${llvm}/llvm-objdump`, "--dwarf=frames", ps]).out;
  const fdeLen = new Map<bigint, number>();
  for (const m of fr.matchAll(/^[0-9a-f]{8} ([0-9a-f]{8}) [0-9a-f]{8} FDE cie=[0-9a-f]+ pc=([0-9a-f]+)/gm)) fdeLen.set(BigInt(`0x${m[2]}`), parseInt(m[1], 16) + 4);
  const tab = section(ps, "__gcc_except_tab");
  const starts = [...new Set([...f.values()].map((x) => x.lsda).filter((x): x is bigint => x !== null))].sort((a, b) => (a < b ? -1 : 1));
  const tabEnd = tab.addr + BigInt(tab.bytes.length);
  const lsdaLen = (a: bigint) => Number((starts.find((s) => s > a) ?? tabEnd) - a);
  let eh = 0, ex = 0;
  const lines: string[] = [];
  const lay = v2 ? layout(image(ps).arch, freshFns) : null;
  const v2Bytes = new Map(freshFns.map((x, i) => [x.start, fnBytes(lay!.descs[i])]));
  for (const r of fresh) {
    const x = f.get(r.start);
    const e = fdeLen.get(r.start) ?? 0;
    const g = x?.lsda != null ? lsdaLen(x.lsda) : 0;
    const k = v2 ? v2Bytes.get(r.start)! : 16 + (r.rows.length ? 4 + 12 * r.rows.length : 0);
    eh += e; ex += g;
    lines.push(`  ${r.name.padEnd(22)} __eh_frame ${String(e).padStart(4)}  __gcc_except_tab ${String(g).padStart(4)}  EKO ${String(k).padStart(4)}`);
  }
  const ek = lay ? lay.size : ekoBytes(fresh);
  writeFileSync(join(out, "sizes.txt"), lines.join("\n") + "\n");
  report("S1 sizes", "PASS", `${fresh.length} functions: __eh_frame FDEs ${eh} B + __gcc_except_tab ${ex} B = ${eh + ex} B; EKO ${ek} B (16 B chunk header included${v2 ? ", version 2" : ""}), ratio ${(ek / (eh + ex)).toFixed(3)}; CIEs and __unwind_info not counted\n${lines.join("\n")}`);
}

if (!planted && !process.argv.includes("--no-linux")) {
  for (const t of ["aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]) {
    const o = join(out, `eh-${t}`);
    const musl = t.endsWith("musl");
    const cmd = musl
      ? [...base, "--target", t, "-C", "linker=rust-lld", "-C", "linker-flavor=ld.lld", "-L", `native=${root}/target/dist/${t}`, "-l", "static:+whole-archive=ps_unwind", "-o", o]
      : [...base, "--target", t, "--emit=obj", "-o", `${o}.o`];
    const r = run(cmd);
    if (r.code !== 0) report(`L ${t}`, "FAIL", r.err.split("\n").slice(0, 6).join("\n"));
    else report(`L ${t}`, "NOT RUN", musl ? `linked statically with ps_unwind (rust-lld); not run, no Linux machine; ${v2 ? "its v2 table is generated and decoded by tools/eko2.ts E1/H1" : "no EKO chunk (eko-gen reads Mach-O only)"}` : "compiled to an object; not linked (no glibc sysroot, docs/TARGETS.md) and not run");
  }
}

const fail = results.filter((r) => r[1] === "FAIL");
const nr = results.filter((r) => r[1] === "NOT RUN").length;
console.log(`eh: ${results.length - fail.length - nr} pass, ${fail.length} fail, ${nr} not run${planted ? `, plant ${planted}` : ""}${fail.length ? `; failed: ${fail.map((r) => r[0]).join(", ")}` : ""}`);
process.exit(fail.length ? 1 : 0);
