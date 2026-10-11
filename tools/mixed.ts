// Mixed-stack fixture runner. Named checks:
//   S1 dwarf-mode      __unwind_info sends _fx_dwarf to a DWARF FDE
//   S2 cie-0x9b        that FDE has a zPLR CIE with personality encoding 0x9b
//   S3 sentinel-next   _fx_sentinel starts exactly where the _fx_dwarf FDE ends
//   S4 eko-section     __TEXT,__eko_unwind is present
//   S5 compact-frame   _fx_compact is a FRAME-mode compact entry saving x19-x22, d8, d9
//   R1 regcheck        output equals fixtures/mixed/expected/regcheck.txt
//   R2 panic           output equals fixtures/mixed/expected/panic.txt
//   B1 bt-vs-lldb      _Unwind_Backtrace ips equal the physical frames of lldb bt
//   B2 plain-vs-system a plain backtrace from main is the same, stop included,
//                      under the system unwinder and under ps-unwind
// Usage: bun tools/mixed.ts [--lib path] [--write-expected]
import { mkdirSync, readFileSync, writeFileSync } from "fs";
import { join, resolve } from "path";

const root = resolve(import.meta.dir, "..");
const home = process.env.HOME!;
// The public rustc on PATH; PS_RUSTC names another one.
const rustc = process.env.PS_RUSTC ?? "rustc";
const boot: Record<string, string> = {};
const argLib = process.argv.indexOf("--lib");
const lib = argLib > 0 ? resolve(process.argv[argLib + 1]) : join(root, "target/dist/libps_unwind.a");
const writeExpected = process.argv.includes("--write-expected");
const out = join(root, "target/mixed");
const tmp = join(root, "target/tmp");
mkdirSync(out, { recursive: true });
mkdirSync(tmp, { recursive: true });
const sysroot = Bun.spawnSync({ cmd: ["rustc", "--print", "sysroot"], stdout: "pipe" }).stdout.toString().trim();
const tools = `${sysroot}/lib/rustlib/aarch64-apple-darwin/bin`;
const env = { PATH: process.env.PATH!, HOME: home, TMPDIR: tmp, ...boot };

function run(cmd: string[], timeout = 60000) {
  const r = Bun.spawnSync({ cmd, cwd: root, env, stdout: "pipe", stderr: "pipe", timeout });
  return { out: r.stdout.toString(), err: r.stderr.toString(), code: r.exitCode, sig: r.signalCode ?? "" };
}
const results: [string, boolean, string][] = [];
const check = (name: string, ok: boolean, detail: string) => {
  results.push([name, ok, detail]);
  console.log(`${ok ? "ok  " : "FAIL"} ${name}: ${detail}`);
};

const bin = join(out, "mixed");
const b = run([rustc, "--edition", "2021", "-O", "-C", "panic=unwind", "-C", "debuginfo=2", "fixtures/mixed/mixed.rs", "-C", `link-arg=-Wl,-force_load,${lib}`, "-o", bin]);
if (b.code !== 0) {
  console.log(`FAIL build\n${b.out}${b.err}`);
  process.exit(1);
}

const syms = new Map<string, bigint>();
for (const l of run(["nm", bin]).out.split("\n")) {
  const m = l.match(/^([0-9a-f]+) T (_fx_\w+)$/);
  if (m) syms.set(m[2], BigInt(`0x${m[1]}`));
}
const fxd = syms.get("_fx_dwarf") ?? 0n;
const sentinel = syms.get("_fx_sentinel") ?? 0n;
const off = (fxd - 0x100000000n).toString(16).padStart(8, "0");
const ui = run([`${tools}/llvm-objdump`, "--unwind-info", bin]).out;
const enc = ui.match(new RegExp(`function offset=0x${off}, encoding=0x([0-9a-f]{8})`));
const mode = enc ? (parseInt(enc[1], 16) >>> 24) & 0xf : -1;
check("S1 dwarf-mode", mode === 3, enc ? `_fx_dwarf encoding 0x${enc[1]}` : "no __unwind_info entry for _fx_dwarf");

const frames = run([`${tools}/llvm-objdump`, "--dwarf=frames", bin]).out;
const fde = frames.match(new RegExp(`FDE cie=([0-9a-f]{8}) pc=0*${fxd.toString(16)}\\.\\.\\.([0-9a-f]+)`));
let cieOk = false;
let cieDetail = "no FDE for _fx_dwarf";
if (fde) {
  const block = frames.split("\n\n").find((s) => new RegExp(`^${fde[1]} [0-9a-f]{8} [0-9a-f]{8} CIE`, "m").test(s)) ?? "";
  const aug = block.match(/Augmentation:\s+"(\w+)"/)?.[1] ?? "?";
  const data = block.match(/Augmentation data:\s+([0-9A-F ]+)/)?.[1]?.trim() ?? "?";
  cieOk = aug === "zPLR" && data.startsWith("9B");
  cieDetail = `CIE ${fde[1]} augmentation ${aug} data ${data}`;
}
check("S2 cie-0x9b", cieOk, cieDetail);
const fdeEnd = fde ? BigInt(`0x${fde[2]}`) : -1n;
check("S3 sentinel-next", fdeEnd === sentinel, `FDE end 0x${fdeEnd.toString(16)} _fx_sentinel 0x${sentinel.toString(16)}`);
const sizes = run(["size", "-m", bin]).out;
const fxc = syms.get("_fx_compact") ?? 0n;
const encC = ui.match(new RegExp(`function offset=0x${(fxc - 0x100000000n).toString(16).padStart(8, "0")}, encoding=0x([0-9a-f]{8})`));
const cbits = encC ? parseInt(encC[1], 16) : 0;
check("S5 compact-frame", ((cbits >>> 24) & 0xf) === 4 && (cbits & 0x103) === 0x103, encC ? `_fx_compact encoding 0x${encC[1]} (FRAME, x19/x20 x21/x22 d8/d9 pairs)` : "no __unwind_info entry for _fx_compact");
const eko = sizes.match(/Section __eko_unwind: (\d+)/);
check("S4 eko-section", !!eko, eko ? `__eko_unwind ${eko[1]} bytes` : "missing");

for (const [name, mode] of [["R1 regcheck", "regcheck"], ["R2 panic", "panic"]]) {
  const r = run([bin, mode]);
  const text = `stdout:\n${r.out}stderr:\n${r.err}status: ${r.sig ? `signal ${r.sig}` : `exit ${r.code}`}\n`;
  writeFileSync(join(out, `${mode}.txt`), text);
  const exp = join(root, "fixtures/mixed/expected", `${mode}.txt`);
  if (writeExpected) writeFileSync(exp, text);
  const want = readFileSync(exp, "utf8");
  check(name, text === want, text === want ? "identical to expected" : `differs:\n${text}`);
}

const l = run(["lldb", "--batch", "-o", "b fx_trace_cb", "-o", "run bt", "-o", "bt", "-o", "breakpoint delete -f", "-o", "continue", "--", bin, "bt"], 120000);
writeFileSync(join(out, "lldb.txt"), l.out + l.err);
// lldb lists inlined frames; a physical frame is a run of [inlined] lines
// ended by one plain line, and its pc is the pc shown on the first line.
const lldbFrames: { ip: bigint; name: string }[] = [];
let groupIp: bigint | null = null;
for (const line of l.out.split("\n")) {
  const m = line.match(/frame #\d+: 0x([0-9a-f]+) (\S+)/);
  if (!m) continue;
  if (groupIp === null) groupIp = BigInt(`0x${m[1]}`);
  if (line.includes("[inlined]")) continue;
  lldbFrames.push({ ip: groupIp, name: m[2] });
  groupIp = null;
}
const uw = [...l.out.matchAll(/^uw \d+ ip 0x([0-9a-f]+) cfa/gm)].map((m) => BigInt(`0x${m[1]}`));
const start = lldbFrames.findIndex((f) => uw.length > 0 && f.ip === uw[0]);
let same = start >= 0 && uw.length > 0;
const rows: string[] = [];
for (let i = 0; start >= 0 && i < Math.max(uw.length, lldbFrames.length - start); i++) {
  const f = lldbFrames[start + i];
  const u = uw[i];
  if (u !== undefined && (!f || f.ip !== u)) same = false;
  rows.push(`  ${String(i).padStart(2)} uw ${u !== undefined ? `0x${u.toString(16)}` : "(stop)".padEnd(11)} lldb ${f ? `0x${f.ip.toString(16)} ${f.name}` : "-"}`);
}
const extra = start >= 0 ? lldbFrames.slice(start + uw.length).map((f) => f.name) : [];
check("B1 bt-vs-lldb", same, `${uw.length} frames equal; lldb continues with ${extra.join(", ") || "nothing"}\n${rows.join("\n")}`);

const sysBin = join(out, "mixed_sys");
const sb = run([rustc, "--edition", "2021", "-O", "-C", "panic=unwind", "-C", "debuginfo=2", "fixtures/mixed/mixed.rs", "-o", sysBin]);
const p1 = run([sysBin, "btplain"]);
const p2 = run([bin, "btplain"]);
writeFileSync(join(out, "btplain.sys.txt"), p1.out);
writeFileSync(join(out, "btplain.ps.txt"), p2.out);
check("B2 plain-vs-system", sb.code === 0 && p1.out === p2.out && p1.out.length > 0, `system and ps-unwind _Unwind_Backtrace from main:\n${p2.out.trimEnd()}`);

const bad = results.filter((r) => !r[1]).length;
console.log(bad === 0 ? "mixed: PASS" : `mixed: FAIL (${bad})`);
process.exit(bad === 0 ? 0 : 1);
