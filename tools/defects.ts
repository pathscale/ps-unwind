// Planted-defect runner. Each defect is an exact text substitution in src/.
// For each: plant, rebuild, run the verifiers (tools/mixed.ts and
// tools/eh.ts), require at least one named check to fail, revert
// with git checkout, rebuild, and require every verifier to pass again.
// Usage: bun tools/defects.ts [name...]
import { mkdirSync, readFileSync, writeFileSync } from "fs";
import { join, resolve } from "path";

const root = resolve(import.meta.dir, "..");
const tmp = join(root, "target/tmp");
mkdirSync(join(root, "target/defects"), { recursive: true });
const env = { PATH: process.env.PATH!, HOME: process.env.HOME!, TMPDIR: tmp };

const defects = [
  {
    name: "fde-off-by-one",
    what: "FDE range lookup off by one: the return address itself is used as the lookup key instead of return address minus one",
    file: "src/abi.rs",
    from: "if self.ip_before_insn { self.regs.pc } else { self.regs.pc - 1 }",
    to: "if self.ip_before_insn { self.regs.pc } else { self.regs.pc }",
  },
  {
    name: "0x9b-decode",
    what: "DW_EH_PE_indirect ignored, so 0x9b decodes to the GOT slot instead of the personality it holds",
    file: "src/mem.rs",
    from: "if encoding & DW_EH_PE_INDIRECT != 0 {",
    to: "if encoding & DW_EH_PE_INDIRECT != 0 && false {",
  },
  {
    name: "wrong-call-site",
    what: "EKO handler lookup returns the landing pad of the previous call site",
    file: "src/eko.rs",
    from: "let (r, pad, action) = row(mid);",
    to: "let (r, _, _) = row(mid); let (_, pad, action) = row(mid.saturating_sub(1));",
  },
  {
    name: "missing-callee-saved",
    what: "compact unwind FRAME step does not restore x22 (second register of the x21/x22 pair)",
    file: "src/compact.rs",
    from: "next.x[reg + 1] = unsafe { load::<usize>(loc) };",
    to: "if reg + 1 != 22 { next.x[reg + 1] = unsafe { load::<usize>(loc) }; }",
  },
];

function sh(cmd: string[]) {
  const r = Bun.spawnSync({ cmd, cwd: root, env, stdout: "pipe", stderr: "pipe", timeout: 600000 });
  return { code: r.exitCode, text: r.stdout.toString() + r.stderr.toString() };
}
function verifiers() {
  const m = sh(["bun", "tools/mixed.ts"]);
  const s = sh(["bun", "tools/eh.ts", "--no-lldb", "--no-linux"]);
  return { m, s, pass: m.code === 0 && s.code === 0 };
}
const summary = (t: string) => t.split("\n").filter((l) => /^(FAIL|eh: )/.test(l)).map((l) => l.slice(0, 200)).join("\n");

const pick = process.argv.slice(2);
let bad = 0;
for (const d of defects.filter((d) => pick.length === 0 || pick.includes(d.name))) {
  const path = join(root, d.file);
  const src = readFileSync(path, "utf8");
  const hits = src.split(d.from).length - 1;
  if (hits !== 1) {
    console.log(`REFUSED ${d.name}: anchor found ${hits} times in ${d.file}`);
    bad++;
    continue;
  }
  writeFileSync(path, src.replace(d.from, d.to));
  const diff = sh(["git", "diff", "--", d.file]).text;
  const build = sh(["./tools/build.sh"]);
  let log = `== defect ${d.name}: ${d.what}\n${diff}\n`;
  let caught = false;
  if (build.code !== 0) {
    log += `build failed:\n${build.text}\n`;
  } else {
    const v = verifiers();
    caught = !v.pass;
    log += `-- tools/mixed.ts (exit ${v.m.code})\n${v.m.text}\n-- tools/eh.ts (exit ${v.s.code})\n${summary(v.s.text)}\n`;
  }
  sh(["git", "checkout", "--", d.file]);
  const rebuilt = sh(["./tools/build.sh"]);
  const after = rebuilt.code === 0 ? verifiers() : null;
  const restored = !!after && after.pass;
  log += `-- reverted with git checkout -- ${d.file}; verifiers after revert: ${restored ? "PASS" : "FAIL"}\n`;
  log += `RESULT ${d.name}: ${caught ? "caught" : "NOT CAUGHT"}, ${restored ? "clean after revert" : "NOT CLEAN after revert"}\n`;
  writeFileSync(join(root, "target/defects", `${d.name}.txt`), log);
  console.log(log);
  if (!caught || !restored) bad++;
}
console.log(bad === 0 ? "defects: PASS (every planted defect failed a named check and was reverted)" : `defects: FAIL (${bad})`);
process.exit(bad === 0 ? 0 : 1);
