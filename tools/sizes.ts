// Size report.
//   bun tools/sizes.ts lib                 shipped archive and object per target
//   bun tools/sizes.ts image <macho>       __eh_frame + __gcc_except_tab (and
//        __unwind_info) of a linked arm64 Mach-O image against what the EKO v1
//        table (docs/FORMAT.md) would need for the same functions:
//        16-byte chunk header + 16 bytes per function + for each function with
//        an LSDA, 4 + 12 bytes per call site that has a landing pad.
//        Functions are the distinct addresses of __TEXT,__text symbols; LSDAs
//        come from the __unwind_info LSDA index; call sites are parsed here.
import { readFileSync, statSync, existsSync } from "fs";
import { join, resolve } from "path";

const root = resolve(import.meta.dir, "..");
const sysroot = Bun.spawnSync({ cmd: ["rustc", "--print", "sysroot"], stdout: "pipe" }).stdout.toString().trim();
const tools = `${sysroot}/lib/rustlib/aarch64-apple-darwin/bin`;
const sh = (cmd: string[]) => Bun.spawnSync({ cmd, stdout: "pipe", stderr: "pipe" }).stdout.toString();

if (process.argv[2] === "lib") {
  for (const t of ["", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"]) {
    const d = join(root, "target/dist", t);
    const a = join(d, "libps_unwind.a");
    if (!existsSync(a)) { console.log(`${t || "aarch64-apple-darwin"}: not built`); continue; }
    const sz = sh([`${tools}/llvm-size`, join(d, "ps_unwind.o")]).trim().split("\n").pop()!.trim().split(/\s+/);
    console.log(`${(t || "aarch64-apple-darwin").padEnd(28)} libps_unwind.a ${statSync(a).size} B, ps_unwind.o ${statSync(join(d, "ps_unwind.o")).size} B, text ${sz[0]} data ${sz[1]} bss ${sz[2]}`);
  }
  process.exit(0);
}

const img = resolve(process.argv[3]);
const bytes = readFileSync(img);
const sects = new Map<string, { addr: number; size: number; offset: number }>();
let cur: string | null = null;
let rec: any = {};
for (const line of sh(["otool", "-l", img]).split("\n")) {
  const t = line.trim().split(/\s+/);
  if (t[0] === "sectname") { cur = t[1]; rec = {}; }
  else if (cur && t[0] === "addr") rec.addr = Number(BigInt(t[1]) - 0x100000000n);
  else if (cur && t[0] === "size") rec.size = Number(BigInt(t[1]));
  else if (cur && t[0] === "offset") { rec.offset = Number(t[1]); if (!sects.has(cur)) sects.set(cur, rec); cur = null; }
}
const size = (n: string) => sects.get(n)?.size ?? 0;

const funcs = new Set(sh(["nm", "-n", "-s", "__TEXT", "__text", img]).split("\n").map((l) => l.split(" ")[0]).filter((a) => /^[0-9a-f]+$/.test(a)));
const ui = sh([`${tools}/llvm-objdump`, "--unwind-info", img]);
const lsdas = [...ui.matchAll(/^\s+\[\d+\]: function offset=0x([0-9a-f]+), LSDA offset=0x([0-9a-f]+)$/gm)].map((m) => parseInt(m[2], 16));
const gx = sects.get("__gcc_except_tab")!;
let at = 0;
const u8 = () => bytes[at++];
const uleb = () => { let r = 0, s = 0, b; do { b = u8(); r += (b & 0x7f) * 2 ** s; s += 7; } while (b & 0x80); return r; };
const u32 = () => { const v = bytes.readUInt32LE(at); at += 4; return v; };
let rows = 0, pads = 0, refused = 0;
for (const off of lsdas) {
  at = gx.offset + (off - gx.addr);
  if (u8() !== 0xff) { refused++; continue; }
  if (u8() !== 0xff) uleb();
  const enc = u8();
  const len = uleb();
  const end = at + len;
  let n = 0;
  while (at < end) {
    const rd = enc === 0x01 ? uleb : enc === 0x03 ? u32 : null;
    if (!rd) { refused++; break; }
    rd(); rd();
    const lp = rd();
    uleb();
    if (lp !== 0) n++;
  }
  rows += n;
  if (n > 0) pads++;
}
const platform = size("__eh_frame") + size("__gcc_except_tab");
const eko = 16 + 16 * funcs.size + pads * 4 + rows * 12;
console.log(`image ${img.replace(root + "/", "")}`);
console.log(`  functions ${funcs.size}, with LSDA ${lsdas.length}, with landing pads ${pads}, landing-pad call sites ${rows}${refused ? `, LSDAs not parsed ${refused}` : ""}`);
console.log(`  __eh_frame ${size("__eh_frame")} + __gcc_except_tab ${size("__gcc_except_tab")} = ${platform} B (plus __unwind_info ${size("__unwind_info")} B)`);
console.log(`  EKO v1 for the same functions: 16 + 16*${funcs.size} + 4*${pads} + 12*${rows} = ${eko} B`);
console.log(`  Linux, EKO replaces CFI + LSDA of EKO functions: ratio EKO / (__eh_frame + __gcc_except_tab) = ${(eko / platform).toFixed(3)}`);
const darwinNow = platform + size("__unwind_info");
console.log(`  Darwin, EKO is added (the platform tables stay): ${darwinNow} + ${eko} = ${darwinNow + eko} B, +${((100 * eko) / darwinNow).toFixed(1)}% unwind data`);
