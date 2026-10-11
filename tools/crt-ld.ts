// crt linker driver. rustc runs it as -C linker with -C link-self-contained=no,
// so rustc names no crt object itself. This driver builds the start/end of the
// line and hands it to rust-lld (flavor gnu):
//   executable:     <start> crti.o crtbegin.o  ...rustc args...  crtend.o crtn.o
//   shared object:          crti.o crtbeginS.o ...rustc args...  crtendS.o crtn.o
// <start> is rcrt1.o for a static PIE, crt1.o otherwise (libc objects, kept).
// C1: any crtbegin*.o, crtend*.o or crtfastmath.o not from PS_UNWIND_CRT_DIR on the
// line fails the link by name before the linker runs.
// Env: PS_UNWIND_CRT_DIR (our objects), PS_UNWIND_CRT_LIBC_DIR (crt1.o, crti.o, crtn.o),
//      PS_UNWIND_CRT_MODE=none links with no crtbegin/crtend at all (the step 1
//      measurement), PS_UNWIND_CRT_ALLOW_FOREIGN=1 skips C1 (only for the C4 plant).
import { existsSync } from "fs";
import { basename, resolve } from "path";

const ours = resolve(process.env.PS_UNWIND_CRT_DIR ?? "");
const libc = process.env.PS_UNWIND_CRT_LIBC_DIR ?? "";
const mode = process.env.PS_UNWIND_CRT_MODE ?? "crt";
const args: string[] = [];
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "-flavor") { i++; continue; }
  args.push(argv[i]);
}
const foreign = args.filter((a) => /^(crtbegin|crtend)[^/]*\.o$|^crtfastmath\.o$/.test(basename(a)) && resolve(a).replace(/\/[^/]*$/, "") !== ours);
if (foreign.length && process.env.PS_UNWIND_CRT_ALLOW_FOREIGN !== "1") {
  for (const f of foreign) console.error(`FAIL C1 foreign crt object on the link line: ${f}`);
  process.exit(1);
}
if (!libc || !existsSync(`${libc}/crti.o`)) {
  console.error(`crt-ld: PS_UNWIND_CRT_LIBC_DIR has no crti.o: ${libc}`);
  process.exit(1);
}
const shared = args.includes("-shared");
const pie = args.includes("-pie");
const isStatic = args.includes("-static") || args.includes("-Bstatic");
const s = shared ? "S" : "";
const head: string[] = [];
if (!shared) head.push(`${libc}/${pie && isStatic ? "rcrt1.o" : pie ? "Scrt1.o" : "crt1.o"}`);
head.push(`${libc}/crti.o`);
const tail: string[] = [];
if (mode !== "none") { head.push(`${ours}/crtbegin${s}.o`); tail.push(`${ours}/crtend${s}.o`); }
tail.push(`${libc}/crtn.o`);
const r = Bun.spawnSync({ cmd: [process.env.PS_UNWIND_CRT_LLD ?? "rust-lld", "-flavor", "gnu", ...head, ...args, ...tail], stdout: "inherit", stderr: "inherit" });
process.exit(r.exitCode ?? 1);
