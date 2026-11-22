// Fake hbc2js launcher. Replies are abridged copies of real `hbc2js-machine/1`
// output captured from hbc2js 0.1.2 on a small Hermes bytecode v96 file.
// argv: <mode> <hbc2js arguments...>
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
const VERSION = {
  schema: "hbc2js-machine/1",
  kind: "version",
  ok: true,
  hbc2js: "0.1.2",
  contract: 1,
  hbcVersions: [84, 94, 96, 98, 99],
  node: "24.22.1",
};
const INFO = {
  schema: "hbc2js-machine/1",
  kind: "info",
  ok: true,
  hbc2js: "0.1.2",
  input: {
    sha256: "8dea0f0c9466dd2891bb67b367c9dca1d9c1acaf58293220663b9114c7aa533a",
    bytes: 859,
  },
  warnings: [],
  version: 96,
  layoutClass: "C",
  opcodeTable: "hbc96",
  probe: {
    candidates: [{ layoutClass: "C", passed: true }],
    chosen: "C/hbc96",
    forced: false,
    decidedBy: ["P2", "version"],
    exhaustive: true,
    sampledFunctions: 2,
    totalFunctions: 2,
  },
  functionCount: 2,
  stringCount: 15,
  sections: [
    { name: "header", offset: 0, size: 128 },
    { name: "functionHeaders", offset: 128, size: 32 },
  ],
  diagnostics: [],
};
const ERROR = {
  schema: "hbc2js-machine/1",
  kind: "error",
  ok: false,
  code: "E_IO",
  message: "cannot read /nonexistent: ENOENT",
  error: {
    code: "E_IO",
    message: "cannot read /nonexistent: ENOENT",
    context: {},
  },
};

const [mode, ...args] = process.argv.slice(2);
const emit = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);

// The digest of the file argv names, as the real tool reports it.
const inputOf = () => {
  const file = args.find(
    (arg, index) =>
      index > 0 &&
      !arg.startsWith("-") &&
      !/^\d+$/u.test(arg) &&
      args[index - 1] !== "--offset" &&
      args[index - 1] !== "--limit",
  );
  try {
    const bytes = readFileSync(file);
    return {
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
    };
  } catch {
    return INFO.input;
  }
};
const ROWS = [
  { id: 0, factoryFn: 74, deps: [1, 3], fnCount: 2 },
  { id: 1, factoryFn: 76, deps: [2], fnCount: 5 },
  { id: 2, factoryFn: 80, deps: [], fnCount: 1 },
];
const WARNING = {
  code: "W_LAYOUT_ASSUMED",
  message: "opcode table assumed, not proven; pass --layout to override",
};
const modulesReply = () => {
  const offset = Number(args[args.indexOf("--offset") + 1] ?? 0);
  const limit = Number(args[args.indexOf("--limit") + 1] ?? 200);
  const rows = mode === "no-metro" ? [] : ROWS.slice(offset, offset + limit);
  const next = offset + rows.length;
  return {
    schema: "hbc2js-machine/1",
    kind: "modules",
    ok: true,
    hbc2js: "0.1.2",
    input: inputOf(),
    warnings: mode === "warn" ? [WARNING] : [],
    metro: mode !== "no-metro",
    total: mode === "no-metro" ? 0 : ROWS.length,
    offset,
    rows,
    next: mode !== "no-metro" && next < ROWS.length ? next : null,
  };
};

// `decompile --fn N|--module M --json [--passes=none]` as a function reply.
const decompileReply = () => {
  const flag = (name) => {
    const at = args.indexOf(name);
    return at === -1 ? null : Number(args[at + 1]);
  };
  const module = flag("--module");
  const fn = module === null ? flag("--fn") : module + 74;
  const passes = args.includes("--passes=none") ? "none" : "default";
  const body =
    mode === "big-source"
      ? "  // padding\n".repeat(2_000)
      : `  // NODE_OPTIONS=${process.env.NODE_OPTIONS ?? ""}\n`;
  return {
    schema: "hbc2js-machine/1",
    kind: "function",
    ok: true,
    hbc2js: "0.1.0",
    input: inputOf(),
    warnings: [],
    fn,
    name: module === null ? "i" : "",
    moduleId: module,
    factoryOf: module,
    source: `function _fn${fn}(a1) {\n${body}  return a1;\n}\n`,
    verified: { structurer: true, syntax: mode !== "verify-fail" },
    passes,
  };
};
const hangsOnDecompile =
  args[0] === "decompile" &&
  (mode === "hang-decompile" || mode === "ignore-sigterm-decompile");

if (hangsOnDecompile) {
  if (mode === "ignore-sigterm-decompile") process.on("SIGTERM", () => {});
  setInterval(() => {}, 1_000);
} else if (mode === "hang") {
  setInterval(() => {}, 1_000);
} else if (mode === "ignore-sigterm") {
  process.on("SIGTERM", () => {});
  setInterval(() => {}, 1_000);
} else if (mode === "not-json") {
  process.stdout.write("hbc2js 0.1.2\n");
} else if (mode === "contract-2") {
  emit({ ...VERSION, schema: "hbc2js-machine/2", contract: 2 });
} else if (mode === "contract-2-same-schema") {
  emit({ ...VERSION, contract: 2 });
} else if (mode === "newer-version") {
  emit({ ...VERSION, hbc2js: "0.4.2" });
} else if (mode === "error") {
  emit(ERROR);
  process.exitCode = 2;
} else if (mode === "fail-exit") {
  process.stderr.write("boom\n");
  process.exitCode = 1;
} else if (args.includes("--version")) {
  emit(VERSION);
} else if (mode === "info-error") {
  emit(ERROR);
  process.exitCode = 2;
} else if (args.includes("--info")) {
  const input = inputOf();
  emit({
    ...INFO,
    input:
      mode === "digest-mismatch" ? { ...input, sha256: "0".repeat(64) } : input,
    warnings: mode === "warn" ? [WARNING] : [],
  });
} else if (args[0] === "decompile" && mode === "resource") {
  const message = "E_RESOURCE: estimated heap 4096 MB exceeds the 512 MB limit";
  emit({
    schema: "hbc2js-machine/1",
    kind: "error",
    ok: false,
    code: "E_RESOURCE",
    message,
    error: { code: "E_RESOURCE", message, context: { requiredMb: 4096 } },
  });
  process.exitCode = 3;
} else if (args[0] === "decompile") {
  emit(decompileReply());
  if (mode === "verify-fail") process.exitCode = 5;
} else if (args[0] === "modules") {
  emit(modulesReply());
} else {
  process.stderr.write(`unexpected invocation: ${args.join(" ")}\n`);
  process.exitCode = 2;
}
