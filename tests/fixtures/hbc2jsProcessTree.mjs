// Fake hbc2js launcher. Replies are abridged copies of real `hbc2js-machine/1`
// output captured from hbc2js 0.1.0 on a small Hermes bytecode v96 file.
// argv: <mode> <hbc2js arguments...>
const VERSION = {
  schema: "hbc2js-machine/1",
  kind: "version",
  ok: true,
  hbc2js: "0.1.0",
  contract: 1,
  hbcVersions: [84, 94, 96, 98, 99],
  node: "24.22.1",
};
const INFO = {
  schema: "hbc2js-machine/1",
  kind: "info",
  ok: true,
  hbc2js: "0.1.0",
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

if (mode === "hang") {
  setInterval(() => {}, 1_000);
} else if (mode === "ignore-sigterm") {
  process.on("SIGTERM", () => {});
  setInterval(() => {}, 1_000);
} else if (mode === "not-json") {
  process.stdout.write("hbc2js 0.1.0\n");
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
} else if (args.includes("--info")) {
  emit(INFO);
} else {
  process.stderr.write(`unexpected invocation: ${args.join(" ")}\n`);
  process.exitCode = 2;
}
