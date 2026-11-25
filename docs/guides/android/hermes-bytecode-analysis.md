# React Native Hermes bytecode analysis

React Native apps built for Hermes ship their JavaScript as Hermes bytecode (HBC)
instead of source. REA reads that bytecode through the caller's hbc2js
launcher: an offline decompiler that turns an `.hbc` file into JavaScript. REA never
installs hbc2js, and no tool executes the target bytecode.

The family has three tools:

| Tool                        | Answers                                                                        |
| --------------------------- | ------------------------------------------------------------------------------ |
| `inspect_hbc2js_client`     | Which launcher REA selected, its version, machine contract and HBC versions    |
| `inspect_hermes_bytecode`   | Digest, HBC version, probe decision, sections, and a page of the Metro modules |
| `decompile_hermes_function` | One function or one Metro module factory as JavaScript                         |

## Supply tools

hbc2js is bring-your-own. Select the launcher through the environment:

```sh
# Optional: absolute path to the hbc2js launcher; without it, hbc2js resolves from PATH.
export REA_HBC2JS_COMMAND=/absolute/path/hbc2js
```

Readiness is `rea inspect-hbc2js-client`: it runs `hbc2js --version --json`. REA
requires `contract` 1 in the reply. Use hbc2js 0.1.2 (published on npm; REA's parsing fixtures were captured from it and the `verify:hbc2js` lane passes against it on macOS). `verified` admission is that release; `compatible` is another release of the same contract and
carries a limitation. A missing launcher reports `capability_unavailable` with the
`REA_HBC2JS_COMMAND` remediation. A launcher on another contract is refused.

## Answer an analyst question

```sh
rea inspect-hbc2js-client
rea inspect-hermes-bytecode /targets/index.android.hbc --module-limit 50
rea decompile-hermes-function /targets/index.android.hbc --module-id 0
rea decompile-hermes-function /targets/index.android.hbc --function-index 3 --passes none
rea decompile-hermes-function /targets/index.android.hbc --function-index 3 --decompile-timeout-ms 600000 --max-heap-mb 4096
```

The `.hbc` is the file Metro and Hermes produced, for example
`index.android.bundle` extracted from an APK. REA does not unpack the APK for these
tools.

`inspect_hermes_bytecode` reports REA's own SHA-256 and size of the file and
cross-checks them against hbc2js's digest; a mismatch fails the call. Header and
section facts are observations. The layout and opcode-table choice (`probe`) and
the module table are derivations. Module ids are numeric Metro ids; hbc2js recovers no
file names. `metro_detected: false` means no Metro `__d` table was found in the
global function, not that the bundle has no modules. Page with
`module_offset` and `module_limit`, following `page.next_offset`. Each hbc2js
`W_*` warning is a limitation; `W_LAYOUT_ASSUMED` means the opcode table was
assumed, not proven.

`decompile_hermes_function` takes `path`, exactly one of `function_index` and
`module_id` (a module id decompiles that module's factory function), and `passes`
(`default`, or `none` for the structured output without readability passes). It
returns `source`, the function `name`, `module_id`, `factory_of`, `verification`, the
`passes` used, and the target digest cross-checked against hbc2js's.

## What the source means

The source is a derivation, not a recovery:

- Names are synthesized. Original identifiers are not in the bytecode.
- Identifiers captured from enclosing functions are declared by parents that
  are not shown, so they appear free.
- REA does not claim semantic equivalence. `verification` reports hbc2js's own
  structure and syntax self-checks only.
- When hbc2js exits 5 (`verification.syntax: false`) REA still returns the source,
  with a limitation: the text may not parse.

## Limits and recovery

| Control                                                | Default              | Where it applies                          |
| ------------------------------------------------------ | -------------------- | ----------------------------------------- |
| `decompile_timeout_ms` (`hbc2js.decompile_timeout_ms`) | 300000 ms            | Wall clock for one decompile process      |
| `max_heap_mb` (`hbc2js.max_heap_mb`)                   | unset (Node default) | V8 old-space of the hbc2js process        |
| `max_source_bytes`                                     | 262144 bytes         | Source returned; a longer function is cut |
| `output_limit_bytes`                                   | 8388608 bytes        | Output captured per hbc2js decoding run   |
| `version_output_limit_bytes`                           | 65536 bytes          | Output captured from `--version --json`   |

- Each control is a per-call parameter and a runtime analysis setting; the parameter
  wins, then the setting, then the default. `update_analysis_settings` changes a
  setting without restarting REA; it applies to the next call.
- A deadline stops hbc2js and its process tree and reports the setting id. Raise
  `decompile_timeout_ms`, and allow cleanup headroom in the outer MCP client deadline.
  The version probe has its own fixed 20 s deadline that this does not raise.
- `max_heap_mb` is passed to the child as `NODE_OPTIONS=--max-old-space-size=<MB>`.
  Nothing else in the environment is persisted. When hbc2js estimates it needs more
  memory it fails fast with `E_RESOURCE`; REA reports the tool's `requiredMb` and names
  `hbc2js.max_heap_mb` as the recovery.
- `truncated: true` carries `source_bytes` (the full size) and a `recovery`. Raise
  `max_source_bytes`, or decompile a smaller function. The source is never paged.
- `output_limit_bytes` (at most 67108864) and `version_output_limit_bytes` (at most 1048576) are per-call parameters on every hbc2js tool; they have no runtime setting.
  When a capture is exhausted the refusal names the parameter, its default and its
  maximum. Raise it on the next call; no restart is needed.
- `inspect_hermes_bytecode` keeps a fixed 120 s deadline per hbc2js command.

## Real verification

`npm run verify:hbc2js` drives all three tools through the compiled CLI and a stdio
MCP server against a real launcher. It skips with a message, and claims no coverage,
when hbc2js is missing, lacks contract 1, or no sample is available. See
[Testing lanes](../../testing-lanes.md#hbc2js-hermes-bytecode).
