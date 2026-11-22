import {
  hbc2jsInputSchemas,
  hbc2jsResultSchemas,
} from "../../domain/hbc2js/hermesBytecode.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata, toolEffects } from "../toolEffects.js";

/** Hermes bytecode analysis served by a caller-supplied hbc2js launcher. */
export const HBC2JS_TOOL_CONTRACTS = [
  {
    name: "inspect_hbc2js_client",
    cli: true,
    ...toolContractMetadata(
      "inspect_hbc2js_client",
      toolEffects({
        mutatesSession: true,
        launchesProcess: true,
      }),
    ),
    description:
      "Inspect the caller-selected hbc2js launcher: resolved command, selection source, version, machine contract and the Hermes bytecode versions it accepts. Reads no target. REA never installs hbc2js; select a launcher with REA_HBC2JS_COMMAND (absolute) or hbc2js on PATH.",
    kind: "hbc2js-provider",
    inputSchema: hbc2jsInputSchemas.inspect_hbc2js_client,
    outputSchema: evidenceResultOf(hbc2jsResultSchemas.inspect_hbc2js_client),
    examples: [{ title: "Check the hbc2js launcher", input: {} }],
  },
  {
    name: "inspect_hermes_bytecode",
    cli: true,
    ...toolContractMetadata(
      "inspect_hermes_bytecode",
      toolEffects({ launchesProcess: true }),
    ),
    description:
      "Inspect a Hermes bytecode (.hbc) file through the caller-selected hbc2js launcher: REA's own sha256 and size (cross-checked against hbc2js), HBC version, layout and opcode table with the probe decision, function and string counts, sections, and a page of the Metro module table. Header and sections are observations; the probe choice and module table are derivations. Module ids are numeric Metro ids; metro_detected:false is a fact about the bundle, not an absence of modules. Static: the bytecode is never executed.",
    kind: "hbc2js-provider",
    inputSchema: hbc2jsInputSchemas.inspect_hermes_bytecode,
    outputSchema: evidenceResultOf(hbc2jsResultSchemas.inspect_hermes_bytecode),
    examples: [
      {
        title: "Inspect a bundle and its first modules",
        input: { path: "/targets/index.android.hbc", module_limit: 50 },
      },
    ],
  },
  {
    name: "decompile_hermes_function",
    cli: true,
    ...toolContractMetadata(
      "decompile_hermes_function",
      toolEffects({ launchesProcess: true }),
    ),
    description:
      "Decompile one function (function_index) or one Metro module factory (module_id) of a Hermes bytecode (.hbc) file to JavaScript through the caller-selected hbc2js launcher. The result is a derivation: names are synthesized, identifiers captured from enclosing functions appear free, and semantic equivalence to the bytecode is not claimed. verification.syntax:false returns the source with a limitation. Source is capped by max_source_bytes with truncated and a recovery; decompile_timeout_ms and max_heap_mb (settings hbc2js.decompile_timeout_ms, hbc2js.max_heap_mb) bound the hbc2js process. Static: the bytecode is never executed.",
    kind: "hbc2js-provider",
    inputSchema: hbc2jsInputSchemas.decompile_hermes_function,
    outputSchema: evidenceResultOf(
      hbc2jsResultSchemas.decompile_hermes_function,
    ),
    examples: [
      {
        title: "Decompile a Metro module factory",
        input: { path: "/targets/index.android.hbc", module_id: 0 },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
