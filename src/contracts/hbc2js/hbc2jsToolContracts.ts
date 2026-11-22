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
] as const satisfies readonly ToolContract[];
