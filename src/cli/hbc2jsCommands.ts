import type { RequestAnalysisPort } from "../ports/AnalysisProvider.js";
import type { Hbc2jsRequest } from "../domain/hbc2js/hermesBytecode.js";
import { createHermesBytecodeAnalysisService } from "../application/ProviderOperationServices.js";
import { createHermesBytecodeAnalysisProvider } from "../composition/hbc2js.js";
import { HBC2JS_TOOL_CONTRACTS } from "../contracts/hbc2js/hbc2jsToolContracts.js";
import type { Hbc2jsOperation } from "../domain/hbc2js/hermesBytecode.js";
import type { Logger } from "pino";
import { contractNamed } from "./contractCliDescription.js";
import { registerContractCommand } from "./contractCommand.js";
import {
  analyzeWithService,
  type EvidenceInspectionService,
} from "./contractCommandRunners.js";
import { finishCliEvidenceCommand } from "./cliEvidenceCallerPath.js";
import { projectCliAnalysisResult } from "./projectCliAnalysisResult.js";
import type { CliInstance } from "./types.js";

/** Expose the same explicit hbc2js requests through one-shot CLI commands. */
export const registerHbc2jsCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<Record<string, string | undefined>>,
  provider: RequestAnalysisPort<Hbc2jsRequest> = createHermesBytecodeAnalysisProvider(
    environment,
  ),
): void => {
  const service = createHermesBytecodeAnalysisService(provider);
  const run =
    (operation: Hbc2jsOperation) => (): EvidenceInspectionService => ({
      inspect: (input, { signal }) =>
        service.execute(operation, input, { signal }),
      close: () => provider.close(),
    });

  registerContractCommand(
    cli,
    logger,
    contractNamed(HBC2JS_TOOL_CONTRACTS, "inspect_hbc2js_client"),
    {
      description:
        "Inspect the caller-selected hbc2js launcher without reading any target",
    },
    analyzeWithService(run("inspect_hbc2js_client"), "hbc2js"),
  );
  registerContractCommand(
    cli,
    logger,
    contractNamed(HBC2JS_TOOL_CONTRACTS, "inspect_hermes_bytecode"),
    {
      description:
        "Inspect a Hermes bytecode file through hbc2js: digest, version, probe decision, sections and Metro modules",
      positionals: ["path"],
    },
    (input, { operation, signal }) => {
      const owned = run("inspect_hermes_bytecode")();
      return finishCliEvidenceCommand(
        input.path,
        () => owned.inspect(input, { signal }),
        owned,
        "hbc2js",
        operation,
        signal,
      ).then(projectCliAnalysisResult);
    },
  );
  registerContractCommand(
    cli,
    logger,
    contractNamed(HBC2JS_TOOL_CONTRACTS, "decompile_hermes_function"),
    {
      description:
        "Decompile one function or Metro module factory of a Hermes bytecode file through hbc2js",
      positionals: ["path"],
    },
    (input, { operation, signal }) => {
      const owned = run("decompile_hermes_function")();
      return finishCliEvidenceCommand(
        input.path,
        () => owned.inspect(input, { signal }),
        owned,
        "hbc2js",
        operation,
        signal,
      ).then(projectCliAnalysisResult);
    },
  );
};
