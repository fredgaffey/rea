import type { RequestAnalysisPort } from "../ports/AnalysisProvider.js";
import type { Hbc2jsRequest } from "../domain/hbc2js/hermesBytecode.js";
import { Hbc2jsProvider } from "../hbc2js/Hbc2jsProvider.js";
import { HOST_PLATFORM } from "../platform/HostPlatform.js";

/** Construct one hbc2js provider bound to the caller-selected launcher. */
export const createHermesBytecodeAnalysisProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
  platform: NodeJS.Platform = HOST_PLATFORM.platform,
): RequestAnalysisPort<Hbc2jsRequest> => new Hbc2jsProvider({ environment, platform });
