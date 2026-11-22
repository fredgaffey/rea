import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { onTestFinished } from "vitest";

const FIXTURE = fileURLToPath(
  new URL("./hbc2jsProcessTree.mjs", import.meta.url),
);

/** Write an executable POSIX launcher that runs the fake hbc2js in one mode. */
export const writeHbc2jsLauncher = async (mode: string): Promise<string> => {
  const directory = await mkdtemp(join(tmpdir(), "rea-hbc2js-"));
  onTestFinished(() => rm(directory, { recursive: true, force: true }));
  const launcher = join(directory, "hbc2js");
  await writeFile(
    launcher,
    `#!/bin/sh\nexec "${process.execPath}" "${FIXTURE}" ${mode} "$@"\n`,
  );
  await chmod(launcher, 0o755);
  return launcher;
};
