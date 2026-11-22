/** The machine contract REA admits. hbc2js keeps it additive within a number. */
export const HBC2JS_CONTRACT = 1;
/** The hbc2js release this adapter's replies were captured from. */
export const HBC2JS_VERIFIED_VERSION = "0.1.0";

/** Admission of one hbc2js `--version --json` reply. */
export type Hbc2jsVersionAdmission =
  | { readonly status: "verified"; readonly version: string }
  | {
      readonly status: "compatible";
      readonly version: string;
      readonly limitation: string;
    }
  | { readonly status: "unsupported"; readonly message: string };

/** Caller-facing statement of what is admitted. */
export const hbc2jsReleaseLine = (): string =>
  `hbc2js with machine contract ${String(HBC2JS_CONTRACT)} (verified with ${HBC2JS_VERIFIED_VERSION})`;

/** Disclaimer carried by every result from a release other than the verified one. */
export const hbc2jsReleaseLimitation = (version: string): string =>
  `This inspection uses caller-supplied hbc2js ${version}. REA verified the argument and reply parsing against ${HBC2JS_VERIFIED_VERSION}; other releases that report contract ${String(HBC2JS_CONTRACT)} are admitted and the observed version is reported.`;

/** Classify one version reply against the admitted contract. */
export const admitHbc2jsVersion = (reply: {
  readonly hbc2js: string;
  readonly contract: number;
}): Hbc2jsVersionAdmission => {
  if (reply.contract !== HBC2JS_CONTRACT)
    return {
      status: "unsupported",
      message: `Unsupported hbc2js ${reply.hbc2js}: it reports machine contract ${String(reply.contract)}; accepted is ${hbc2jsReleaseLine()}`,
    };
  if (reply.hbc2js === HBC2JS_VERIFIED_VERSION)
    return { status: "verified", version: reply.hbc2js };
  return {
    status: "compatible",
    version: reply.hbc2js,
    limitation: hbc2jsReleaseLimitation(reply.hbc2js),
  };
};
