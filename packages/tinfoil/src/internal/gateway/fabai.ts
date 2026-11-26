/**
 * Checks FabAI's gateway options before any network I/O; every failure is a
 * {@link ConfigurationError}.
 *
 * @experimental FabAI's gateway options; see {@link GatewayOptions}.
 */
import { ConfigurationError } from "../../errors.js";
import type { GatewayOptions } from "../../options.js";
import { TRUSTED_REPO_OWNER } from "./catalog.js";

/** A GitHub user or organization name. */
const GITHUB_OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;

const SEAL_CHECK_REPLACES = "sealCheck replaces the verifier: leave verifier, verificationCheck and every model pin's verifier unset";

/** The repository owner the options select, ending in a slash. */
export function checkFabAIOptions(options: GatewayOptions): string {
  if (options.sealCheck !== undefined) {
    if (typeof options.sealCheck !== "function") throw new ConfigurationError("sealCheck must be a function");
    if (options.verifier !== undefined || options.verificationCheck !== undefined) throw new ConfigurationError(SEAL_CHECK_REPLACES);
    for (const pin of options.modelPins?.values() ?? []) {
      if (pin.verifier !== undefined) throw new ConfigurationError(SEAL_CHECK_REPLACES);
    }
  }
  if (options.repositoryOwner === undefined) return TRUSTED_REPO_OWNER;
  if (!GITHUB_OWNER.test(options.repositoryOwner)) {
    throw new ConfigurationError(`repository owner ${JSON.stringify(options.repositoryOwner)} isn't a GitHub user or organization name`);
  }
  return `${options.repositoryOwner}/`;
}
