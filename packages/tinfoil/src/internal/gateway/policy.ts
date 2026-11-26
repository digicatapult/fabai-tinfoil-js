/**
 * Which repository a model's replicas are verified against, and under which
 * policy: a pin the caller set, or the untrusted catalog's repository under
 * the default policy. Pinned-only mode serves nothing else.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
import { parseReference, Verifier } from "@tinfoilsh/verifier";
import { AttestationError, ConfigurationError, messageOf } from "../../errors.js";
import type { Catalog, ModelPin } from "../../options.js";
import { TRUSTED_REPO_OWNER, trusted } from "./catalog.js";

/**
 * A replica to verify: its host, the reference it is verified against, and the model whose pin set the reference, if any.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export interface Replica {
  readonly host: string;
  readonly ref: string;
  readonly model: string;
}

/**
 * The key under which a replica's transport is kept.
 *
 * @experimental The gateway route is new; this API may change without a major version.
 */
export function replicaKey(r: Replica): string {
  return `${r.host}\0${r.ref}\0${r.model}`;
}

interface ResolvedPin {
  readonly repo: string;
  readonly verifier: Verifier;
}

/** @experimental The gateway route is new; this API may change without a major version. */
export class GatewayPolicy {
  readonly #pins: ReadonlyMap<string, ResolvedPin>;
  readonly #pinnedOnly: boolean;
  readonly #verifier: Verifier;
  /** The repository owner, ending in a slash. */
  readonly #owner: string;

  private constructor(pins: ReadonlyMap<string, ResolvedPin>, pinnedOnly: boolean, verifier: Verifier, owner: string) {
    this.#pins = pins;
    this.#pinnedOnly = pinnedOnly;
    this.#verifier = verifier;
    this.#owner = owner;
  }

  /** Checks the pins, which must name repositories of `owner` (ending in a slash), and the policies; every failure is a {@link ConfigurationError}. */
  static async create(modelPins: ReadonlyMap<string, ModelPin> | undefined, pinnedOnly: boolean, verifier: Verifier | undefined, owner = TRUSTED_REPO_OWNER): Promise<GatewayPolicy> {
    const pins = modelPins ?? new Map<string, ModelPin>();
    if (pinnedOnly && pins.size === 0) throw new ConfigurationError("pinned-only mode requires at least one model pin");
    if (verifier === undefined) {
      try {
        verifier = await Verifier.create();
      } catch (err) {
        throw new ConfigurationError(`gateway verification options: ${messageOf(err)}`, { cause: err });
      }
    }
    if (verifier.callerAuthorizesConfig) throw new ConfigurationError(CALLER_AUTHORIZED);
    const resolved = new Map<string, ResolvedPin>();
    for (const [model, pin] of pins) {
      if (pin.verifier?.callerAuthorizesConfig) throw new ConfigurationError(`model ${JSON.stringify(model)}: ${CALLER_AUTHORIZED}`);
      if (model.trim() === "" || !pin.repo.startsWith(owner)) {
        throw new ConfigurationError(`model pin ${JSON.stringify(model)} repository ${JSON.stringify(pin.repo)} must belong to ${owner}`);
      }
      try {
        parseReference(pin.repo);
      } catch (err) {
        throw new ConfigurationError(`model ${JSON.stringify(model)}: ${messageOf(err)}`, { cause: err });
      }
      resolved.set(model, { repo: pin.repo, verifier: pin.verifier ?? verifier });
    }
    return new GatewayPolicy(resolved, pinnedOnly, verifier, owner);
  }

  /**
   * The replica hosts serving `model` and what they are verified against. A
   * model the policy doesn't serve is a {@link ConfigurationError}; a catalog
   * offering a pinned model from another repository is an
   * {@link AttestationError}.
   */
  resolve(model: string, catalog: Catalog): { hosts: readonly string[]; replica: Omit<Replica, "host"> } {
    const pin = this.#pins.get(model);
    if (this.#pinnedOnly && pin === undefined) throw new ConfigurationError(`model ${JSON.stringify(model)} is not pinned`);
    const entry = catalog.get(model);
    if (!trusted(entry, this.#owner)) {
      throw new ConfigurationError(`model ${JSON.stringify(model)} has no valid bare ${this.#owner} repository with replicas in the gateway catalog`);
    }
    if (pin !== undefined) {
      const repo = pin.repo.split("@", 1)[0]!;
      if (entry.repo !== repo) {
        throw new AttestationError(`model ${JSON.stringify(model)}: expected repository ${JSON.stringify(repo)}, gateway offered ${JSON.stringify(entry.repo)}`);
      }
      return { hosts: entry.hosts, replica: { ref: pin.repo, model } };
    }
    return { hosts: entry.hosts, replica: { ref: entry.repo, model: "" } };
  }

  /** Whether the policy serves `model` from `catalog`. */
  serves(model: string, catalog: Catalog): boolean {
    try {
      this.resolve(model, catalog);
      return true;
    } catch {
      return false;
    }
  }

  /** The repository owner, ending in a slash. */
  owner(): string {
    return this.#owner;
  }

  /** The policy a replica of `r` is verified under. */
  verifierFor(r: Omit<Replica, "host">): Verifier {
    return this.#pins.get(r.model)?.verifier ?? this.#verifier;
  }
}

/** Gateway replicas are verified against repository pins, so a config the caller supplies or authorizes has no place. */
const CALLER_AUTHORIZED = "caller-authorized config requires a direct enclave client";
