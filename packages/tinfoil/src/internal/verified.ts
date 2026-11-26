/**
 * The verification cache a transport sits on. It verifies the enclave on
 * first use, and again when the verification expires or is invalidated, and
 * publishes each verification together with whatever a transport binds to
 * its keys, so a request never sends under keys other than those of the
 * verification it checked. Concurrent callers share one verification,
 * including its failure. No network I/O happens until the first request or
 * `ensureVerified`. For a single-use enclave (a seal check), each request
 * claims a verification of its own instead.
 */
import { AttestationError } from "../errors.js";
import { closedError } from "./dispose.js";
import { Enclave, FRESHNESS_EXPIRED, freshAt } from "./enclave.js";
import type { Verification } from "@tinfoilsh/verifier";
import type { Attested } from "./sealcheck.js";

/** One successful verification and what the transport bound to its keys. */
export interface State<T, V extends Attested = Attested> {
  readonly verification: V;
  readonly bound: T;
}

interface Entry<T, V extends Attested> extends State<T, V> {
  rejected: boolean;
  /** Set once a request has been sent under a single-use state, so no other request reuses it. */
  claimed: boolean;
}

/**
 * `V` is what the enclave's verifications are: {@link Attested} for an
 * enclave that may have a seal check, or {@link Verification}, the default,
 * for one that can't.
 */
export class VerifiedEnclave<T = void, V extends Attested = Verification> {
  readonly #enclave: Enclave;
  readonly #bind: (v: V) => T | Promise<T>;
  readonly #release: (bound: T) => void;
  readonly #clock: () => Date;
  #current: Entry<T, V> | undefined;
  /** The refresh in flight, shared by every caller that needs one. */
  #refreshing: Promise<void> | undefined;
  #closed = false;

  /**
   * `bind` makes what the transport ties to a verification's keys; a cache
   * that only caches verifications binds `() => undefined`. `release` is
   * called with a binding once its state is replaced or found expired, so
   * connections tied to retired keys are closed.
   */
  constructor(enclave: Enclave, bind: (v: V) => T | Promise<T>, clock: () => Date = () => new Date(), release: (bound: T) => void = () => {}) {
    this.#enclave = enclave;
    this.#bind = bind;
    this.#clock = clock;
    this.#release = release;
  }

  enclave(): Enclave {
    return this.#enclave;
  }

  /** A state valid now, verifying first only if the current one has expired or been invalidated. */
  ensureVerified(signal?: AbortSignal): Promise<State<T, V>> {
    return this.#verified(signal, false, false, (e) => e.attest());
  }

  /**
   * As {@link ensureVerified}, for a request about to be sent under the
   * state. For a single-use enclave, the state is claimed, and a claimed
   * state is never returned again, so each request gets a verification of
   * its own.
   */
  claim(signal?: AbortSignal): Promise<State<T, V>> {
    return this.#verified(signal, false, true, (e) => e.attest());
  }

  /** Verifies again even if the current verification is still valid. */
  reverify(signal?: AbortSignal): Promise<State<T, V>> {
    return this.#verified(signal, true, false, (e) => e.attest());
  }

  /** Verifies like {@link reverify} but without the retry, so a caller trying several enclaves moves on quickly. */
  verifyOnce(signal?: AbortSignal): Promise<State<T, V>> {
    return this.#verified(signal, true, false, (e) => e.attestOnce());
  }

  /** The last successful verification without checking it, or undefined before the first. */
  current(): V | undefined {
    return this.#current?.verification;
  }

  /** Marks the state a request was sent under rejected, so the next request verifies again; a replaced state leaves the current one valid. */
  invalidate(state: State<T, V>): void {
    if (this.#current !== undefined && this.#current.verification === state.verification) this.#current.rejected = true;
  }

  /**
   * Releases the current binding and verifies no more: every later call
   * for a state rejects as closed, and a refresh in flight releases what it
   * binds instead of publishing it. The last verification stays readable.
   * Closing again does nothing.
   */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#current !== undefined) this.#release(this.#current.bound);
  }

  #valid(entry: Entry<T, V>): boolean {
    return !entry.rejected && freshAt(entry.verification, this.#clock());
  }

  async #verified(signal: AbortSignal | undefined, force: boolean, claim: boolean, verify: (e: Enclave) => Promise<Attested>): Promise<State<T, V>> {
    const single = this.#enclave.singleUse();
    for (;;) {
      if (this.#closed) throw closedError();
      signal?.throwIfAborted();
      const current = this.#current;
      if (current !== undefined && this.#valid(current) && !force && !(single && current.claimed)) {
        if (single && claim) current.claimed = true;
        return current;
      }
      // A caller's cancellation does not abort a refresh other callers need,
      // so the refresh runs without the signal; the caller stops waiting.
      // That holds for a one-shot probe too: its fetch is bounded by its
      // own timeout, and a probe that joined a refresh can't abort it from
      // under the callers that share it.
      const refresh = (this.#refreshing ??= this.#refresh(verify).finally(() => {
        this.#refreshing = undefined;
      }));
      await raceWithSignal(refresh, signal);
      // A request can reject the new state before this caller wakes, so the
      // loop checks the current state again rather than trust the refresh.
      force = false;
    }
  }

  /** Verifies the enclave and publishes the result as the current state. */
  async #refresh(verify: (e: Enclave) => Promise<Attested>): Promise<void> {
    // Only an enclave with a seal check makes anything but a Verification, and V admits that for one.
    const verification = (await verify(this.#enclave)) as V;
    const bound = await this.#bind(verification);
    const entry: Entry<T, V> = { verification, bound, rejected: false, claimed: false };
    // A close during the refresh already released the current binding; this one is not published.
    if (this.#closed) {
      this.#release(bound);
      throw closedError();
    }
    // Binding can outlast freshness.
    if (!this.#valid(entry)) {
      this.#release(bound);
      throw new AttestationError(FRESHNESS_EXPIRED);
    }
    // What the replaced state holds is tied to its keys.
    if (this.#current !== undefined) this.#release(this.#current.bound);
    this.#current = entry;
  }
}

/** Resolves or rejects with `promise`, or rejects with the signal's reason as soon as it aborts. */
function raceWithSignal<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return promise;
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason);
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}
