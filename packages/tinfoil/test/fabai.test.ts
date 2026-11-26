/**
 * FabAI's gateway options, end to end against the local EHBP server standing
 * in for the gateway: the repository owner, the seal check in place of the
 * verifier with one check per send, and the omitted cache prefix. Unset,
 * the client behaves as upstream's, which the rest of the suite checks.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AttestationError, ConfigurationError } from "../src/errors.js";
import { createGatewayHTTPClient, type GatewayClientSeams } from "../src/gateway-client.js";
import { Enclave } from "../src/internal/enclave.js";
import { KeyedTransport } from "../src/internal/transport/transport.js";
import { isSealChecked } from "../src/internal/sealcheck.js";
import type { Fetch, GatewayOptions, SealCheck } from "../src/options.js";
import { fromHex, type Verifier } from "../../verifier/src/index.js";
import { startEhbpServer, type EhbpServer, type Seen } from "./helpers/ehbp-server.js";

const GATEWAY_URL = "https://gateway.fabai.internal/v1/";
const REPLICA = "protected.fabai.internal";
const PROMPT = "the canary sings at midnight";
const CATALOG = {
  "fabai-chat": { repo: "digicatapult/fabai-demo", hosts: [REPLICA] },
  "tinfoil-chat": { repo: "tinfoilsh/confidential-chat", hosts: ["chat.tinfoil.sh"] },
};
let gateway: EhbpServer;
let sends: Seen[] = [];

/** A fetch that sends requests addressed to the gateway's name to the local server standing in for it. */
function toLocal(): Fetch {
  return (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const local = new URL(gateway.origin);
    url.protocol = local.protocol;
    url.host = local.host;
    return fetch(new Request(url, request));
  };
}

const seams: GatewayClientSeams = { catalogFetch: toLocal(), documentFetch: toLocal(), sleep: async () => {}, ehbp: { fetch: toLocal() }, resolveSecret: async (s) => s || "resolved-secret" };

/** A seal check that counts its calls and returns the local replica's key. */
function counting(): { check: SealCheck; calls: { relay: string; host: string }[] } {
  const calls: { relay: string; host: string }[] = [];
  return {
    calls,
    check: async (target) => {
      calls.push(target);
      return fromHex(gateway.publicKeyHex);
    },
  };
}

function fabai(check: SealCheck, extra: Partial<GatewayOptions> = {}): GatewayOptions {
  return { url: GATEWAY_URL, repositoryOwner: "digicatapult", sealCheck: check, omitCachePrefix: true, ...extra };
}

function chat(client: { fetch: Fetch; baseURL: string }): Promise<Response> {
  return client.fetch(new URL("chat/completions", client.baseURL), {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer test-api-key" },
    body: JSON.stringify({ model: "fabai-chat", messages: [{ role: "user", content: PROMPT }] }),
  });
}

beforeAll(async () => {
  gateway = await startEhbpServer((seen) => {
    if (seen.path === "/catalog") return { headers: { "content-type": "application/json" }, body: JSON.stringify(CATALOG) };
    if (seen.path.startsWith("/.well-known/tinfoil-attestation")) throw new Error("a seal check fetches its own documents");
    sends.push(seen);
    return { headers: { "content-type": "application/json" }, body: JSON.stringify({ ok: true }) };
  });
});

afterAll(async () => {
  await gateway.close();
});

describe("FabAI gateway options", () => {
  it("serves only the repository owner's models", async () => {
    const client = await createGatewayHTTPClient(fabai(counting().check), seams);
    expect(await client.models()).toEqual(["fabai-chat"]);
    const upstream = await createGatewayHTTPClient({ url: GATEWAY_URL, verifier: { callerAuthorizesConfig: false } as unknown as Verifier }, seams);
    expect(await upstream.models(), "unset, the owner is tinfoilsh").toEqual(["tinfoil-chat"]);
  });

  it("checks before every send, sealing each request to its own check's key", async () => {
    sends = [];
    const { check, calls } = counting();
    const client = await createGatewayHTTPClient(fabai(check), seams);
    const sequential = 3;
    const concurrent = 8;
    for (let i = 0; i < sequential; i++) {
      const response = await chat(client);
      expect(await response.json()).toEqual({ ok: true });
    }
    await Promise.all(Array.from({ length: concurrent }, async () => (await chat(client)).json()));

    expect(calls.length).toBeGreaterThanOrEqual(sequential + concurrent);
    expect(calls[0]).toEqual({ relay: "gateway.fabai.internal", host: REPLICA });
    expect(sends).toHaveLength(sequential + concurrent);
    for (const seen of sends) {
      expect(seen.sealed).toBe(true);
      expect(new TextDecoder().decode(seen.body)).toContain(PROMPT);
      expect(seen.headers["x-tinfoil-seal"]).toBe(REPLICA);
      expect(seen.headers["x-tinfoil-cache-prefix"], "nothing derived from the prompt reaches the gateway").toBeUndefined();
    }
    expect(client.current, "a seal check's result isn't a Verification").toEqual([]);
    await expect(client.ensureVerified("fabai-chat")).rejects.toBeInstanceOf(ConfigurationError);
  });

  it("sends nothing to a replica the check refuses, and doesn't retry", async () => {
    sends = [];
    let calls = 0;
    const refused = new Error("software tick failed");
    const client = await createGatewayHTTPClient(
      fabai(async () => {
        calls++;
        throw refused;
      }),
      seams,
    );
    const failure = await chat(client).catch((err: unknown) => err);
    expect(failure).toBeInstanceOf(AttestationError);
    expect((failure as Error).message).toContain("seal check rejected protected.fabai.internal: software tick failed");
    expect(calls).toBe(1);
    expect(sends).toEqual([]);
  });

  it("refuses a key that isn't 32 bytes", async () => {
    const client = await createGatewayHTTPClient(fabai(async () => new Uint8Array(31)), seams);
    await expect(chat(client)).rejects.toBeInstanceOf(AttestationError);
  });

  it("keeps the cache prefix unless asked to omit it", async () => {
    sends = [];
    const { check } = counting();
    const withPrefix = await createGatewayHTTPClient(fabai(check, { omitCachePrefix: false }), seams);
    await (await chat(withPrefix)).json();
    expect(sends[0]!.headers["x-tinfoil-cache-prefix"]).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses inconsistent options before any network I/O", async () => {
    const { check } = counting();
    const verifier = {} as Verifier;
    const refused: GatewayOptions[] = [
      fabai(check, { verifier }),
      fabai(check, { verificationCheck: () => {} }),
      fabai(check, { modelPins: new Map([["fabai-chat", { repo: "digicatapult/fabai-demo", verifier }]]) }),
      fabai(check, { repositoryOwner: "digicatapult/" }),
      fabai(check, { repositoryOwner: "digicatapult/fabai-demo" }),
      fabai(check, { repositoryOwner: "-digicatapult" }),
      fabai(check, { modelPins: new Map([["chat", { repo: "tinfoilsh/confidential-chat" }]]) }),
    ];
    let fetched = 0;
    const counted: GatewayClientSeams = {
      ...seams,
      catalogFetch: (input, init) => {
        fetched++;
        return toLocal()(input, init);
      },
    };
    for (const options of refused) {
      await expect(createGatewayHTTPClient(options, counted)).rejects.toBeInstanceOf(ConfigurationError);
    }
    expect(fetched).toBe(0);
  });
});

describe("single-use transport", () => {
  it("never seals two concurrent sends under one check", async () => {
    let checks = 0;
    const keys = new Set<string>();
    const enclave = await Enclave.create({
      host: REPLICA,
      pin: {},
      sealCheck: async () => {
        checks++;
        return crypto.getRandomValues(new Uint8Array(32));
      },
    });
    const transport = new KeyedTransport(enclave, {
      name: "ehbp",
      validateRequest: () => {},
      bind: (v) => ({
        fetch: async () => {
          expect(isSealChecked(v)).toBe(true);
          keys.add(v.hpkePublicKey!);
          return new Response(null, { status: 204 });
        },
      }),
    });
    const sends = 16;
    await Promise.all(Array.from({ length: sends }, () => transport.fetch("https://gateway.fabai.internal/v1/chat/completions", { method: "POST" })));
    expect(keys.size, "every send claimed a check of its own").toBe(sends);
    expect(checks).toBeGreaterThanOrEqual(sends);
  });

  it("lets a send claim the check made just before it", async () => {
    let checks = 0;
    const enclave = await Enclave.create({
      host: REPLICA,
      pin: {},
      sealCheck: async () => {
        checks++;
        return crypto.getRandomValues(new Uint8Array(32));
      },
    });
    const transport = new KeyedTransport(enclave, { name: "ehbp", validateRequest: () => {}, bind: () => ({ fetch: async () => new Response(null, { status: 204 }) }) });
    await transport.state();
    await transport.fetch("https://gateway.fabai.internal/v1/", { method: "POST" });
    expect(checks, "the gateway's pre-send check is the send's").toBe(1);
    await transport.fetch("https://gateway.fabai.internal/v1/", { method: "POST" });
    expect(checks).toBe(2);
  });
});
