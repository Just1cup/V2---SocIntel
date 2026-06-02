import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { api, request } from "./api.js";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function jsonResponse(payload) {
  return {
    ok: true,
    status: 200,
    headers: new Headers({ "content-type": "application/json" }),
    json: async () => payload,
    text: async () => JSON.stringify(payload),
  };
}

test("request forwards AbortSignal to fetch", async () => {
  const controller = new AbortController();
  let fetchOptions = null;

  globalThis.fetch = async (_url, options) => {
    fetchOptions = options;
    return jsonResponse({ ok: true });
  };

  const payload = await request("/health", { signal: controller.signal });

  assert.deepEqual(payload, { ok: true });
  assert.equal(fetchOptions.signal, controller.signal);
});

test("api methods accept request options and preserve AbortSignal", async () => {
  const controller = new AbortController();
  let fetchOptions = null;
  let fetchUrl = "";

  globalThis.fetch = async (url, options) => {
    fetchUrl = url;
    fetchOptions = options;
    return jsonResponse({ data: { objects: [] } });
  };

  await api.getTaxiiObjects(
    "",
    "mitre-attack",
    "enterprise-attack",
    { type: "attack-pattern" },
    { signal: controller.signal },
  );

  assert.equal(fetchOptions.signal, controller.signal);
  assert.match(fetchUrl, /type=attack-pattern/);
});
