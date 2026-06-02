import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { sleep } from "./asyncControl.js";

const originalSetTimeout = globalThis.setTimeout;
const originalClearTimeout = globalThis.clearTimeout;

afterEach(() => {
  globalThis.setTimeout = originalSetTimeout;
  globalThis.clearTimeout = originalClearTimeout;
});

test("sleep rejects with AbortError when signal is already aborted", async () => {
  const controller = new AbortController();
  controller.abort();

  await assert.rejects(sleep(1000, controller.signal), { name: "AbortError" });
});

test("sleep clears the pending timeout when aborted", async () => {
  const controller = new AbortController();
  const timeoutId = { id: "timeout-1" };
  let clearedTimeout = null;

  globalThis.setTimeout = () => timeoutId;
  globalThis.clearTimeout = (id) => {
    clearedTimeout = id;
  };

  const promise = sleep(1000, controller.signal);
  controller.abort();

  await assert.rejects(promise, { name: "AbortError" });
  assert.equal(clearedTimeout, timeoutId);
});
