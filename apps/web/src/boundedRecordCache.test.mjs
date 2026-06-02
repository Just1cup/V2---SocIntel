import assert from "node:assert/strict";
import { test } from "node:test";

import { upsertBoundedRecord } from "./boundedRecordCache.js";

test("upsertBoundedRecord evicts the oldest keys beyond the entry limit", () => {
  const record = {
    T1001: { name: "first" },
    T1002: { name: "second" },
    T1003: { name: "third" },
  };

  const next = upsertBoundedRecord(record, "T1004", { name: "fourth" }, 3);

  assert.deepEqual(Object.keys(next), ["T1002", "T1003", "T1004"]);
  assert.equal(next.T1004.name, "fourth");
  assert.equal(record.T1001.name, "first");
});

test("upsertBoundedRecord refreshes an existing key as the newest entry", () => {
  const record = {
    T1001: { version: 1 },
    T1002: { version: 1 },
    T1003: { version: 1 },
  };

  const next = upsertBoundedRecord(record, "T1001", { version: 2 }, 3);

  assert.deepEqual(Object.keys(next), ["T1002", "T1003", "T1001"]);
  assert.equal(next.T1001.version, 2);
});
