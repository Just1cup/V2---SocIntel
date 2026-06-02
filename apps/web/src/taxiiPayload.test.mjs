import assert from "node:assert/strict";
import { test } from "node:test";

import { capTaxiiObjectsPayload, createJsonPreview, taxiiObjectCount, taxiiPayloadWasTruncated } from "./taxiiPayload.js";

function makePayload(count) {
  return {
    source: { id: "mitre-attack" },
    endpoint: "objects",
    data: {
      objects: Array.from({ length: count }, (_, index) => ({
        id: `attack-pattern--${index}`,
        type: "attack-pattern",
      })),
    },
  };
}

test("capTaxiiObjectsPayload retains only the configured number of objects", () => {
  const payload = makePayload(5);
  const capped = capTaxiiObjectsPayload(payload, 2);

  assert.equal(capped.data.objects.length, 2);
  assert.equal(capped.data.objects_total_count, 5);
  assert.equal(capped.data.objects_retained_count, 2);
  assert.equal(taxiiObjectCount(capped), 5);
  assert.equal(taxiiPayloadWasTruncated(capped), true);
  assert.equal(payload.data.objects.length, 5);
});

test("capTaxiiObjectsPayload marks small payloads as not truncated", () => {
  const capped = capTaxiiObjectsPayload(makePayload(2), 5);

  assert.equal(capped.data.objects.length, 2);
  assert.equal(capped.data.objects_total_count, 2);
  assert.equal(taxiiPayloadWasTruncated(capped), false);
});

test("createJsonPreview truncates oversized JSON previews", () => {
  const preview = createJsonPreview({ text: "a".repeat(50) }, 20);

  assert.equal(preview.length, 33);
  assert.equal(preview.endsWith("...truncated"), true);
});
