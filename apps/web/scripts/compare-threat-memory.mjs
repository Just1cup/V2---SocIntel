import { performance } from "node:perf_hooks";

import { capTaxiiObjectsPayload, createJsonPreview } from "../src/taxiiPayload.js";

const OBJECT_COUNT = 5000;
const DESCRIPTION_SIZE = 1024;
const RETAINED_LIMIT = 500;
const PREVIEW_LIMIT = 100_000;

function makePayload() {
  return {
    data: {
      objects: Array.from({ length: OBJECT_COUNT }, (_, index) => ({
        id: `attack-pattern--${index}`,
        type: "attack-pattern",
        name: `Technique ${index}`,
        description: "x".repeat(DESCRIPTION_SIZE),
        external_references: [{ source_name: "mitre", external_id: `T${index}` }],
      })),
    },
  };
}

function heapUsedMb() {
  global.gc?.();
  return process.memoryUsage().heapUsed / 1024 / 1024;
}

function measure(label, operation) {
  const startHeap = heapUsedMb();
  const start = performance.now();
  const result = operation();
  const durationMs = performance.now() - start;
  const endHeap = heapUsedMb();
  return {
    label,
    durationMs: Number(durationMs.toFixed(2)),
    heapDeltaMb: Number((endHeap - startHeap).toFixed(2)),
    retainedObjects: result.retainedObjects,
    previewChars: result.previewChars,
  };
}

const beforePayload = makePayload();
const before = measure("before_full_payload_and_full_preview", () => {
  const retained = beforePayload;
  const preview = JSON.stringify(retained.data, null, 2);
  return {
    retainedObjects: retained.data.objects.length,
    previewChars: preview.length,
  };
});

const afterPayload = makePayload();
const after = measure("after_capped_payload_and_capped_preview", () => {
  const retained = capTaxiiObjectsPayload(afterPayload, RETAINED_LIMIT);
  const preview = createJsonPreview(retained.data, PREVIEW_LIMIT);
  return {
    retainedObjects: retained.data.objects.length,
    previewChars: preview.length,
  };
});

console.log(JSON.stringify({ objectCount: OBJECT_COUNT, descriptionSize: DESCRIPTION_SIZE, before, after }, null, 2));
