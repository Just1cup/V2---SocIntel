export const MAX_TAXII_OBJECTS_IN_MEMORY = 500;
export const JSON_PREVIEW_MAX_CHARS = 100_000;

export function capTaxiiObjectsPayload(payload, maxObjects = MAX_TAXII_OBJECTS_IN_MEMORY) {
  const objects = payload?.data?.objects;
  if (!Array.isArray(objects)) return payload;

  const totalObjects = objects.length;
  const cappedObjects = objects.slice(0, maxObjects);

  return {
    ...payload,
    data: {
      ...payload.data,
      objects: cappedObjects,
      objects_total_count: totalObjects,
      objects_retained_count: cappedObjects.length,
      objects_truncated: totalObjects > cappedObjects.length,
    },
  };
}

export function taxiiObjectCount(payload) {
  return payload?.data?.objects_total_count ?? payload?.data?.objects?.length ?? 0;
}

export function taxiiPayloadWasTruncated(payload) {
  return Boolean(payload?.data?.objects_truncated);
}

export function createJsonPreview(value, maxChars = JSON_PREVIEW_MAX_CHARS) {
  const text = JSON.stringify(value, null, 2);
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars)}\n...truncated`;
}
