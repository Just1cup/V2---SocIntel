export function upsertBoundedRecord(record, key, value, maxEntries) {
  const next = { ...record };
  delete next[key];
  next[key] = value;

  const overflow = Object.keys(next).length - maxEntries;
  if (overflow <= 0) return next;

  for (const oldKey of Object.keys(next).slice(0, overflow)) {
    delete next[oldKey];
  }
  return next;
}
