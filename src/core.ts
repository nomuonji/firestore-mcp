export type FirestoreValue = Record<string, unknown>;

const SIMPLE_FIELD = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SAFE_SEGMENT = /^[^/]{1,1500}$/;
const RESERVED_FIELD = /^__.*__$/;

export function assertCollectionPath(path: string): string[] {
  const segments = splitPath(path);
  if (segments.length % 2 !== 1) {
    throw new Error("collectionPath must contain an odd number of path segments.");
  }
  return segments;
}

export function assertDocumentPath(path: string): string[] {
  const segments = splitPath(path);
  if (segments.length < 2 || segments.length % 2 !== 0) {
    throw new Error("documentPath must contain an even number of path segments (collection/document).");
  }
  return segments;
}

export function assertParentDocumentPath(path?: string): string[] {
  if (!path) return [];
  return assertDocumentPath(path);
}

function splitPath(path: string): string[] {
  if (typeof path !== "string" || path.length === 0 || path.length > 6000) {
    throw new Error("Firestore path must be a non-empty string of at most 6000 characters.");
  }
  const segments = path.split("/");
  if (segments.some((part) => !SAFE_SEGMENT.test(part) || part === "." || part === "..")) {
    throw new Error("Firestore path contains an invalid or reserved segment.");
  }
  return segments;
}

export function assertFieldPath(path: string): string {
  if (typeof path !== "string" || path.length > 1500 || !path.split(".").every((part) => SIMPLE_FIELD.test(part) && !RESERVED_FIELD.test(part))) {
    throw new Error("Query field paths must use simple dot-separated field names.");
  }
  return path;
}

function assertFieldName(name: string): void {
  if (typeof name !== "string" || name.length === 0 || new TextEncoder().encode(name).length > 1500 || RESERVED_FIELD.test(name)) {
    throw new Error("Document field names must be non-empty, at most 1500 UTF-8 bytes, and not reserved.");
  }
}

export function encodeUpdateFieldPath(name: string): string {
  assertFieldName(name);
  if (SIMPLE_FIELD.test(name)) return name;
  const escaped = name.replace(/\\/g, "\\\\").replace(/\u0060/g, (character) => "\\" + character);
  return String.fromCharCode(96) + escaped + String.fromCharCode(96);
}
export function assertDocumentData(data: unknown): Record<string, unknown> {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("data must be a JSON object.");
  }
  const record = data as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length > 200) throw new Error("A document write may contain at most 200 top-level fields.");
  for (const key of keys) assertFieldName(key);
  return record;
}

export function encodeValue(value: unknown): Record<string, unknown> {
  if (value === null) return { nullValue: "NULL" };
  if (typeof value === "string") return { stringValue: value };
  if (typeof value === "boolean") return { booleanValue: value };
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Firestore values cannot contain NaN or Infinity.");
    return Number.isSafeInteger(value)
      ? { integerValue: String(value) }
      : { doubleValue: value };
  }
  if (Array.isArray(value)) {
    return { arrayValue: { values: value.map(encodeValue) } };
  }
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    if (Object.keys(object).length === 1 && typeof object.$timestamp === "string") {
      return { timestampValue: object.$timestamp };
    }
    if (Object.keys(object).length === 1 && typeof object.$reference === "string") {
      return { referenceValue: object.$reference };
    }
    const fields: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(object)) {
      assertFieldName(key);
      fields[key] = encodeValue(child);
    }
    return { mapValue: { fields } };
  }
  throw new Error("Unsupported Firestore value type.");
}

export function encodeFields(data: Record<string, unknown>): Record<string, unknown> {
  const fields: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(assertDocumentData(data))) {
    fields[key] = encodeValue(value);
  }
  return fields;
}

export function decodeValue(value: Record<string, unknown>): unknown {
  if ("nullValue" in value) return null;
  if ("stringValue" in value) return value.stringValue;
  if ("booleanValue" in value) return value.booleanValue;
  if ("integerValue" in value) {
    const raw = String(value.integerValue);
    const num = Number(raw);
    return Number.isSafeInteger(num) ? num : raw;
  }
  if ("doubleValue" in value) return value.doubleValue;
  if ("timestampValue" in value) return { $timestamp: value.timestampValue };
  if ("referenceValue" in value) return { $reference: value.referenceValue };
  if ("bytesValue" in value) return { $bytes: value.bytesValue };
  if ("geoPointValue" in value) return { $geoPoint: value.geoPointValue };
  if ("arrayValue" in value) {
    const values = (value.arrayValue as { values?: Record<string, unknown>[] } | undefined)?.values ?? [];
    return values.map(decodeValue);
  }
  if ("mapValue" in value) {
    const fields = (value.mapValue as { fields?: Record<string, Record<string, unknown>> } | undefined)?.fields ?? {};
    return decodeFields(fields);
  }
  return value;
}

export function decodeFields(fields: Record<string, Record<string, unknown>> = {}): Record<string, unknown> {
  return Object.fromEntries(Object.entries(fields).map(([key, value]) => [key, decodeValue(value)]));
}

export function safeEqual(left: string, right: string): boolean {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return difference === 0;
}

export function publicDocument(document: Record<string, unknown>): Record<string, unknown> {
  const name = typeof document.name === "string" ? document.name : "";
  const rawId = name.split("/").pop() ?? "";
  let id = rawId;
  try {
    id = decodeURIComponent(rawId);
  } catch {
    // Keep the raw ID if the resource name does not contain valid URI escapes.
  }
  return {
    id,
    data: decodeFields((document.fields ?? {}) as Record<string, Record<string, unknown>>),
    ...(document.createTime ? { createTime: document.createTime } : {}),
    ...(document.updateTime ? { updateTime: document.updateTime } : {})
  };
}

export function extractBearerToken(header: string | null): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1] ?? null;
}
