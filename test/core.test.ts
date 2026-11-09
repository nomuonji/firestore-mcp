import test from "node:test";
import assert from "node:assert/strict";
import {
  assertCollectionPath,
  assertDocumentPath,
  decodeFields,
  encodeFields,
  safeEqual
} from "../src/core.js";

test("validates Firestore collection and document paths", () => {
  assert.deepEqual(assertCollectionPath("accounts"), ["accounts"]);
  assert.deepEqual(assertCollectionPath("accounts/a1/posts"), ["accounts", "a1", "posts"]);
  assert.deepEqual(assertDocumentPath("accounts/a1"), ["accounts", "a1"]);
  assert.throws(() => assertCollectionPath("accounts/a1"));
  assert.throws(() => assertDocumentPath("accounts"));
  assert.throws(() => assertDocumentPath("accounts/a1/posts"));
  assert.throws(() => assertCollectionPath("../secrets"));
});

test("round trips supported Firestore JSON field values", () => {
  const source = {
    title: "example",
    count: 12,
    enabled: true,
    empty: null,
    tags: ["a", "b"],
    nested: { answer: 42 },
    createdAt: { $timestamp: "2026-11-09T00:00:00Z" }
  };
  assert.deepEqual(decodeFields(encodeFields(source) as Record<string, Record<string, unknown>>), source);
});

test("uses a length-aware constant-time token comparison", () => {
  assert.equal(safeEqual("same-token", "same-token"), true);
  assert.equal(safeEqual("same-token", "same-tokeN"), false);
  assert.equal(safeEqual("short", "longer"), false);
});
