import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  captureWebScreenshotInputSchema,
  createWebScreenshotArtifact,
  webScreenshotArtifactSchema,
} from "./webScreenshot.js";

const pngBytes = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
  "base64",
);

describe("createWebScreenshotArtifact", () => {
  it("inlines base64 by default", () => {
    const artifact = createWebScreenshotArtifact(pngBytes);
    expect(artifact.data_base64).toBe(pngBytes.toString("base64"));
    expect(artifact.saved_to_path).toBeUndefined();
    expect(artifact.sha256).toBe(
      createHash("sha256").update(pngBytes).digest("hex"),
    );
    expect(artifact.bytes).toBe(pngBytes.byteLength);
  });

  it("switches to saved_to_path (and omits base64) when a path is supplied", () => {
    const artifact = createWebScreenshotArtifact(pngBytes, "/tmp/shot.png");
    expect(artifact.saved_to_path).toBe("/tmp/shot.png");
    expect(artifact.data_base64).toBeUndefined();
    expect(artifact.sha256).toBe(
      createHash("sha256").update(pngBytes).digest("hex"),
    );
  });
});

describe("webScreenshotArtifactSchema", () => {
  const digest = createHash("sha256").update(pngBytes).digest("hex");

  it("rejects an artifact carrying both base64 and a saved_to_path", () => {
    const result = webScreenshotArtifactSchema.safeParse({
      sha256: digest,
      bytes: pngBytes.byteLength,
      media_type: "image/png",
      data_base64: pngBytes.toString("base64"),
      saved_to_path: "/tmp/shot.png",
    });
    expect(result.success).toBe(false);
  });

  it("rejects an artifact carrying neither delivery form", () => {
    const result = webScreenshotArtifactSchema.safeParse({
      sha256: digest,
      bytes: pngBytes.byteLength,
      media_type: "image/png",
    });
    expect(result.success).toBe(false);
  });

  it("accepts a saved_to_path artifact without validating its on-disk bytes", () => {
    // Digest validation only applies to the inline-base64 variant. The caller
    // owns the on-disk file lifecycle.
    const result = webScreenshotArtifactSchema.safeParse({
      sha256: "0".repeat(64),
      bytes: 123456,
      media_type: "image/png",
      saved_to_path: "/absolute/elsewhere.png",
    });
    expect(result.success).toBe(true);
  });
});

describe("captureWebScreenshotInputSchema", () => {
  const base = {
    cdp_endpoint: "http://127.0.0.1:9222",
    allowed_origins: ["https://app.example.test"],
    target_id: "page-1",
  };

  it("accepts an absent output_path", () => {
    expect(captureWebScreenshotInputSchema.safeParse(base).success).toBe(true);
  });

  it("accepts an absolute output_path", () => {
    expect(
      captureWebScreenshotInputSchema.safeParse({
        ...base,
        output_path: "/tmp/shot.png",
      }).success,
    ).toBe(true);
  });

  it("rejects a relative output_path", () => {
    expect(
      captureWebScreenshotInputSchema.safeParse({
        ...base,
        output_path: "shot.png",
      }).success,
    ).toBe(false);
  });
});
