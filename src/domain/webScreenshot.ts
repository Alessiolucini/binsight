import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";

import { z } from "zod";

import { browserCompletenessSchema } from "./browserCompleteness.js";
import {
  browserAllowedOriginsSchema,
  browserObservationEndpointSchema,
} from "./browserObservation.js";
import { browserVersionSchema } from "./browserObservationSchemas.js";

/** Self-verifying PNG artifact. Carries either inline base64 (default) or a
 * `saved_to_path` string naming the on-disk PNG file the caller requested via
 * `output_path`. Exactly one of the two is present on any valid artifact. */
export const webScreenshotArtifactSchema = z
  .object({
    sha256: z.string().regex(/^[a-f0-9]{64}$/u),
    bytes: z.number().int().min(1),
    media_type: z.literal("image/png"),
    data_base64: z.string().optional(),
    saved_to_path: z.string().min(1).optional(),
  })
  .superRefine((artifact, context) => {
    const hasBase64 = artifact.data_base64 !== undefined;
    const hasPath = artifact.saved_to_path !== undefined;
    if (hasBase64 === hasPath) {
      context.addIssue({
        code: "custom",
        message:
          "Screenshot artifact must carry exactly one of data_base64 or saved_to_path",
      });
      return;
    }
    if (!hasBase64) return;
    const bytes = decodeCanonicalBase64(artifact.data_base64 as string);
    if (bytes === undefined) {
      context.addIssue({ code: "custom", message: "Invalid canonical base64" });
      return;
    }
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    if (bytes.byteLength !== artifact.bytes || sha256 !== artifact.sha256)
      context.addIssue({
        code: "custom",
        message: "Screenshot artifact digest or size mismatch",
      });
  });
export type WebScreenshotArtifact = z.infer<typeof webScreenshotArtifactSchema>;

/** Input for one read-only visible-viewport screenshot. */
export const captureWebScreenshotInputSchema = z.strictObject({
  cdp_endpoint: browserObservationEndpointSchema,
  allowed_origins: browserAllowedOriginsSchema,
  target_id: z.string().trim().min(1),
  output_path: z
    .string()
    .trim()
    .min(1)
    .refine((value) => isAbsolute(value), {
      message: "output_path must be an absolute filesystem path.",
    })
    .optional()
    .describe(
      "Optional absolute filesystem path to write the PNG to. When set, the returned artifact carries saved_to_path instead of inline data_base64, so the MCP response stays small for large viewports.",
    ),
});
export type CaptureWebScreenshotInput = z.infer<
  typeof captureWebScreenshotInputSchema
>;

/** Screenshot observation with embedded immutable artifact bytes. */
export const webScreenshotSchema = z.object({
  browser: browserVersionSchema,
  target: z.object({
    target_id: z.string(),
    url: z.string(),
    origin: z.string(),
  }),
  captured_at: z.iso.datetime(),
  viewport: z.object({
    width: z.number().int().min(1),
    height: z.number().int().min(1),
  }),
  artifact: webScreenshotArtifactSchema,
  completeness: browserCompletenessSchema,
  limitations: z.array(z.string()),
});
export type WebScreenshot = z.infer<typeof webScreenshotSchema>;

/** Input for local pixel comparison of two screenshot artifacts. */
export const compareWebScreenshotsInputSchema = z.strictObject({
  before: webScreenshotArtifactSchema,
  after: webScreenshotArtifactSchema,
  channel_threshold: z.number().int().min(0).max(255).default(0),
});
export type CompareWebScreenshotsInput = z.infer<
  typeof compareWebScreenshotsInputSchema
>;

/** Value-only visual difference metrics; no OCR or image mutation. */
const webScreenshotDiffContextShape = {
  before: z.object({
    width: z.number().int().min(1),
    height: z.number().int().min(1),
  }),
  after: z.object({
    width: z.number().int().min(1),
    height: z.number().int().min(1),
  }),
  channel_threshold: z.number().int().min(0).max(255),
  limitations: z.array(z.string()),
};

export const webScreenshotDiffSchema = z
  .discriminatedUnion("status", [
    z.object({
      ...webScreenshotDiffContextShape,
      status: z.literal("identical"),
      compared_pixels: z.number().int().positive(),
      changed_pixels: z.literal(0),
      changed_ratio: z.literal(0),
      maximum_channel_delta: z.number().int().min(0).max(255),
      mean_absolute_channel_delta: z.number().min(0).max(255),
    }),
    z.object({
      ...webScreenshotDiffContextShape,
      status: z.literal("different"),
      compared_pixels: z.number().int().positive(),
      changed_pixels: z.number().int().positive(),
      changed_ratio: z.number().positive().max(1),
      maximum_channel_delta: z.number().int().positive().max(255),
      mean_absolute_channel_delta: z.number().positive().max(255),
    }),
    z.object({
      ...webScreenshotDiffContextShape,
      status: z.literal("dimension_mismatch"),
      compared_pixels: z.literal(0),
      changed_pixels: z.null(),
      changed_ratio: z.null(),
      maximum_channel_delta: z.null(),
      mean_absolute_channel_delta: z.null(),
    }),
  ])
  .superRefine((diff, context) => {
    const sameDimensions =
      diff.before.width === diff.after.width &&
      diff.before.height === diff.after.height;
    if (sameDimensions !== (diff.status !== "dimension_mismatch"))
      context.addIssue({
        code: "custom",
        path: ["status"],
        message: "Screenshot comparison status must match viewport dimensions",
      });
    if (
      diff.status !== "dimension_mismatch" &&
      diff.compared_pixels !== diff.before.width * diff.before.height
    )
      context.addIssue({
        code: "custom",
        path: ["compared_pixels"],
        message: "Compared pixel count must match the shared dimensions",
      });
  });
export type WebScreenshotDiff = z.infer<typeof webScreenshotDiffSchema>;

/** Create a content-addressed PNG artifact from captured bytes.
 *
 * By default the bytes are inlined as base64. Pass `savedToPath` when the
 * caller requested on-disk delivery via `output_path`; the artifact then
 * carries that absolute path instead of the base64 payload so the MCP
 * response stays small for large viewports. */
export const createWebScreenshotArtifact = (
  bytes: Buffer,
  savedToPath?: string,
): WebScreenshotArtifact => {
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const base = {
    sha256,
    bytes: bytes.byteLength,
    media_type: "image/png" as const,
  };
  return webScreenshotArtifactSchema.parse(
    savedToPath === undefined
      ? { ...base, data_base64: bytes.toString("base64") }
      : { ...base, saved_to_path: savedToPath },
  );
};

/** Strict canonical base64 decoder used before digest validation. */
export const decodeCanonicalBase64 = (value: string): Buffer | undefined => {
  if (value.length === 0 || value.length % 4 !== 0) return undefined;
  const decoded = Buffer.from(value, "base64");
  return decoded.toString("base64") === value ? decoded : undefined;
};
