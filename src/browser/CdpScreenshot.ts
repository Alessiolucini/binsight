import { writeFile } from "node:fs/promises";

import type { ProgressReporter } from "../application/ProgressReporter.js";
import type {
  CaptureWebScreenshotInput,
  WebScreenshot,
} from "../domain/webScreenshot.js";
import { createWebScreenshotArtifact } from "../domain/webScreenshot.js";
import { BrowserObservationError } from "../domain/browserObservationError.js";
import { isMainFrameNavigation } from "./CdpCaptureEventHelpers.js";
import type { CdpEndpointDiscovery, CdpEndpointTarget } from "./CdpEndpoint.js";
import type { CdpConnection, CdpEvent } from "./CdpConnection.js";
import {
  allowedSanitizedUrl,
  recordValue,
  cdpStringValue,
} from "./CdpCaptureValues.js";
import { mainFrameUrl } from "./CdpCaptureDocuments.js";
import { captureFrames } from "./CdpCaptureDocuments.js";
import { CdpCaptureCompleteness } from "./CdpCaptureCompleteness.js";
import { decodeCanonicalBase64 } from "../domain/webScreenshot.js";
import { readPngHeaderDimensions } from "../domain/pngHeader.js";

interface ScreenshotContext {
  readonly connection: CdpConnection;
  readonly sessionId: string | undefined;
  readonly discovery: CdpEndpointDiscovery;
  readonly target: CdpEndpointTarget;
  readonly input: CaptureWebScreenshotInput;
  readonly signal?: AbortSignal;
  readonly progress?: ProgressReporter;
}

/** Capture the current viewport without navigation, evaluation, or page mutation. */
export const captureCdpScreenshot = async (
  context: ScreenshotContext,
): Promise<WebScreenshot> => {
  const origins = new Set(context.input.allowed_origins);
  await context.progress?.report({
    phase: "browser_observation",
    completed: 1,
    total: 2,
    message: "Authorizing current screenshot frame",
  });
  await context.connection.send(
    "Page.enable",
    {},
    context.sessionId,
    context.signal,
  );
  const before = await context.connection.send(
    "Page.getFrameTree",
    {},
    context.sessionId,
    context.signal,
  );
  const beforeUrl = mainFrameUrl(before);
  const authorized = allowedSanitizedUrl(beforeUrl, origins);
  const mainFrame = captureFrames(before, origins, 1).items[0];
  if (authorized === undefined || mainFrame === undefined)
    throw new BrowserObservationError("inspect_web_page", "target_not_allowed");
  const initialFrame = recordValue(
    recordValue(recordValue(before)?.frameTree)?.frame,
  );
  const navigation = {
    changed: false,
    leftScope: false,
    url: beforeUrl,
    loaderId: cdpStringValue(initialFrame?.loaderId),
  };
  const removeListener = context.connection.onEvent((event) => {
    if (event.sessionId !== context.sessionId) return;
    observeScreenshotNavigation(event, mainFrame.frame_id, origins, navigation);
  });
  let result: ReturnType<typeof recordValue>;
  let after: unknown;
  try {
    result = recordValue(
      await context.connection.send(
        "Page.captureScreenshot",
        { format: "png", fromSurface: true, captureBeyondViewport: false },
        context.sessionId,
        context.signal,
      ),
    );
    after = await context.connection.send(
      "Page.getFrameTree",
      {},
      context.sessionId,
      context.signal,
    );
  } finally {
    removeListener();
  }
  const encoded = cdpStringValue(result?.data);
  const bytes =
    encoded === undefined ? undefined : decodeCanonicalBase64(encoded);
  if (bytes === undefined)
    throw new BrowserObservationError("inspect_web_page", "protocol_error");
  const dimensions = readPngHeaderDimensions(bytes);
  if (dimensions === undefined)
    throw new BrowserObservationError("inspect_web_page", "protocol_error");
  if (navigation.leftScope)
    throw new BrowserObservationError("inspect_web_page", "target_not_allowed");
  const afterUrl = mainFrameUrl(after);
  if (
    navigation.changed ||
    afterUrl !== beforeUrl ||
    allowedSanitizedUrl(afterUrl, origins) === undefined
  )
    throw new BrowserObservationError("inspect_web_page", "target_changed");
  await context.progress?.report({
    phase: "browser_observation",
    completed: 2,
    total: 2,
    message: "Screenshot capture complete",
    terminal: true,
  });
  const outputPath = context.input.output_path;
  if (outputPath !== undefined) {
    // Absolute-path validation is enforced by the Zod schema upstream.
    try {
      await writeFile(outputPath, bytes);
    } catch (cause: unknown) {
      // Delivery-site IO failures surface as a TypeError the provider adapter
      // wraps into a ProviderAdapterError, matching how the rest of this
      // module reports non-protocol host failures.
      throw new TypeError(
        `capture_web_screenshot could not write PNG to ${outputPath}: ${
          cause instanceof Error ? cause.message : String(cause)
        }`,
      );
    }
  }
  const extraLimitation =
    outputPath === undefined
      ? []
      : [
          "PNG bytes were written to the caller-supplied output_path; data_base64 is omitted to keep the response compact.",
        ];
  return {
    browser: context.discovery.version,
    target: {
      target_id: context.target.id,
      url: authorized.url,
      origin: authorized.origin ?? "",
    },
    captured_at: new Date().toISOString(),
    viewport: dimensions,
    artifact: createWebScreenshotArtifact(bytes, outputPath),
    completeness: new CdpCaptureCompleteness().snapshot(),
    limitations: [
      "The screenshot contains the visible viewport, including on-screen content.",
      "BinSight does not scroll, evaluate JavaScript, or capture beyond the current viewport.",
      ...extraLimitation,
    ],
  };
};

const observeScreenshotNavigation = (
  event: CdpEvent,
  mainFrameId: string,
  origins: ReadonlySet<string>,
  state: {
    changed: boolean;
    leftScope: boolean;
    readonly url: string | undefined;
    readonly loaderId: string | undefined;
  },
): void => {
  if (!isMainFrameNavigation(event, mainFrameId)) return;
  const params = recordValue(event.params);
  if (params === undefined) return;
  const frame =
    event.method === "Page.frameNavigated" ? recordValue(params.frame) : params;
  if (
    event.method === "Page.frameNavigated" &&
    state.loaderId !== undefined &&
    state.loaderId !== "" &&
    cdpStringValue(frame?.loaderId) === state.loaderId &&
    cdpStringValue(frame?.url) === state.url
  )
    return;

  state.changed = true;
  if (allowedSanitizedUrl(frame?.url, origins) === undefined)
    state.leftScope = true;
};
