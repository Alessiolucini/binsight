import type { InspectWebPageInput } from "../domain/browserObservation.js";
import type { WebPageInspection } from "../domain/browserObservationSchemas.js";
import type { ProgressReporter } from "../application/ProgressReporter.js";
import { BrowserObservationError } from "../domain/browserObservationError.js";
import type { BrowserObservationOperation } from "../domain/browserObservationErrors.js";
import { stableWebResources } from "../domain/webInventory.js";
import type { CdpEndpointDiscovery, CdpEndpointTarget } from "./CdpEndpoint.js";
import { CdpConnection } from "./CdpConnection.js";
import { CdpCaptureEvents } from "./CdpCaptureEvents.js";
import { authorizedMainFrame } from "./CdpAuthorizedMainFrame.js";
import { captureStorage } from "./CdpCaptureStorage.js";
import { optionalCdpCommand } from "./CdpOptionalCommand.js";
import { CdpCommandRejection } from "./CdpCommandRejection.js";
import {
  captureAccessibility,
  captureDom,
  captureFrames,
  captureResources,
  type CapturedResource,
  type DomCapture,
  mainFrameUrl,
} from "./CdpCaptureDocuments.js";
import { capturedSvgNodeKind } from "./CdpCaptureDomSvg.js";
import {
  allowedSanitizedUrl,
  delayWithCancellation,
} from "./CdpCaptureValues.js";
import { captureScripts } from "./CdpPageCaptureScripts.js";
import { captureWorkers } from "./CdpPageCaptureWorkers.js";
import type { WebSourceMapRequest } from "./WebSourceMapFetcher.js";

export interface CaptureContext {
  readonly connection: CdpConnection;
  readonly sessionId: string | undefined;
  readonly operation: Extract<
    BrowserObservationOperation,
    "inspect_web_page" | "analyze_web_bundle"
  >;
  readonly discovery: CdpEndpointDiscovery;
  readonly target: CdpEndpointTarget;
  readonly input: InspectWebPageInput;
  readonly signal?: AbortSignal;
  readonly progress?: ProgressReporter;
}

export interface CaptureState {
  readonly context: CaptureContext;
  readonly events: CdpCaptureEvents;
  readonly allowedOrigins: ReadonlySet<string>;
  readonly limitations: string[];
  readonly startedAt: string;
  /** CDP sessions BinSight auto-attached to during this capture (OOPIF
   * iframes, dedicated/shared/service workers). Populated as
   * `Target.attachedToTarget` events arrive on the main session; drained on
   * `Target.detachedFromTarget`. Used by the event listener to route child
   * events into the main inventory with session-scoped script-ids. */
  readonly childSessions: Map<string, ChildSessionAttachment>;
  /** True once the main session has issued `Target.setAutoAttach`. */
  autoAttachEnabled: boolean;
  /** Counts of scripts/exceptions seen per attached child-target type, for
   * surfacing in limitations. */
  readonly childScriptCounts: Map<string, number>;
  /** Reasons we could not attach a child session, for surfacing. */
  readonly childAttachFailures: string[];
}

interface ChildSessionAttachment {
  readonly sessionId: string;
  readonly targetId: string;
  readonly type: string;
  readonly url: string | null;
}

/** CDP target types for which script coverage expands beyond the main page. */
const AUTO_ATTACHABLE_TARGET_TYPES: ReadonlySet<string> = new Set([
  "iframe",
  "worker",
  "shared_worker",
  "service_worker",
  "webview",
]);

interface CapturedSections {
  readonly attachedUrl: string;
  readonly frames: WebPageInspection["frames"];
  readonly dom: DomCapture;
  readonly accessibility: ReturnType<typeof captureAccessibility>;
  readonly scripts: WebPageInspection["scripts"];
  readonly resources: WebPageInspection["resources"];
  readonly workers: WebPageInspection["workers"];
  readonly storage: WebPageInspection["storage"];
}

export interface CapturedPage {
  readonly inspection: WebPageInspection;
  readonly sourceMapRequests: readonly WebSourceMapRequest[];
}

/** Capture and normalize one attached page without evaluating page JavaScript. */
export const capturePage = async (
  context: CaptureContext,
): Promise<CapturedPage> => {
  const allowedOrigins = new Set(context.input.allowed_origins);
  const events = new CdpCaptureEvents(context.input, allowedOrigins);
  const state: CaptureState = {
    context,
    events,
    allowedOrigins,
    limitations: [
      "Observation starts when BinSight attaches; prior network and console activity is unavailable.",
      "Raw network headers, bodies, cookies, storage values, console objects, and WebSocket payloads are never retained; explicitly requested primitive console text is retained verbatim, while payload captures retain value-free shapes.",
      "Source maps are reported only as declarative URLs and are not fetched.",
      "URL-less scripts and console events without an allowed source URL are excluded because their origin cannot be proven.",
      ...(context.target.attached === null
        ? [
            "CDP discovery omitted the target attachment state; attached is reported as unknown.",
          ]
        : []),
    ],
    startedAt: new Date().toISOString(),
    childSessions: new Map(),
    autoAttachEnabled: false,
    childScriptCounts: new Map(),
    childAttachFailures: [],
  };
  const removeListener = context.connection.onEvent((event) => {
    routeCdpEvent(event, state);
  });
  try {
    return await captureAuthorizedPage(state);
  } finally {
    removeListener();
  }
};

/** Route a CDP event to the main inventory, remapping scripts seen on an
 * auto-attached child session (OOPIF iframe or worker) so their script-ids
 * do not collide with the main session's. Also handles `Target.*` events
 * on the main session to open/close child sessions. Exported for tests. */
export const routeCdpEvent = (
  event: {
    readonly method: string;
    readonly params: unknown;
    readonly sessionId?: string;
  },
  state: CaptureState,
): void => {
  const sessionId = event.sessionId;
  if (sessionId === state.context.sessionId) {
    if (event.method === "Target.attachedToTarget") {
      handleTargetAttached(event.params, state);
      // Fall through so events.ingest observes the main-session copy of the
      // event too (future handlers may want it). The child-session work above
      // is fire-and-forget on a separate CDP command.
    } else if (event.method === "Target.detachedFromTarget") {
      handleTargetDetached(event.params, state);
    }
    state.events.ingest(event);
    return;
  }
  if (sessionId === undefined) return;
  const attachment = state.childSessions.get(sessionId);
  if (attachment === undefined) return;
  const remapped = remapChildEvent(event, attachment);
  if (remapped === undefined) return;
  if (event.method === "Debugger.scriptParsed")
    state.childScriptCounts.set(
      attachment.type,
      (state.childScriptCounts.get(attachment.type) ?? 0) + 1,
    );
  state.events.ingest(remapped);
};

/** Clone a child-session event so its `scriptId` / `executionContextId` are
 * namespaced by the child session, avoiding collisions in the main inventory's
 * per-id maps. Returns `undefined` for event methods we deliberately drop
 * (e.g. further `Target.*` nested events we handle separately). Exported
 * for tests. */
export const remapChildEvent = (
  event: {
    readonly method: string;
    readonly params: unknown;
    readonly sessionId?: string;
  },
  attachment: ChildSessionAttachment,
):
  | {
      readonly method: string;
      readonly params: unknown;
      readonly sessionId?: string;
    }
  | undefined => {
  // We intentionally only forward the small set of handlers the main
  // CdpCaptureEvents.ingest reacts to for a child session: script metadata,
  // execution-context lifecycle, and page errors. Network, websockets and
  // console are left to the main session only — their request/connection ids
  // live on the main session's scope and we have not enabled Network on the
  // child.
  const forwarded: ReadonlySet<string> = new Set([
    "Debugger.scriptParsed",
    "Runtime.executionContextCreated",
    "Runtime.executionContextDestroyed",
    "Runtime.executionContextsCleared",
  ]);
  if (!forwarded.has(event.method)) return undefined;
  const params = event.params;
  if (typeof params !== "object" || params === null) return event;
  const scoped: Record<string, unknown> = {
    ...(params as Record<string, unknown>),
  };
  const prefix = `${attachment.type}:${attachment.sessionId}:`;
  if (typeof scoped.scriptId === "string")
    scoped.scriptId = `${prefix}${scoped.scriptId}`;
  const context = (scoped as { context?: Record<string, unknown> }).context;
  if (context && typeof context.id === "number")
    scoped.context = { ...context, id: Number.MAX_SAFE_INTEGER - context.id };
  return { ...event, params: scoped };
};

/** React to `Target.attachedToTarget`: validate the target type, record the
 * child session, and (fire-and-forget) enable Runtime+Debugger on it so the
 * child's scripts stream into the main inventory. Exported for tests. */
export const handleTargetAttached = (
  params: unknown,
  state: CaptureState,
): void => {
  if (typeof params !== "object" || params === null) return;
  const payload = params as Record<string, unknown>;
  const sessionId = payload.sessionId;
  const targetInfo = payload.targetInfo as Record<string, unknown> | undefined;
  if (typeof sessionId !== "string" || sessionId.length === 0) return;
  if (!targetInfo) return;
  const type = typeof targetInfo.type === "string" ? targetInfo.type : "";
  const targetId =
    typeof targetInfo.targetId === "string" ? targetInfo.targetId : "";
  const url = typeof targetInfo.url === "string" ? targetInfo.url : null;
  if (!AUTO_ATTACHABLE_TARGET_TYPES.has(type)) return;
  if (state.childSessions.has(sessionId)) return;
  const attachment: ChildSessionAttachment = { sessionId, targetId, type, url };
  state.childSessions.set(sessionId, attachment);
  // The user explicitly asked for cross-origin coverage via auto-attach, so
  // treat the child target's origin as in-scope — otherwise its scripts would
  // be dropped by the main session's `disallowed_origin` filter the moment
  // they arrive. The allowedOrigins Set is shared with CdpCaptureEvents by
  // reference, so this add is seen immediately by handleScriptParsed.
  if (typeof url === "string" && url.length > 0) {
    try {
      const origin = new URL(url).origin;
      (state.allowedOrigins as Set<string>).add(origin);
    } catch {
      // A target with an unparseable URL (chrome:// or similar) stays
      // without an added origin; its scripts will still be filtered out,
      // which is fine — we don't want to open the gate wider than needed.
    }
  }
  const { connection, signal } = state.context;
  void (async () => {
    try {
      await connection.send("Runtime.enable", {}, sessionId, signal);
      await connection.send("Debugger.enable", {}, sessionId, signal);
      // Propagate auto-attach recursively so nested OOPIFs / nested workers
      // are also reached. Flatten keeps all sessions on one WebSocket.
      await connection.send(
        "Target.setAutoAttach",
        { autoAttach: true, waitForDebuggerOnStart: false, flatten: true },
        sessionId,
        signal,
      );
    } catch (cause: unknown) {
      // A failure here is non-fatal: the capture still returns everything
      // the main session saw, plus a limitation naming the lost coverage.
      state.childAttachFailures.push(
        `${type} (${targetId}): ${cause instanceof Error ? cause.message : String(cause)}`,
      );
      state.childSessions.delete(sessionId);
    }
  })();
};

/** React to `Target.detachedFromTarget`: drop the session so later events
 * from it are ignored. We do not need to disable domains on the child —
 * the detach already tore the session down. Exported for tests. */
export const handleTargetDetached = (
  params: unknown,
  state: CaptureState,
): void => {
  if (typeof params !== "object" || params === null) return;
  const payload = params as Record<string, unknown>;
  const sessionId = payload.sessionId;
  if (typeof sessionId !== "string") return;
  state.childSessions.delete(sessionId);
};

const captureAuthorizedPage = async (
  state: CaptureState,
): Promise<CapturedPage> => {
  const { context, allowedOrigins, limitations } = state;
  const { connection, sessionId, input, signal } = context;
  await authorizeObservationWindow(state);
  await captureJsonResponseBodies(state);
  const frameResult = await authorizedMainFrame({
    connection: context.connection,
    sessionId: context.sessionId,
    signal: context.signal,
    allowedOrigins,
    operation: context.operation,
  });
  const attachedUrl = mainFrameUrl(frameResult) ?? "";
  const frameCapture = captureFrames(
    frameResult,
    allowedOrigins,
    undefined,
    state.events.completeness,
  );
  const frames = frameCapture.items;
  const captureFrame = frames[0];
  if (captureFrame === undefined)
    throw new BrowserObservationError("inspect_web_page", "target_not_allowed");
  state.events.beginFinalCapture(captureFrame.frame_id);
  const resourceCapture = captureResources(
    await connection.send("Page.getResourceTree", {}, sessionId, signal),
    allowedOrigins,
    state.events.completeness,
  );
  const resources = stableWebResources(
    resourceCapture.items.map(publicResource),
  );
  const dom = await capturePageDom(state);
  const accessibility = await accessibilityForFrames(state, frames);
  const scripts = await captureScripts({
    context,
    events: state.events,
    rawResources: resourceCapture.items,
    resources,
    frameIds: new Set(frames.map((frame) => frame.frame_id)),
  });
  const workers = await captureWorkers(
    { context, allowedOrigins, limitations, events: state.events },
    new Set(frames.map((frame) => frame.frame_id)),
  );
  const storageCapture = await captureStorage(
    context,
    attachedUrl,
    limitations,
  );
  if (!input.include_storage_keys)
    state.events.completeness.exclude("storage_keys", "not_approved", null);
  else if (storageCapture.keysExclusion !== undefined)
    state.events.completeness.exclude(
      "storage_keys",
      storageCapture.keysExclusion,
      null,
    );
  await report(context.progress, 3, "Normalizing browser evidence");
  const completedFrameResult = await authorizedMainFrame({
    connection: context.connection,
    sessionId: context.sessionId,
    signal: context.signal,
    allowedOrigins,
    operation: context.operation,
  });
  const completedUrl = mainFrameUrl(completedFrameResult) ?? "";
  if (state.events.originViolation)
    throw new BrowserObservationError("inspect_web_page", "target_not_allowed");
  if (state.events.navigationDuringCapture || completedUrl !== attachedUrl)
    throw new BrowserObservationError("inspect_web_page", "target_changed");
  // Body IDs were enumerated before asynchronous CDP reads. Events remain
  // enabled through the final capture, so account for eligible responses that
  // arrived while those reads were pending.
  state.events.settleUnexaminedResponseBodies();
  state.events.recordScriptMetadataBudgetExclusions();
  // Surface how many additional scripts came from auto-attached child targets
  // (OOPIF iframes, workers). An empty map on a successful auto-attach simply
  // means the page has no such targets.
  const childCounts = [...state.childScriptCounts.entries()];
  if (childCounts.length > 0) {
    childCounts.sort((left, right) => right[1] - left[1]);
    const summary = childCounts
      .map(([type, count]) => `${type}:${String(count)}`)
      .join(", ");
    state.limitations.push(
      `Expanded script coverage via Target.setAutoAttach: ${summary}. These scripts live in the main scripts.items list and are identified by their origin and URL.`,
    );
  }
  if (state.childAttachFailures.length > 0) {
    const first = state.childAttachFailures.slice(0, 3).join("; ");
    const extra =
      state.childAttachFailures.length > 3
        ? ` (+${String(state.childAttachFailures.length - 3)} further failure(s))`
        : "";
    state.limitations.push(
      `Some auto-attach handshakes failed and their scripts are missing: ${first}${extra}.`,
    );
  }
  // Surface the top out-of-scope origins so callers can tell which hosts to
  // add to `allowed_origins` to recover the missing scripts. The aggregate
  // `scripts/disallowed_origin` count already lives in `completeness.excluded`;
  // this limitation names the hosts.
  const droppedOrigins = [...state.events.droppedScriptOrigins.entries()];
  if (droppedOrigins.length > 0) {
    droppedOrigins.sort((left, right) => right[1] - left[1]);
    const topEntries = droppedOrigins
      .slice(0, 5)
      .map(([origin, count]) => `${origin} (${String(count)})`);
    const totalDropped = droppedOrigins.reduce(
      (sum, [, count]) => sum + count,
      0,
    );
    const remainder =
      droppedOrigins.length > 5
        ? `; +${String(droppedOrigins.length - 5)} further origin(s)`
        : "";
    state.limitations.push(
      `Script metadata was filtered for ${String(totalDropped)} script(s) whose origin is outside allowed_origins. Top origins: ${topEntries.join(", ")}${remainder}. Add them to allowed_origins to retain their scripts.`,
    );
  }
  return {
    inspection: normalizedInspection(state, {
      attachedUrl,
      frames,
      dom,
      accessibility,
      scripts: scripts.inventory,
      resources,
      workers,
      storage: storageCapture.value,
    }),
    sourceMapRequests: scripts.sourceMapRequests,
  };
};

const captureJsonResponseBodies = async (
  state: CaptureState,
): Promise<void> => {
  const requests = state.events.responseBodyRequests();
  for (let index = 0; index < requests.length; index += 1) {
    const candidate = requests[index];
    if (candidate === undefined) continue;
    const current = state.events.currentResponseBodyRequest(candidate);
    if (current === undefined) continue;
    if (current.encoded_data_length === null) {
      state.events.responseBodyUnavailable(candidate);
      continue;
    }
    let result: unknown;
    try {
      result = await optionalCdpCommand(
        state.context,
        "Network.getResponseBody",
        { requestId: candidate.requestId },
        state.limitations,
      );
    } catch (cause: unknown) {
      if (
        !(cause instanceof CdpCommandRejection) ||
        cause.command !== "Network.getResponseBody" ||
        cause.code !== -32_000 ||
        cause.reportedMessage === null
      )
        throw cause;
      state.events.responseBodyUnavailable(candidate);
      state.limitations.push(
        `Response body unavailable for request ${candidate.requestId}: ${cause.userMessage}`,
      );
      continue;
    }
    if (result !== undefined) {
      state.events.ingestResponseBody(candidate, result);
      continue;
    }
    for (const remaining of requests.slice(index))
      state.events.responseBodyUnavailable(remaining);
    return;
  }
};

const authorizeObservationWindow = async (
  state: CaptureState,
): Promise<void> => {
  const { context, allowedOrigins, events } = state;
  const { connection, sessionId, signal } = context;
  await report(context.progress, 1, "Enabling passive CDP domains");
  await connection.send("Page.enable", {}, sessionId, signal);
  const initialFrameResult = await authorizedMainFrame({
    connection: context.connection,
    sessionId: context.sessionId,
    signal: context.signal,
    allowedOrigins,
    operation: context.operation,
  });
  const mainFrame = captureFrames(initialFrameResult, allowedOrigins).items[0];
  if (mainFrame === undefined)
    throw new BrowserObservationError("inspect_web_page", "target_not_allowed");
  events.beginAuthorizedFrame(mainFrame.frame_id);
  await enableObservationDomains(connection, sessionId, signal);
  await enableChildTargetAutoAttach(state);
  await report(context.progress, 2, "Observing page events");
  await delayWithCancellation(
    context.input.observation_ms,
    context.operation,
    signal,
  );
  if (events.originViolation)
    throw new BrowserObservationError("inspect_web_page", "target_not_allowed");
};

const capturePageDom = async (state: CaptureState): Promise<DomCapture> => {
  const { context, allowedOrigins } = state;
  const result = await context.connection.send(
    "DOMSnapshot.captureSnapshot",
    {
      computedStyles: [],
      includePaintOrder: false,
      includeDOMRects: false,
    },
    context.sessionId,
    context.signal,
  );
  const capture = captureDom(
    result,
    allowedOrigins,
    context.input,
    state.events.completeness,
  );
  let step = capture.next();
  let descriptionUnavailable = false;
  const pendingController = new AbortController();
  const signal =
    context.signal === undefined
      ? pendingController.signal
      : AbortSignal.any([context.signal, pendingController.signal]);
  while (!step.done) {
    const pending = step.value.map(async (query) => {
      if (descriptionUnavailable) return undefined;
      try {
        return capturedSvgNodeKind(
          query,
          await context.connection.send(
            "DOM.describeNode",
            { backendNodeId: query.backendNodeId, depth: 0 },
            context.sessionId,
            signal,
          ),
        );
      } catch (cause: unknown) {
        // A detached node can disappear between snapshot and description.
        // Preserve partial metadata, but propagate transport/cancellation errors.
        if (!(cause instanceof CdpCommandRejection)) throw cause;
        if (cause.code === -32_601) descriptionUnavailable = true;
        else if (cause.code !== -32_000) throw cause;
        return undefined;
      }
    });
    try {
      // Promise.all preserves snapshot order even when CDP replies out of order.
      step = capture.next(await Promise.all(pending));
    } catch (cause: unknown) {
      // Stop and settle this bounded batch before the session can be detached.
      pendingController.abort();
      await Promise.allSettled(pending);
      throw cause;
    }
  }
  if (step.value.unresolvedSvgNodes > 0)
    state.limitations.push(
      `SVG identity was unavailable for ${String(step.value.unresolvedSvgNodes)} snapshotted XLink candidate nodes; their URL destinations remain unknown.`,
    );
  return step.value;
};

const normalizedInspection = (
  state: CaptureState,
  captured: CapturedSections,
): WebPageInspection => ({
  browser: state.context.discovery.version,
  target: normalizedTarget(
    state.context.target,
    captured.attachedUrl,
    state.allowedOrigins,
  ),
  capture_window: {
    started_at: state.startedAt,
    ended_at: new Date().toISOString(),
    observation_ms: state.context.input.observation_ms,
  },
  completeness: state.events.completeness.snapshot(),
  frames: [...captured.frames],
  dom: { total_nodes: captured.dom.total, nodes: [...captured.dom.nodes] },
  accessibility: {
    total_nodes: captured.accessibility.total,
    text_capture: captured.accessibility.textCapture,
    nodes: [...captured.accessibility.nodes],
  },
  scripts: captured.scripts,
  resources: [...captured.resources],
  network: {
    requests: [...state.events.network.values()],
    websocket_connections: [...state.events.webSocketConnectionsById.values()],
    coverage_started_at: state.startedAt,
    prior_activity_available: false,
  },
  console: {
    events: [...state.events.console],
    coverage_started_at: state.startedAt,
    prior_activity_available: false,
  },
  workers: [...captured.workers],
  metadata: {
    responses: [...state.events.responseMetadata],
    dom_urls: [...captured.dom.urls],
    agent_hints: deduplicatedAgentHints([
      ...state.events.agentHints,
      ...captured.dom.agentHints,
    ]),
    excluded_dom_urls: captured.dom.excludedUrls,
    headers_allowlisted: true,
  },
  storage: captured.storage,
  limitations: state.limitations,
});

const enableObservationDomains = async (
  connection: CdpConnection,
  sessionId: string | undefined,
  signal?: AbortSignal,
): Promise<void> => {
  await connection.send("Runtime.enable", {}, sessionId, signal);
  await connection.send("Debugger.enable", {}, sessionId, signal);
  await connection.send("Network.enable", {}, sessionId, signal);
};

/** Enable auto-attach on the main session so Chrome delivers
 * `Target.attachedToTarget` events for every OOPIF iframe and worker that
 * belongs to this page — present and future. A failure here is non-fatal: the
 * main-frame capture still proceeds, but a `limitations` string names the
 * expanded coverage we lost. */
const enableChildTargetAutoAttach = async (
  state: CaptureState,
): Promise<void> => {
  try {
    await state.context.connection.send(
      "Target.setAutoAttach",
      { autoAttach: true, waitForDebuggerOnStart: false, flatten: true },
      state.context.sessionId,
      state.context.signal,
    );
    state.autoAttachEnabled = true;
  } catch (cause: unknown) {
    state.limitations.push(
      `Script coverage is limited to the main page: Target.setAutoAttach failed (${
        cause instanceof Error ? cause.message : String(cause)
      }). Cross-origin iframes and workers were not inspected.`,
    );
  }
};

const accessibilityForFrames = async (
  state: CaptureState,
  frames: readonly { readonly frame_id: string }[],
): Promise<ReturnType<typeof captureAccessibility>> => {
  const { context, limitations, events } = state;
  const results: unknown[] = [];
  let unavailable = false;
  for (const frame of frames) {
    const result = await optionalCdpCommand(
      context,
      "Accessibility.getFullAXTree",
      { frameId: frame.frame_id },
      limitations,
    );
    if (result === undefined) unavailable = true;
    else results.push(result);
  }
  if (unavailable) events.completeness.unavailable("accessibility");
  const capture = captureAccessibility(results, {
    includeText: context.input.include_accessibility_text,
    ...(results.length === 0 && unavailable ? { unavailable: true } : {}),
    completeness: events.completeness,
  });
  if (!context.input.include_accessibility_text)
    events.completeness.exclude(
      "accessibility",
      "not_approved",
      capture.textCapture.excluded_fields,
    );
  if (capture.hasUnobservedChildren)
    events.completeness.truncate("accessibility");
  return capture;
};

const publicResource = ({ rawUrl: _rawUrl, ...resource }: CapturedResource) =>
  resource;

const deduplicatedAgentHints = (
  hints: WebPageInspection["metadata"]["agent_hints"],
): WebPageInspection["metadata"]["agent_hints"] => {
  const seen = new Set<string>();
  return hints.filter((hint) => {
    const key = `${hint.mechanism}\0${hint.declaration}\0${hint.url ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

const normalizedTarget = (
  target: CdpEndpointTarget,
  currentUrl: string,
  allowedOrigins: ReadonlySet<string>,
): WebPageInspection["target"] => {
  const url = allowedSanitizedUrl(currentUrl, allowedOrigins);
  return {
    target_id: target.id,
    type: target.type,
    title: target.title,
    url: url?.url ?? "[unsupported-url]",
    origin: url?.origin ?? "",
    attached: target.attached,
  };
};

const report = async (
  progress: ProgressReporter | undefined,
  completed: number,
  message: string,
): Promise<void> =>
  await progress?.report({
    phase: "browser_observation",
    completed,
    total: 3,
    message,
    ...(completed === 3 ? { terminal: true } : {}),
  });
