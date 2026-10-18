/**
 * Unit tests for the auto-attach wiring in CdpPageCapture: how we fan the
 * main-session CDP event stream out to cover OOPIF iframes and workers (the
 * "100% script coverage" fix). These tests exercise the pure routing/remap
 * helpers in isolation — the fire-and-forget enable-domains work on a child
 * session needs a live CdpConnection and lives behind the integration suite.
 */
import { describe, expect, it } from "vitest";

import { CdpCaptureEvents } from "./CdpCaptureEvents.js";
import { inspectWebPageInputSchema } from "../domain/browserObservation.js";
import {
  routeCdpEvent,
  remapChildEvent,
  handleTargetAttached,
  handleTargetDetached,
  type CaptureState,
} from "./CdpPageCapture.js";

const makeInput = () =>
  inspectWebPageInputSchema.parse({
    cdp_endpoint: "http://127.0.0.1:9222",
    allowed_origins: ["https://app.example.test"],
    target_id: "root-target",
    observation_ms: 500,
    include_accessibility_text: false,
    include_console_text: false,
    include_json_body_shapes: false,
    include_websocket_shapes: false,
    include_storage_keys: false,
    include_storage_fingerprints: false,
    include_script_sources: true,
  });

const makeState = (): CaptureState => {
  const input = makeInput();
  const allowedOrigins = new Set(input.allowed_origins);
  const events = new CdpCaptureEvents(input, allowedOrigins);
  // The ingest switch keys off `scripts` existing; make sure we start fresh.
  events.beginAuthorizedFrame("root-frame");
  return {
    context: {
      // We never call .send in these tests — handleTargetAttached dispatches
      // its work via void (async () => ...)(), and we don't await it.
      connection: {
        send: () => Promise.reject(new Error("not reached in this test")),
        onEvent: () => () => undefined,
      } as never,
      sessionId: "main-session",
      operation: "inspect_web_page",
      discovery: {} as never,
      target: {
        id: "root-target",
        type: "page",
        title: "",
        url: "https://app.example.test/",
        origin: "https://app.example.test",
        attached: true,
      } as never,
      input,
    },
    events,
    allowedOrigins,
    limitations: [],
    startedAt: new Date(0).toISOString(),
    childSessions: new Map(),
    autoAttachEnabled: false,
    childScriptCounts: new Map(),
    childAttachFailures: [],
  };
};

describe("handleTargetAttached", () => {
  it("records OOPIF iframe child sessions and fires-and-forgets domain enabling", () => {
    const state = makeState();
    handleTargetAttached(
      {
        sessionId: "child-iframe-1",
        targetInfo: {
          type: "iframe",
          targetId: "iframe-1",
          url: "https://widget.example.com/embed",
          attached: true,
        },
      },
      state,
    );
    expect(state.childSessions.get("child-iframe-1")).toEqual({
      sessionId: "child-iframe-1",
      targetId: "iframe-1",
      type: "iframe",
      url: "https://widget.example.com/embed",
    });
  });

  it("records all four auto-attachable target types (iframe + 3 worker flavors)", () => {
    const state = makeState();
    const types = [
      "iframe",
      "worker",
      "shared_worker",
      "service_worker",
    ] as const;
    for (const type of types)
      handleTargetAttached(
        {
          sessionId: `s-${type}`,
          targetInfo: {
            type,
            targetId: `t-${type}`,
            url: `https://w.example.com/${type}`,
          },
        },
        state,
      );
    expect([...state.childSessions.keys()].sort()).toEqual(
      types.map((t) => `s-${t}`).sort(),
    );
  });

  it("ignores target types we deliberately do not attach to (page, browser, other)", () => {
    const state = makeState();
    for (const type of ["page", "browser", "background_page", "unknown"])
      handleTargetAttached(
        {
          sessionId: `s-${type}`,
          targetInfo: {
            type,
            targetId: `t-${type}`,
            url: "https://other.example.com/",
          },
        },
        state,
      );
    expect(state.childSessions.size).toBe(0);
  });

  it("drops malformed Target.attachedToTarget payloads", () => {
    const state = makeState();
    handleTargetAttached(null, state);
    handleTargetAttached({ sessionId: "" }, state);
    handleTargetAttached({ sessionId: "ok", targetInfo: null }, state);
    handleTargetAttached(
      {
        sessionId: "ok",
        targetInfo: { type: 42, targetId: "x", url: "x" },
      },
      state,
    );
    expect(state.childSessions.size).toBe(0);
  });

  it("deduplicates repeat attach events for the same session", () => {
    const state = makeState();
    const payload = {
      sessionId: "s1",
      targetInfo: {
        type: "worker",
        targetId: "t1",
        url: "https://app.example.test/sw.js",
      },
    };
    handleTargetAttached(payload, state);
    handleTargetAttached(payload, state);
    expect(state.childSessions.size).toBe(1);
  });
});

describe("handleTargetDetached", () => {
  it("removes a tracked child session", () => {
    const state = makeState();
    handleTargetAttached(
      {
        sessionId: "s-worker",
        targetInfo: {
          type: "worker",
          targetId: "t-worker",
          url: "https://app.example.test/w.js",
        },
      },
      state,
    );
    handleTargetDetached({ sessionId: "s-worker" }, state);
    expect(state.childSessions.size).toBe(0);
  });

  it("is a no-op for untracked sessions and malformed payloads", () => {
    const state = makeState();
    handleTargetDetached({ sessionId: "never-attached" }, state);
    handleTargetDetached(null, state);
    handleTargetDetached({}, state);
    expect(state.childSessions.size).toBe(0);
  });
});

describe("remapChildEvent", () => {
  const attachment = {
    sessionId: "child-1",
    targetId: "t",
    type: "iframe" as const,
    url: null,
  };

  it("prefixes Debugger.scriptParsed scriptId so main-session ids cannot collide", () => {
    const event = {
      method: "Debugger.scriptParsed",
      params: {
        scriptId: "7",
        url: "https://widget.example.com/w.js",
        hash: "cdp-hash",
      },
      sessionId: "child-1",
    };
    const remapped = remapChildEvent(event, attachment);
    expect(remapped).toBeDefined();
    expect((remapped!.params as { scriptId: string }).scriptId).toBe(
      "iframe:child-1:7",
    );
    // Original URL is preserved so stable keys still resolve correctly.
    expect((remapped!.params as { url: string }).url).toBe(
      "https://widget.example.com/w.js",
    );
  });

  it("preserves other Runtime.executionContext event params without mutating input", () => {
    const originalContext = { id: 42, name: "main", origin: "https://x.test" };
    const event = {
      method: "Runtime.executionContextCreated",
      params: { context: originalContext },
      sessionId: "child-1",
    };
    const remapped = remapChildEvent(event, attachment);
    expect(remapped).toBeDefined();
    const ctx = (remapped!.params as { context: { id: number; name: string } })
      .context;
    expect(ctx.id).toBe(Number.MAX_SAFE_INTEGER - 42);
    expect(ctx.name).toBe("main");
    // Mutation isolation: the shared `context` object we passed in is untouched.
    expect(originalContext.id).toBe(42);
  });

  it("drops Network/console/websocket events (we only enable Runtime+Debugger on children)", () => {
    for (const method of [
      "Network.requestWillBeSent",
      "Network.responseReceived",
      "Runtime.consoleAPICalled",
      "Network.webSocketCreated",
    ])
      expect(
        remapChildEvent(
          { method, params: {}, sessionId: "child-1" },
          attachment,
        ),
      ).toBeUndefined();
  });
});

describe("routeCdpEvent", () => {
  it("ingests main-session events unchanged", () => {
    const state = makeState();
    routeCdpEvent(
      {
        method: "Debugger.scriptParsed",
        params: {
          scriptId: "main-7",
          url: "https://app.example.test/x.js",
          hash: "cdp-hash",
        },
        sessionId: "main-session",
      },
      state,
    );
    expect(state.events.scripts.has("main-7")).toBe(true);
  });

  it("ignores events from unknown sessions (not main, not attached)", () => {
    const state = makeState();
    routeCdpEvent(
      {
        method: "Debugger.scriptParsed",
        params: {
          scriptId: "x",
          url: "https://app.example.test/x.js",
          hash: "cdp-hash",
        },
        sessionId: "stranger",
      },
      state,
    );
    expect(state.events.scripts.size).toBe(0);
  });

  it("after Target.attachedToTarget, forwards that child's scriptParsed with a scoped id and bumps child-count", () => {
    const state = makeState();
    routeCdpEvent(
      {
        method: "Target.attachedToTarget",
        params: {
          sessionId: "s-iframe",
          targetInfo: {
            type: "iframe",
            targetId: "t-iframe",
            url: "https://widget.example.com/",
          },
        },
        sessionId: "main-session",
      },
      state,
    );
    expect(state.childSessions.size).toBe(1);
    routeCdpEvent(
      {
        method: "Debugger.scriptParsed",
        params: {
          scriptId: "7",
          url: "https://widget.example.com/w.js",
          hash: "cdp-hash",
        },
        sessionId: "s-iframe",
      },
      state,
    );
    expect(state.events.scripts.has("iframe:s-iframe:7")).toBe(true);
    expect(state.childScriptCounts.get("iframe")).toBe(1);
  });

  it("Target.detachedFromTarget stops forwarding events from that session", () => {
    const state = makeState();
    routeCdpEvent(
      {
        method: "Target.attachedToTarget",
        params: {
          sessionId: "s-sw",
          targetInfo: {
            type: "service_worker",
            targetId: "t-sw",
            url: "https://app.example.test/sw.js",
          },
        },
        sessionId: "main-session",
      },
      state,
    );
    routeCdpEvent(
      {
        method: "Target.detachedFromTarget",
        params: { sessionId: "s-sw" },
        sessionId: "main-session",
      },
      state,
    );
    const scriptsBefore = state.events.scripts.size;
    routeCdpEvent(
      {
        method: "Debugger.scriptParsed",
        params: {
          scriptId: "9",
          url: "https://app.example.test/sw.js",
          hash: "cdp-hash",
        },
        sessionId: "s-sw",
      },
      state,
    );
    expect(state.events.scripts.size).toBe(scriptsBefore);
  });
});
