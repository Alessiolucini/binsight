import type { InspectWebPageInput } from "../domain/browserObservation.js";
import type { WebPageInspection } from "../domain/browserObservationSchemas.js";
import type { CdpCaptureCompleteness } from "./CdpCaptureCompleteness.js";
import type { CapturedScript, NetworkState } from "./CdpCaptureEventTypes.js";

export interface CdpCaptureEventsState {
  readonly input: InspectWebPageInput;
  readonly allowedOrigins: ReadonlySet<string>;
  readonly scripts: Map<string, CapturedScript>;
  readonly scriptMetadataBudgetOmissionsById: Map<string, true>;
  /** Count of dropped scripts, keyed by the HTTP(S) origin we filtered them from.
   * Populated when a `Debugger.scriptParsed` URL has an origin outside
   * `allowed_origins` so we can surface the top missing origins back to the
   * caller instead of only an aggregate `disallowed_origin` count. */
  readonly droppedScriptOrigins: Map<string, number>;
  rejectedScriptMetadataBudgetCount: number;
  rejectedSourceMapMetadataBudgetCount: number;
  readonly scriptMetadataBytesById: Map<string, number>;
  retainedScriptMetadataBytes: number;
  readonly executionContextFrames: Map<string, string>;
  readonly network: Map<string, NetworkState>;
  readonly networkRequestTimestamps: Map<string, number>;
  readonly malformedRedirectRequestIds: Set<string>;
  readonly webSocketConnectionsById: Map<
    string,
    WebPageInspection["network"]["websocket_connections"][number]
  >;
  console: WebPageInspection["console"]["events"];
  responseMetadata: WebPageInspection["metadata"]["responses"];
  agentHints: WebPageInspection["metadata"]["agent_hints"];
  readonly completeness: CdpCaptureCompleteness;
  originViolation: boolean;
  navigationDuringCapture: boolean;
  mainFrameId: string | undefined;
  /**
   * Identity of the document last observed in the main frame. `frameNavigated`
   * re-fires for the same document, so this is what distinguishes a real
   * document change from a duplicate event.
   */
  committedDocument: string | undefined;
}
