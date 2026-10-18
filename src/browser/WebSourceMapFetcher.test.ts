import { expect, it } from "vitest";

import { fetchWebSourceMaps } from "./WebSourceMapFetcher.js";
import { analyzeWebBundleInputSchema } from "../domain/webBundleAnalysis.js";

const input = analyzeWebBundleInputSchema.parse({
  cdp_endpoint: "http://127.0.0.1:9222",
  allowed_origins: ["http://127.0.0.1:9222"],
  target_id: "page-1",
  fetch_source_maps: true,
});

it("marks the result unavailable when the caller requested fetching but no in-scope sourceMappingURL was observed", async () => {
  const result = await fetchWebSourceMaps([], input, undefined, {
    fetch: async () => {
      throw new Error("No source-map request should be made");
    },
  });

  // Prior to the fix this returned `status: "not_requested"` even when
  // `fetch_source_maps: true`, which was indistinguishable from "the caller
  // did not ask". The caller asked; we just had nothing to fetch.
  expect(result).toEqual({
    status: "unavailable",
    requested: 0,
    processed: 0,
    items: [],
    limitation:
      "No in-scope sourceMappingURL references were observed; no source maps were fetched.",
  });
});

it("honors cancellation before returning an empty request set", async () => {
  const controller = new AbortController();
  const reason = new Error("cancelled before fetching");
  controller.abort(reason);

  await expect(fetchWebSourceMaps([], input, controller.signal)).rejects.toBe(
    reason,
  );
});
