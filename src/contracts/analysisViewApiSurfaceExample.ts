/** Generated from the two-request apiSurfaceHar fixture through the HAR decoder and view service. */
export const API_SURFACE_EXAMPLE = {
  input: {
    source: {
      kind: "retained-evidence",
      evidence_id:
        "ev_dd6f24c1a08bb1f67856ae0b48eb19008895edcea79104da335d7941922b142d",
    },
    view: {
      kind: "api-surface",
      offset: 0,
      limit: 50,
    },
  },
  output: {
    parent_evidence_id:
      "ev_dd6f24c1a08bb1f67856ae0b48eb19008895edcea79104da335d7941922b142d",
    parent_operation: "inspect_web_network_capture",
    parent_digest:
      "dd6f24c1a08bb1f67856ae0b48eb19008895edcea79104da335d7941922b142d",
    view_digest:
      "bd58228b01006b07657c3ed3e409e327b61153b0ff01a8676b02b0eb662d5398",
    artifact: {
      path: "/fixtures/api-surface.har",
      sha256:
        "4a1411315a0e2ace8f10a7a59b7e5c31e464b917d2448868366eaae3b49553be",
    },
    coverage: {
      status: "page",
      examined: 1,
      total: 1,
      next_offset: null,
      exhausted: true,
    },
    limitations: [
      "Grouping does not establish handler identity, URL-space schemas or causality.",
      "HAR text is producer-decoded Unicode. Original body bytes remain unknown unless content explicitly uses valid base64; declared sizes are preserved independently of retained bytes. mitmproxy 12.2.3 SaveHar may report null optional postData.text; that null is retained and omitted only from the upstream validation copy.",
    ],
    unknowns: [],
    records: {
      examined: 2,
      total: 2,
      excluded: 0,
    },
    templated_groups: 1,
    groups: [
      {
        method: "GET",
        origin: "https://api.example.test",
        path_template: "/users/{numeric}",
        templated_segments: [
          {
            segment_index: 1,
            rule: "numeric",
            basis: "inferred",
            observed_values: ["8812", "9031"],
          },
        ],
        record_ordinals: [0, 1],
        statuses: [200, 404],
        content_types: ["application/json", "text/plain"],
        flags: ["mixed-statuses", "mixed-content-types"],
      },
    ],
    excluded_records: [],
    kind: "api-surface",
    view: {
      kind: "api-surface",
      offset: 0,
      limit: 50,
    },
  },
} as const;
