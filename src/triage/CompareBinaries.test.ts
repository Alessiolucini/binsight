import { describe, expect, it } from "vitest";
import { compareBinariesInputSchema } from "../domain/triage/compareBinaries.js";
import { diffBinaries } from "./CompareBinariesDiff.js";

const input = (over: Record<string, unknown> = {}) =>
  compareBinariesInputSchema.parse({
    base_path: "/a",
    target_path: "/b",
    ...over,
  });

describe("diffBinaries", () => {
  it("reports identical buffers with no regions", () => {
    const buf = Buffer.from([1, 2, 3, 4]);
    const r = diffBinaries(buf, Buffer.from(buf), input());
    expect(r.identical).toBe(true);
    expect(r.changed_bytes).toBe(0);
    expect(r.regions).toHaveLength(0);
    expect(r.changed_range).toBeNull();
  });

  it("classifies a zeroed region", () => {
    const base = Buffer.from([0x11, 0x22, 0x33, 0x44]);
    const target = Buffer.from([0x11, 0x00, 0x00, 0x44]);
    const r = diffBinaries(base, target, input({ word_size: 1 }));
    expect(r.regions).toHaveLength(1);
    expect(r.regions[0]?.kind).toBe("zeroed");
    expect(r.summary.zeroed_bytes).toBe(2);
    expect(r.changed_bytes).toBe(2);
  });

  it("classifies a 0xFF-filled region (limit removal)", () => {
    const base = Buffer.from([0x10, 0x20, 0x30, 0x40]);
    const target = Buffer.from([0x10, 0xff, 0xff, 0x40]);
    const r = diffBinaries(base, target, input({ word_size: 1 }));
    expect(r.regions[0]?.kind).toBe("filled");
    expect(r.summary.filled_bytes).toBe(2);
  });

  it("reports before/after values for a modified region (rev-limiter style)", () => {
    // 0x191F (6431) little-endian at offset 2 -> 0x1D24 (7460)
    const base = Buffer.from([0x00, 0x00, 0x1f, 0x19]);
    const target = Buffer.from([0x00, 0x00, 0x24, 0x1d]);
    const r = diffBinaries(base, target, input({ word_size: 2 }));
    expect(r.regions[0]?.kind).toBe("modified");
    const sample = r.regions[0]?.samples[0];
    expect(sample?.before).toBe(6431);
    expect(sample?.after).toBe(7460);
    expect(sample?.offset).toBe("0x2");
  });

  it("coalesces nearby changes by the region gap and bounds regions", () => {
    const base = Buffer.alloc(100, 0x55);
    const target = Buffer.from(base);
    target[0] = 0x00;
    target[5] = 0x00; // within gap 32 -> same region
    target[80] = 0x00; // far -> separate region
    const r = diffBinaries(base, target, input({ region_gap: 32 }));
    expect(r.summary.region_count).toBe(2);
    expect(r.region_coverage.total).toBe(2);
  });

  it("truncates regions and reports coverage", () => {
    const base = Buffer.alloc(1000, 0x55);
    const target = Buffer.from(base);
    for (let i = 0; i < 1000; i += 50) target[i] = 0x00; // 20 far-apart regions
    const r = diffBinaries(
      base,
      target,
      input({ region_gap: 1, max_regions: 5 }),
    );
    expect(r.regions).toHaveLength(5);
    expect(r.region_coverage.truncated).toBe(true);
    expect(r.region_coverage.total).toBe(20);
  });

  it("compares only the shorter length and reports size_delta", () => {
    const base = Buffer.from([1, 2, 3]);
    const target = Buffer.from([1, 2, 3, 9, 9]);
    const r = diffBinaries(base, target, input());
    expect(r.compared_bytes).toBe(3);
    expect(r.size_delta).toBe(2);
    expect(r.identical).toBe(false);
    expect(r.changed_bytes).toBe(0);
  });
});
