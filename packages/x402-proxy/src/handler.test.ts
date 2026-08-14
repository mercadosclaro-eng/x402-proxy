import { describe, expect, it } from "vitest";
import {
  computeMppVoucherTarget,
  detectProtocols,
  extractTxSignature,
  splitSseFrames,
} from "./handler.js";

describe("detectProtocols", () => {
  it("detects MPP from WWW-Authenticate Payment header", () => {
    const r = new Response(null, {
      status: 402,
      headers: { "WWW-Authenticate": 'Payment id="abc", realm="test"' },
    });
    expect(detectProtocols(r)).toEqual({ x402: false, mpp: true });
  });

  it("detects x402 from PAYMENT-REQUIRED header", () => {
    const r = new Response(null, {
      status: 402,
      headers: { "PAYMENT-REQUIRED": "eyJ0ZXN0IjoxfQ==" },
    });
    expect(detectProtocols(r)).toEqual({ x402: true, mpp: false });
  });

  it("detects both protocols when both headers present", () => {
    const r = new Response(null, {
      status: 402,
      headers: {
        "WWW-Authenticate": 'Payment id="abc"',
        "PAYMENT-REQUIRED": "eyJ0ZXN0IjoxfQ==",
      },
    });
    expect(detectProtocols(r)).toEqual({ x402: true, mpp: true });
  });

  it("returns both false when neither header present", () => {
    const r = new Response(null, { status: 402 });
    expect(detectProtocols(r)).toEqual({ x402: false, mpp: false });
  });

  it("ignores non-Payment WWW-Authenticate schemes", () => {
    const r = new Response(null, {
      status: 402,
      headers: { "WWW-Authenticate": "Bearer realm=api" },
    });
    expect(detectProtocols(r)).toEqual({ x402: false, mpp: false });
  });

  it("detects X-PAYMENT-REQUIRED variant", () => {
    const r = new Response(null, {
      status: 402,
      headers: { "X-PAYMENT-REQUIRED": "eyJ0ZXN0IjoxfQ==" },
    });
    expect(detectProtocols(r)).toEqual({ x402: true, mpp: false });
  });
});

// --- extractTxSignature ---

describe("extractTxSignature", () => {
  it("extracts reference from MPP Payment-Receipt header", () => {
    const receipt = { method: "tempo", reference: "0xabc123", status: "confirmed" };
    const encoded = Buffer.from(JSON.stringify(receipt)).toString("base64url");
    const r = new Response(null, { headers: { "Payment-Receipt": encoded } });
    expect(extractTxSignature(r)).toBe("0xabc123");
  });

  it("returns undefined for malformed Payment-Receipt", () => {
    const r = new Response(null, { headers: { "Payment-Receipt": "not-valid-base64url" } });
    expect(extractTxSignature(r)).toBeUndefined();
  });

  it("returns undefined when no payment headers present", () => {
    const r = new Response(null);
    expect(extractTxSignature(r)).toBeUndefined();
  });
});

describe("computeMppVoucherTarget", () => {
  it("adds voucher headroom when deposit allows it", () => {
    expect(
      computeMppVoucherTarget({
        requiredCumulative: 1_000_000n,
        deposit: 10_000_000n,
        headroom: 5_000_000n,
      }),
    ).toBe(6_000_000n);
  });

  it("clamps the target to deposit", () => {
    expect(
      computeMppVoucherTarget({
        requiredCumulative: 8_000_000n,
        deposit: 10_000_000n,
        headroom: 5_000_000n,
      }),
    ).toBe(10_000_000n);
  });

  it("falls back to the required cumulative amount when no headroom is available", () => {
    expect(
      computeMppVoucherTarget({
        requiredCumulative: 3_000_000n,
        deposit: 3_000_000n,
        headroom: 5_000_000n,
      }),
    ).toBe(3_000_000n);
  });
});

describe("splitSseFrames", () => {
  it("splits complete LF frames and keeps the trailing partial", () => {
    const { frames, rest } = splitSseFrames("event: a\ndata: 1\n\nevent: b\ndata: 2\n\nevent: c");
    expect(frames).toEqual(["event: a\ndata: 1", "event: b\ndata: 2"]);
    expect(rest).toBe("event: c");
  });

  it("splits CRLF-framed streams", () => {
    const { frames, rest } = splitSseFrames(
      "event: a\r\ndata: 1\r\n\r\nevent: b\r\ndata: 2\r\n\r\n",
    );
    expect(frames).toEqual(["event: a\ndata: 1", "event: b\ndata: 2"]);
    expect(rest).toBe("");
  });

  it("splits bare-CR framed streams", () => {
    const { frames } = splitSseFrames("event: a\rdata: 1\r\rrest");
    expect(frames).toEqual(["event: a\ndata: 1"]);
  });

  it("drops blank frames from keep-alive padding", () => {
    const { frames } = splitSseFrames("\n\n\n\ndata: 1\n\n");
    expect(frames).toEqual(["data: 1"]);
  });

  it("returns no frames until a terminator arrives", () => {
    const { frames, rest } = splitSseFrames("data: partial");
    expect(frames).toEqual([]);
    expect(rest).toBe("data: partial");
  });

  it("reassembles a frame split across reads", () => {
    const first = splitSseFrames("data: hel");
    expect(first.frames).toEqual([]);
    const second = splitSseFrames(`${first.rest}lo\n\n`);
    expect(second.frames).toEqual(["data: hello"]);
    expect(second.rest).toBe("");
  });
});
