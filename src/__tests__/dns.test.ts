import { describe, it, expect } from "vitest";
import { analyzeSpf, analyzeDmarc, formatDnsReport, formatSubdomainReport } from "../dns.js";
import type { DnsRecord, DnsEnumerationResult, SubdomainResult } from "../dns.js";

// ── SPF analysis ──────────────────────────────────────────────────────────────

describe("analyzeSpf", () => {
  function txt(value: string): DnsRecord[] {
    return [{ type: "TXT", value }];
  }

  it("returns null when no SPF record", () => {
    expect(analyzeSpf([{ type: "TXT", value: "some-other-record" }])).toBeNull();
  });

  it("parses a valid -all SPF record with no issues", () => {
    const result = analyzeSpf(txt("v=spf1 include:_spf.google.com -all"));
    expect(result).not.toBeNull();
    expect(result!.allMechanism).toBe("-all");
    expect(result!.issues).toHaveLength(0);
  });

  it("flags +all as critical", () => {
    const result = analyzeSpf(txt("v=spf1 +all"));
    expect(result!.issues.some((f) => f.code === "SPF_PERMISSIVE_ALL" && f.severity === "critical")).toBe(true);
  });

  it("flags ?all as high", () => {
    const result = analyzeSpf(txt("v=spf1 include:mail.example.com ?all"));
    expect(result!.issues.some((f) => f.code === "SPF_NEUTRAL_ALL" && f.severity === "high")).toBe(true);
  });

  it("flags missing all mechanism as medium", () => {
    const result = analyzeSpf(txt("v=spf1 include:mail.example.com"));
    expect(result!.issues.some((f) => f.code === "SPF_NO_ALL" && f.severity === "medium")).toBe(true);
  });

  it("flags >10 DNS lookups as high", () => {
    const mechanisms = Array.from({ length: 11 }, (_, i) => `include:mail${i}.example.com`).join(" ");
    const result = analyzeSpf(txt(`v=spf1 ${mechanisms} -all`));
    expect(result!.lookupCount).toBeGreaterThan(10);
    expect(result!.issues.some((f) => f.code === "SPF_TOO_MANY_LOOKUPS")).toBe(true);
  });

  it("flags duplicate SPF records", () => {
    const records: DnsRecord[] = [
      { type: "TXT", value: "v=spf1 -all" },
      { type: "TXT", value: "v=spf1 include:other.com -all" },
    ];
    const result = analyzeSpf(records);
    expect(result!.issues.some((f) => f.code === "SPF_DUPLICATE")).toBe(true);
  });

  it("extracts mechanisms correctly", () => {
    const result = analyzeSpf(txt("v=spf1 include:_spf.google.com ip4:1.2.3.4 -all"));
    expect(result!.mechanisms).toContain("include:_spf.google.com");
    expect(result!.mechanisms).toContain("ip4:1.2.3.4");
  });
});

// ── DMARC analysis ────────────────────────────────────────────────────────────

describe("analyzeDmarc", () => {
  it("returns null for null input", () => {
    expect(analyzeDmarc(null)).toBeNull();
  });

  it("parses reject policy with no issues", () => {
    const result = analyzeDmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100");
    expect(result!.policy).toBe("reject");
    expect(result!.pct).toBe(100);
    expect(result!.rua).toContain("mailto:dmarc@example.com");
    expect(result!.issues).toHaveLength(0);
  });

  it("flags p=none policy as medium", () => {
    const result = analyzeDmarc("v=DMARC1; p=none; rua=mailto:dmarc@example.com");
    expect(result!.issues.some((f) => f.code === "DMARC_POLICY_NONE" && f.severity === "medium")).toBe(true);
  });

  it("flags missing policy as high", () => {
    const result = analyzeDmarc("v=DMARC1; rua=mailto:dmarc@example.com");
    expect(result!.issues.some((f) => f.code === "DMARC_NO_POLICY" && f.severity === "high")).toBe(true);
  });

  it("flags missing rua as low", () => {
    const result = analyzeDmarc("v=DMARC1; p=reject");
    expect(result!.issues.some((f) => f.code === "DMARC_NO_RUA" && f.severity === "low")).toBe(true);
  });

  it("flags quarantine with pct < 100 as low", () => {
    const result = analyzeDmarc("v=DMARC1; p=quarantine; rua=mailto:r@example.com; pct=50");
    expect(result!.issues.some((f) => f.code === "DMARC_PCT_LOW")).toBe(true);
  });

  it("parses multiple rua addresses", () => {
    const result = analyzeDmarc("v=DMARC1; p=reject; rua=mailto:a@example.com,mailto:b@example.com");
    expect(result!.rua).toHaveLength(2);
  });
});

// ── formatDnsReport ───────────────────────────────────────────────────────────

describe("formatDnsReport", () => {
  function makeResult(overrides: Partial<DnsEnumerationResult> = {}): DnsEnumerationResult {
    return {
      domain: "example.com",
      records: {
        A: [{ type: "A", value: "93.184.216.34", ttl: 3600 }],
        MX: [{ type: "MX", value: "10 mail.example.com" }],
      },
      findings: [{ severity: "info", code: "OK", message: "No DNS misconfigurations found" }],
      ...overrides,
    };
  }

  it("includes domain name in report", () => {
    const report = formatDnsReport(makeResult());
    expect(report).toContain("example.com");
  });

  it("shows A records", () => {
    const report = formatDnsReport(makeResult());
    expect(report).toContain("93.184.216.34");
  });

  it("shows MX records", () => {
    const report = formatDnsReport(makeResult());
    expect(report).toContain("mail.example.com");
  });

  it("shows no issues message when clean", () => {
    const report = formatDnsReport(makeResult());
    expect(report).toContain("No DNS misconfigurations found");
  });

  it("shows issues when present", () => {
    const result = makeResult({
      findings: [{ severity: "high", code: "DMARC_MISSING", message: "No DMARC record found" }],
    });
    const report = formatDnsReport(result);
    expect(report).toContain("[HIGH]");
    expect(report).toContain("DMARC");
  });
});

// ── formatSubdomainReport ─────────────────────────────────────────────────────

describe("formatSubdomainReport", () => {
  it("shows found subdomains", () => {
    const results: SubdomainResult[] = [
      { subdomain: "www.example.com", resolves: true, addresses: ["1.2.3.4"] },
      { subdomain: "api.example.com", resolves: true, cname: "api.example.net" },
    ];
    const report = formatSubdomainReport("example.com", results);
    expect(report).toContain("www.example.com");
    expect(report).toContain("api.example.com");
  });

  it("flags dangling subdomains", () => {
    const results: SubdomainResult[] = [
      {
        subdomain: "old.example.com",
        resolves: true,
        cname: "old.s3.amazonaws.com",
        dangling: true,
        danglingReason: "CNAME points to unclaimed AWS S3 resource",
      },
    ];
    const report = formatSubdomainReport("example.com", results);
    expect(report).toContain("DANGLING");
    expect(report).toContain("AWS S3");
  });

  it("shows count summary", () => {
    const results: SubdomainResult[] = [
      { subdomain: "www.example.com", resolves: true, addresses: ["1.2.3.4"] },
    ];
    const report = formatSubdomainReport("example.com", results);
    expect(report).toContain("1 live subdomain");
  });
});
