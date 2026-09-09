import type { DnsEnumerationResult, Finding } from "./dns.js";

// ── SARIF 2.1.0 types (minimal) ───────────────────────────────────────────────

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri?: string;
  properties: { "problem.severity": string; tags: string[] };
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }>;
}

function severityToLevel(sev: string): "error" | "warning" | "note" {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

const HELP_URLS: Record<string, string> = {
  SPF_MISSING: "https://guardbee.ai/docs/dns#spf",
  SPF_PERMISSIVE_ALL: "https://guardbee.ai/docs/dns#spf",
  SPF_NEUTRAL_ALL: "https://guardbee.ai/docs/dns#spf",
  SPF_NO_ALL: "https://guardbee.ai/docs/dns#spf",
  SPF_TOO_MANY_LOOKUPS: "https://guardbee.ai/docs/dns#spf",
  SPF_DUPLICATE: "https://guardbee.ai/docs/dns#spf",
  DMARC_MISSING: "https://guardbee.ai/docs/dns#dmarc",
  DMARC_NO_POLICY: "https://guardbee.ai/docs/dns#dmarc",
  DMARC_POLICY_NONE: "https://guardbee.ai/docs/dns#dmarc",
};

export function buildSarif(
  toolVersion: string,
  domain: string,
  findings: Finding[]
): object {
  const rulesMap = new Map<string, SarifRule>();
  const sarifResults: SarifResult[] = [];
  const domainUri = `dns://${domain}`;

  for (const f of findings) {
    if (!rulesMap.has(f.code)) {
      rulesMap.set(f.code, {
        id: f.code,
        name: f.code.replace(/_/g, ""),
        shortDescription: { text: f.message },
        helpUri: HELP_URLS[f.code] ?? "https://guardbee.ai/docs/dns",
        properties: {
          "problem.severity": f.severity,
          tags: ["security", "dns", "email-security"],
        },
      });
    }

    sarifResults.push({
      ruleId: f.code,
      level: severityToLevel(f.severity),
      message: { text: `${domain}: ${f.message}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: domainUri },
          },
        },
      ],
    });
  }

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "@guardbee/mcp-dns-intelligence",
            version: toolVersion,
            informationUri: "https://guardbee.ai",
            rules: Array.from(rulesMap.values()),
          },
        },
        results: sarifResults,
      },
    ],
  };
}
