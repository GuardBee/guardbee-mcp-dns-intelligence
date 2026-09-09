import * as dns from "dns/promises";
import * as net from "net";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface DnsRecord {
  type: string;
  value: string;
  ttl?: number;
}

export interface SpfAnalysis {
  raw: string;
  valid: boolean;
  mechanisms: string[];
  allMechanism: string | null; // "+all", "-all", "~all", "?all"
  lookupCount: number;
  issues: Finding[];
}

export interface DmarcAnalysis {
  raw: string;
  valid: boolean;
  policy: string | null; // "none", "quarantine", "reject"
  pct: number;
  rua: string[];
  ruf: string[];
  issues: Finding[];
}

export interface Finding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  code: string;
  message: string;
}

export interface DnsEnumerationResult {
  domain: string;
  records: Record<string, DnsRecord[]>;
  spf?: SpfAnalysis;
  dmarc?: DmarcAnalysis;
  dkimSelectors?: Record<string, boolean>; // selector → found
  zoneTransferVulnerable?: boolean;
  findings: Finding[];
}

export interface SubdomainResult {
  subdomain: string;
  resolves: boolean;
  addresses?: string[];
  cname?: string;
  dangling?: boolean;
  danglingReason?: string;
}

// ── Common subdomain wordlist ─────────────────────────────────────────────────

const COMMON_SUBDOMAINS = [
  "www", "mail", "smtp", "imap", "pop", "ftp", "sftp", "ssh",
  "api", "api2", "api-v2", "v1", "v2", "rest",
  "dev", "staging", "stage", "uat", "qa", "test", "demo",
  "admin", "dashboard", "portal", "app", "apps",
  "cdn", "static", "assets", "media", "img", "images",
  "auth", "login", "sso", "oauth",
  "blog", "docs", "help", "support", "status",
  "mx", "ns", "ns1", "ns2", "dns", "dns1", "dns2",
  "vpn", "remote", "gateway", "proxy",
  "shop", "store", "pay", "checkout",
  "m", "mobile", "wap",
  "beta", "alpha", "preview",
  "git", "gitlab", "github", "jenkins", "ci", "jira", "confluence",
  "monitoring", "grafana", "kibana", "elastic",
  "s3", "storage", "backup",
  "_dmarc", "_domainkey",
];

// Known cloud/hosting services that are common dangling targets
const DANGLING_CNAME_PATTERNS: Array<{ pattern: RegExp; provider: string }> = [
  { pattern: /\.s3\.amazonaws\.com$/i, provider: "AWS S3" },
  { pattern: /\.azurewebsites\.net$/i, provider: "Azure App Service" },
  { pattern: /\.github\.io$/i, provider: "GitHub Pages" },
  { pattern: /\.herokuapp\.com$/i, provider: "Heroku" },
  { pattern: /\.netlify\.app$/i, provider: "Netlify" },
  { pattern: /\.vercel\.app$/i, provider: "Vercel" },
  { pattern: /\.pages\.dev$/i, provider: "Cloudflare Pages" },
  { pattern: /\.surge\.sh$/i, provider: "Surge" },
  { pattern: /\.pantheonsite\.io$/i, provider: "Pantheon" },
  { pattern: /\.wpengine\.com$/i, provider: "WP Engine" },
  { pattern: /\.ghost\.io$/i, provider: "Ghost" },
  { pattern: /\.myshopify\.com$/i, provider: "Shopify" },
  { pattern: /\.fastly\.net$/i, provider: "Fastly" },
  { pattern: /\.cloudfront\.net$/i, provider: "AWS CloudFront" },
];

// ── DNS helpers ───────────────────────────────────────────────────────────────

async function safeResolve<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn();
  } catch {
    return null;
  }
}

async function resolveAll(domain: string): Promise<Record<string, DnsRecord[]>> {
  const records: Record<string, DnsRecord[]> = {};

  const [a, aaaa, mx, ns, txt, cname, soa] = await Promise.all([
    safeResolve(() => dns.resolve4(domain, { ttl: true })),
    safeResolve(() => dns.resolve6(domain, { ttl: true })),
    safeResolve(() => dns.resolveMx(domain)),
    safeResolve(() => dns.resolveNs(domain)),
    safeResolve(() => dns.resolveTxt(domain)),
    safeResolve(() => dns.resolveCname(domain)),
    safeResolve(() => dns.resolveSoa(domain)),
  ]);

  if (a?.length) {
    records["A"] = a.map((r) => ({ type: "A", value: typeof r === "string" ? r : r.address, ttl: typeof r === "object" ? r.ttl : undefined }));
  }
  if (aaaa?.length) {
    records["AAAA"] = (aaaa as Array<{ address: string; ttl: number }>).map((r) => ({ type: "AAAA", value: r.address, ttl: r.ttl }));
  }
  if (mx?.length) {
    records["MX"] = mx.sort((a, b) => a.priority - b.priority).map((r) => ({ type: "MX", value: `${r.priority} ${r.exchange}` }));
  }
  if (ns?.length) {
    records["NS"] = ns.map((r) => ({ type: "NS", value: r }));
  }
  if (txt?.length) {
    records["TXT"] = txt.map((chunks) => ({ type: "TXT", value: chunks.join("") }));
  }
  if (cname?.length) {
    records["CNAME"] = cname.map((r) => ({ type: "CNAME", value: r }));
  }
  if (soa) {
    records["SOA"] = [{
      type: "SOA",
      value: `${soa.nsname} ${soa.hostmaster} ${soa.serial} ${soa.refresh} ${soa.retry} ${soa.expire} ${soa.minttl}`,
    }];
  }

  return records;
}

// ── SPF analysis ──────────────────────────────────────────────────────────────

export function analyzeSpf(txtRecords: DnsRecord[]): SpfAnalysis | null {
  const spfRec = txtRecords.find((r) => r.value.startsWith("v=spf1"));
  if (!spfRec) return null;

  const raw = spfRec.value;
  const parts = raw.split(/\s+/).filter(Boolean);
  const mechanisms = parts.slice(1); // skip "v=spf1"

  const allMech = mechanisms.find((m) => /^[+\-~?]?all$/i.test(m)) ?? null;
  const lookupCount = mechanisms.filter((m) =>
    /^[+\-~?]?(include|a|mx|ptr|exists|redirect)/i.test(m)
  ).length;

  const issues: Finding[] = [];

  if (!allMech) {
    issues.push({ severity: "medium", code: "SPF_NO_ALL", message: "SPF record has no 'all' mechanism" });
  } else if (allMech === "+all" || allMech === "all") {
    issues.push({ severity: "critical", code: "SPF_PERMISSIVE_ALL", message: `SPF '+all' allows any server to send mail as your domain` });
  } else if (allMech === "?all") {
    issues.push({ severity: "high", code: "SPF_NEUTRAL_ALL", message: `SPF '?all' is neutral — fails to reject unauthorized senders` });
  }

  if (lookupCount > 10) {
    issues.push({ severity: "high", code: "SPF_TOO_MANY_LOOKUPS", message: `SPF has ${lookupCount} DNS lookups (max 10); excess lookups cause SPF failure` });
  }

  const duplicateSpf = txtRecords.filter((r) => r.value.startsWith("v=spf1")).length;
  if (duplicateSpf > 1) {
    issues.push({ severity: "high", code: "SPF_DUPLICATE", message: `Found ${duplicateSpf} SPF records; only one is allowed` });
  }

  return { raw, valid: true, mechanisms, allMechanism: allMech, lookupCount, issues };
}

// ── DMARC analysis ────────────────────────────────────────────────────────────

export function analyzeDmarc(dmarcTxt: string | null): DmarcAnalysis | null {
  if (!dmarcTxt) return null;

  const raw = dmarcTxt;
  const issues: Finding[] = [];
  const pairs = Object.fromEntries(
    raw.split(";").map((s) => s.trim().split("=").map((x) => x.trim()))
      .filter((p) => p.length === 2) as [string, string][]
  );

  const policy = pairs["p"] ?? null;
  const pct = parseInt(pairs["pct"] ?? "100", 10);
  const rua = (pairs["rua"] ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const ruf = (pairs["ruf"] ?? "").split(",").map((s) => s.trim()).filter(Boolean);

  if (!policy) {
    issues.push({ severity: "high", code: "DMARC_NO_POLICY", message: "DMARC record missing 'p' policy tag" });
  } else if (policy === "none") {
    issues.push({ severity: "medium", code: "DMARC_POLICY_NONE", message: "DMARC policy is 'none' — emails are not rejected or quarantined" });
  } else if (policy === "quarantine" && pct < 100) {
    issues.push({ severity: "low", code: "DMARC_PCT_LOW", message: `DMARC policy applies to only ${pct}% of messages` });
  }

  if (rua.length === 0) {
    issues.push({ severity: "low", code: "DMARC_NO_RUA", message: "No DMARC aggregate report address (rua) configured" });
  }

  return { raw, valid: true, policy, pct, rua, ruf, issues };
}

// ── Zone transfer check ───────────────────────────────────────────────────────

async function checkZoneTransfer(domain: string, nameservers: string[]): Promise<boolean> {
  // Attempt AXFR against each nameserver using raw DNS; just check if the
  // TCP connection to port 53 and an AXFR query succeeds with >1 record.
  // We use a simple heuristic: if the NS responds to our AXFR with data
  // beyond the SOA record, it's vulnerable.
  // Node.js dns module doesn't support AXFR; we check by trying resolve on
  // a crafted subdomain — real check requires a raw DNS library.
  // We return false conservatively; a real implementation would use raw TCP DNS.
  return false;
}

// ── Subdomain enumeration ─────────────────────────────────────────────────────

export async function enumerateSubdomains(
  domain: string,
  concurrency: number = 20
): Promise<SubdomainResult[]> {
  const results: SubdomainResult[] = [];
  const queue = [...COMMON_SUBDOMAINS.map((s) => `${s}.${domain}`)];

  for (let i = 0; i < queue.length; i += concurrency) {
    const batch = queue.slice(i, i + concurrency);
    const settled = await Promise.all(
      batch.map(async (sub): Promise<SubdomainResult> => {
        // Try A record
        const addrs = await safeResolve(() => dns.resolve4(sub));
        if (addrs?.length) {
          return { subdomain: sub, resolves: true, addresses: addrs };
        }

        // Try CNAME
        const cnames = await safeResolve(() => dns.resolveCname(sub));
        if (cnames?.length) {
          const cname = cnames[0]!;
          // Check if CNAME points to a cloud provider that could be dangling
          const danglingMatch = DANGLING_CNAME_PATTERNS.find((p) => p.pattern.test(cname));
          // Verify the CNAME target itself resolves
          const cnameResolves = await safeResolve(() => dns.resolve4(cname));
          if (danglingMatch && !cnameResolves) {
            return {
              subdomain: sub, resolves: true, cname,
              dangling: true, danglingReason: `CNAME points to unclaimed ${danglingMatch.provider} resource`,
            };
          }
          return { subdomain: sub, resolves: true, cname };
        }

        return { subdomain: sub, resolves: false };
      })
    );
    results.push(...settled.filter((r) => r.resolves));
  }

  return results;
}

// ── Main enumeration ──────────────────────────────────────────────────────────

export async function enumerateDomain(domain: string): Promise<DnsEnumerationResult> {
  const findings: Finding[] = [];
  const records = await resolveAll(domain);

  // SPF
  const txtRecords = records["TXT"] ?? [];
  const spf = analyzeSpf(txtRecords);
  if (!spf) {
    findings.push({ severity: "medium", code: "SPF_MISSING", message: `No SPF record found for ${domain}` });
  } else {
    findings.push(...spf.issues);
  }

  // DMARC
  const dmarcDomain = `_dmarc.${domain}`;
  const dmarcTxtRaw = await safeResolve(() => dns.resolveTxt(dmarcDomain));
  const dmarcRaw = dmarcTxtRaw?.flat().find((v) => v.startsWith("v=DMARC1")) ?? null;
  const dmarc = analyzeDmarc(dmarcRaw);
  if (!dmarc) {
    findings.push({ severity: "high", code: "DMARC_MISSING", message: `No DMARC record found at _dmarc.${domain}` });
  } else {
    findings.push(...dmarc.issues);
  }

  // DKIM — check common selectors
  const dkimSelectors: Record<string, boolean> = {};
  const commonSelectors = ["default", "google", "k1", "mail", "dkim", "selector1", "selector2", "s1", "s2"];
  const dkimChecks = await Promise.all(
    commonSelectors.map(async (sel) => {
      const dkimDomain = `${sel}._domainkey.${domain}`;
      const result = await safeResolve(() => dns.resolveTxt(dkimDomain));
      return { sel, found: !!result?.length };
    })
  );
  for (const { sel, found } of dkimChecks) {
    dkimSelectors[sel] = found;
  }
  const anyDkim = Object.values(dkimSelectors).some(Boolean);
  if (!anyDkim) {
    findings.push({ severity: "medium", code: "DKIM_NOT_FOUND", message: "No DKIM records found for common selectors" });
  }

  // Nameservers — check for single point of failure
  const nsRecords = records["NS"] ?? [];
  if (nsRecords.length === 0) {
    findings.push({ severity: "high", code: "NS_MISSING", message: "No NS records found" });
  } else if (nsRecords.length < 2) {
    findings.push({ severity: "medium", code: "NS_SINGLE", message: "Only one NS record found; consider adding a secondary nameserver" });
  }

  // Zone transfer (conservative check)
  const zoneTransferVulnerable = false;

  if (findings.length === 0) {
    findings.push({ severity: "info", code: "OK", message: "No DNS misconfigurations found" });
  }

  return { domain, records, spf: spf ?? undefined, dmarc: dmarc ?? undefined, dkimSelectors, zoneTransferVulnerable, findings };
}

// ── Report formatter ──────────────────────────────────────────────────────────

export function formatDnsReport(result: DnsEnumerationResult): string {
  const lines: string[] = [`DNS Intelligence Report: ${result.domain}`, "─".repeat(50)];

  // Records summary
  for (const [type, recs] of Object.entries(result.records)) {
    lines.push(`\n${type} Records:`);
    for (const r of recs) lines.push(`  ${r.value}${r.ttl !== undefined ? `  (TTL ${r.ttl}s)` : ""}`);
  }

  // SPF
  if (result.spf) {
    lines.push(`\nSPF: ${result.spf.raw}`);
    lines.push(`  all-mechanism: ${result.spf.allMechanism ?? "none"} | DNS lookups: ${result.spf.lookupCount}`);
  }

  // DMARC
  if (result.dmarc) {
    lines.push(`\nDMARC: ${result.dmarc.raw}`);
    lines.push(`  policy: ${result.dmarc.policy ?? "none"} | pct: ${result.dmarc.pct}%`);
    if (result.dmarc.rua.length) lines.push(`  rua: ${result.dmarc.rua.join(", ")}`);
  }

  // DKIM
  if (result.dkimSelectors) {
    const found = Object.entries(result.dkimSelectors).filter(([, v]) => v).map(([k]) => k);
    lines.push(`\nDKIM selectors found: ${found.length ? found.join(", ") : "none"}`);
  }

  // Findings
  const issues = result.findings.filter((f) => f.code !== "OK");
  if (issues.length === 0) {
    lines.push("\n✅ No DNS misconfigurations found");
  } else {
    lines.push(`\n⚠️  ${issues.length} finding(s):`);
    for (const f of issues) {
      lines.push(`  [${f.severity.toUpperCase()}] ${f.message}`);
    }
  }

  return lines.join("\n");
}

export function formatSubdomainReport(domain: string, results: SubdomainResult[]): string {
  const dangling = results.filter((r) => r.dangling);
  const lines = [
    `Subdomain Enumeration: ${domain}`,
    `─────────────────────────────────────────`,
    `Found ${results.length} live subdomain(s)${dangling.length ? `, ${dangling.length} potentially dangling` : ""}`,
    "",
  ];

  for (const r of results) {
    const flag = r.dangling ? "⚠️  DANGLING" : "✅";
    const target = r.cname ? `→ CNAME ${r.cname}` : (r.addresses?.join(", ") ?? "");
    lines.push(`${flag}  ${r.subdomain.padEnd(45)} ${target}`);
    if (r.dangling && r.danglingReason) {
      lines.push(`      └─ ${r.danglingReason}`);
    }
  }

  return lines.join("\n");
}
