import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  enumerateDomain,
  enumerateSubdomains,
  formatDnsReport,
  formatSubdomainReport,
} from "./dns.js";
import * as dns from "dns/promises";

export async function startServer() {
  const server = new McpServer({
    name: "guardbee-dns-intelligence",
    version: "0.1.0",
  });

  server.tool(
    "enumerate_dns",
    "Enumerate all DNS records for a domain and detect SPF, DMARC, DKIM misconfigurations",
    {
      domain: z.string().describe("Domain to enumerate (e.g. example.com)"),
    },
    async ({ domain }) => {
      const start = Date.now();
      const result = await enumerateDomain(domain.toLowerCase().trim());
      const report = formatDnsReport(result);
      return { content: [{ type: "text", text: `${report}\n\nCompleted in ${Date.now() - start}ms` }] };
    }
  );

  server.tool(
    "enumerate_subdomains",
    "Enumerate common subdomains for a domain and detect dangling subdomain takeover candidates",
    {
      domain: z.string().describe("Root domain to enumerate subdomains for (e.g. example.com)"),
    },
    async ({ domain }) => {
      const start = Date.now();
      const results = await enumerateSubdomains(domain.toLowerCase().trim());
      const report = formatSubdomainReport(domain, results);
      return { content: [{ type: "text", text: `${report}\n\nCompleted in ${Date.now() - start}ms` }] };
    }
  );

  server.tool(
    "check_email_security",
    "Check SPF, DMARC, and DKIM configuration for a domain and get actionable remediation advice",
    {
      domain: z.string().describe("Domain to check email security for"),
      dkimSelectors: z
        .array(z.string())
        .optional()
        .describe("Additional DKIM selectors to check (default: common selectors)"),
    },
    async ({ domain, dkimSelectors: extraSelectors }) => {
      const start = Date.now();
      const result = await enumerateDomain(domain.toLowerCase().trim());

      const lines: string[] = [`Email Security Check: ${domain}`, "─".repeat(50)];

      // SPF
      lines.push("\n── SPF ─────────────────────────────────────────");
      if (!result.spf) {
        lines.push("✗ No SPF record found");
        lines.push("  Add:  v=spf1 include:<your-mail-provider> -all");
      } else {
        lines.push(`✓ ${result.spf.raw}`);
        for (const f of result.spf.issues) lines.push(`  [${f.severity.toUpperCase()}] ${f.message}`);
      }

      // DMARC
      lines.push("\n── DMARC ───────────────────────────────────────");
      if (!result.dmarc) {
        lines.push("✗ No DMARC record found at _dmarc." + domain);
        lines.push("  Add:  v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain);
      } else {
        lines.push(`✓ ${result.dmarc.raw}`);
        for (const f of result.dmarc.issues) lines.push(`  [${f.severity.toUpperCase()}] ${f.message}`);
      }

      // DKIM
      lines.push("\n── DKIM ────────────────────────────────────────");
      const foundDkim = Object.entries(result.dkimSelectors ?? {})
        .filter(([, found]) => found)
        .map(([sel]) => sel);

      if (extraSelectors?.length) {
        const extraChecks = await Promise.all(
          extraSelectors.map(async (sel) => {
            try {
              const txt = await dns.resolveTxt(`${sel}._domainkey.${domain}`);
              return txt.length ? sel : null;
            } catch {
              return null;
            }
          })
        );
        foundDkim.push(...extraChecks.filter((s): s is string => s !== null));
      }

      if (foundDkim.length === 0) {
        lines.push("✗ No DKIM records found");
        lines.push("  Configure DKIM signing with your mail provider and publish the public key");
      } else {
        lines.push(`✓ Found DKIM selectors: ${foundDkim.join(", ")}`);
      }

      const totalIssues = (result.spf?.issues.length ?? 0) + (result.dmarc?.issues.length ?? 0);
      lines.push(`\n${totalIssues === 0 ? "✅ Email security looks good!" : `⚠️  ${totalIssues} issue(s) need attention`}`);
      lines.push(`\nCompleted in ${Date.now() - start}ms`);

      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  server.tool(
    "lookup_dns",
    "Perform a targeted DNS lookup for specific record types on a domain",
    {
      domain: z.string().describe("Domain to query"),
      type: z
        .enum(["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"])
        .describe("DNS record type to look up"),
    },
    async ({ domain, type }) => {
      try {
        let result: string;
        switch (type) {
          case "A": {
            const recs = await dns.resolve4(domain, { ttl: true });
            result = recs.map((r) => `${r.address}  (TTL ${r.ttl}s)`).join("\n");
            break;
          }
          case "AAAA": {
            const recs = await dns.resolve6(domain, { ttl: true }) as Array<{ address: string; ttl: number }>;
            result = recs.map((r) => `${r.address}  (TTL ${r.ttl}s)`).join("\n");
            break;
          }
          case "MX": {
            const recs = await dns.resolveMx(domain);
            result = recs.sort((a, b) => a.priority - b.priority).map((r) => `${r.priority} ${r.exchange}`).join("\n");
            break;
          }
          case "NS": {
            const recs = await dns.resolveNs(domain);
            result = recs.join("\n");
            break;
          }
          case "TXT": {
            const recs = await dns.resolveTxt(domain);
            result = recs.map((chunks) => `"${chunks.join("")}"`).join("\n");
            break;
          }
          case "CNAME": {
            const recs = await dns.resolveCname(domain);
            result = recs.join("\n");
            break;
          }
          case "SOA": {
            const soa = await dns.resolveSoa(domain);
            result = `nsname: ${soa.nsname}\nhostmaster: ${soa.hostmaster}\nserial: ${soa.serial}\nrefresh: ${soa.refresh}\nretry: ${soa.retry}\nexpire: ${soa.expire}\nminttl: ${soa.minttl}`;
            break;
          }
        }
        return { content: [{ type: "text", text: `${type} records for ${domain}:\n${result}` }] };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: "text", text: `No ${type} records found for ${domain}: ${msg}` }] };
      }
    }
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
