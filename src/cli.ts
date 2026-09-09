#!/usr/bin/env node
import { startServer } from "./server.js";
import { enumerateDomain, enumerateSubdomains, formatDnsReport, formatSubdomainReport } from "./dns.js";
import type { Finding } from "./dns.js";
import { buildSarif } from "./sarif.js";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
function getVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(resolve(__dirname, "../package.json"), "utf8")) as { version: string };
    return pkg.version;
  } catch { return "0.0.0"; }
}

// ── Severity helpers ───────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function meetsThreshold(sev: string, threshold: string): boolean {
  return (SEVERITY_RANK[sev] ?? 4) <= (SEVERITY_RANK[threshold] ?? 1);
}

function hasFailingFindings(findings: Finding[], failOn: string): boolean {
  return findings.some((f) => meetsThreshold(f.severity, failOn));
}

// ── Arg parsing ────────────────────────────────────────────────────────────────

function parseArgs(args: string[]): { positionals: string[]; failOn: string; format: string; concurrency: number } {
  const positionals: string[] = [];
  let failOn = "high";
  let format = "text";
  let concurrency = 20;

  for (const arg of args) {
    if (arg.startsWith("--fail-on=")) failOn = arg.split("=")[1] ?? "high";
    else if (arg.startsWith("--format=")) format = arg.split("=")[1] ?? "text";
    else if (arg.startsWith("--concurrency=")) concurrency = parseInt(arg.split("=")[1] ?? "20", 10);
    else if (!arg.startsWith("--")) positionals.push(arg);
  }

  return { positionals, failOn, format, concurrency };
}

// ── CLI commands ───────────────────────────────────────────────────────────────

async function runCheck(rawArgs: string[]): Promise<void> {
  const { positionals, failOn, format } = parseArgs(rawArgs);
  const domain = positionals[0];

  if (!domain) {
    console.error("Usage: guardbee-dns-intelligence check <domain> [--fail-on=high] [--format=text|json]");
    process.exit(2);
  }

  const result = await enumerateDomain(domain);

  if (format === "json") {
    console.log(JSON.stringify(result, null, 2));
  } else if (format === "sarif") {
    console.log(JSON.stringify(buildSarif(getVersion(), domain, result.findings), null, 2));
  } else {
    console.log(formatDnsReport(result));
  }

  process.exit(hasFailingFindings(result.findings, failOn) ? 1 : 0);
}

async function runSubdomains(rawArgs: string[]): Promise<void> {
  const { positionals, format, concurrency } = parseArgs(rawArgs);
  const domain = positionals[0];

  if (!domain) {
    console.error("Usage: guardbee-dns-intelligence subdomains <domain> [--format=text|json] [--concurrency=20]");
    process.exit(2);
  }

  const results = await enumerateSubdomains(domain, concurrency);
  const dangling = results.filter((r) => r.dangling);

  if (format === "json") {
    console.log(JSON.stringify({ domain, total: results.length, dangling: dangling.length, results }, null, 2));
  } else {
    console.log(formatSubdomainReport(domain, results));
  }

  process.exit(dangling.length > 0 ? 1 : 0);
}

function printHelp(): void {
  console.log(`@guardbee/mcp-dns-intelligence

Usage (MCP server):
  guardbee-dns-intelligence [serve]

Usage (CLI):
  guardbee-dns-intelligence check <domain>       Full DNS check (records + SPF/DMARC/DKIM)
  guardbee-dns-intelligence subdomains <domain>  Enumerate subdomains, detect dangling CNAMEs

Options:
  --fail-on=<level>     Exit 1 if findings at this severity or above (default: high)
                        Levels: critical | high | medium | low
  --format=<fmt>        Output format: text (default) | json
  --concurrency=<n>     Parallel subdomain probes (default: 20, subdomains only)

Exit codes:
  0  No issues at or above --fail-on threshold (check) / no dangling subdomains (subdomains)
  1  Issues found (check) or dangling subdomains detected (subdomains)
  2  Error / bad arguments

Examples:
  guardbee-dns-intelligence check example.com
  guardbee-dns-intelligence check example.com --fail-on=medium --format=json
  guardbee-dns-intelligence subdomains example.com --concurrency=50
`);
}

// ── Entry point ────────────────────────────────────────────────────────────────

const [, , firstArg, ...rest] = process.argv;

if (!firstArg || firstArg === "serve") {
  startServer().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  });
} else if (firstArg === "--help" || firstArg === "-h") {
  printHelp();
  process.exit(0);
} else if (firstArg === "check") {
  runCheck(rest).catch((err) => {
    console.error("Error:", (err as Error).message);
    process.exit(2);
  });
} else if (firstArg === "subdomains") {
  runSubdomains(rest).catch((err) => {
    console.error("Error:", (err as Error).message);
    process.exit(2);
  });
} else {
  console.error(`Unknown command: ${firstArg}`);
  console.error("Run with --help for usage.");
  process.exit(2);
}
