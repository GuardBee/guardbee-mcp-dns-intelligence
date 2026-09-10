import { readFileSync, existsSync } from "fs";
import { resolve, join } from "path";

// ── guardbee.yml schema (dns-intelligence section) ────────────────────────────
//
// dns-intelligence:
//   fail-on: high          # critical | high | medium | low
//   concurrency: 20
//   domains:
//     - example.com
//     - staging.example.com

export interface DnsIntelligenceConfig {
  failOn: string;
  concurrency: number;
  domains: string[];
}

const DEFAULTS: DnsIntelligenceConfig = {
  failOn: "high",
  concurrency: 20,
  domains: [],
};

function findConfigFile(startDir: string): string | null {
  const names = ["guardbee.yml", "guardbee.yaml", ".guardbee.yml"];
  let dir = resolve(startDir);

  for (let i = 0; i < 5; i++) {
    for (const name of names) {
      const p = join(dir, name);
      if (existsSync(p)) return p;
    }
    const parent = resolve(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function parseYaml(content: string): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  let currentSection: string | null = null;
  let currentKey: string | null = null;
  let currentList: string[] | null = null;

  for (const rawLine of content.split("\n")) {
    const line = rawLine.replace(/#.*$/, "");
    if (!line.trim()) continue;

    const indent = line.match(/^(\s*)/)?.[1].length ?? 0;

    if (indent === 0 && line.trim().endsWith(":")) {
      if (currentKey && currentList && currentSection) {
        (root[currentSection] as Record<string, unknown>)[currentKey] = currentList;
        currentList = null;
        currentKey = null;
      }
      currentSection = line.trim().slice(0, -1);
      root[currentSection] = {};
      continue;
    }

    if (indent === 2 && currentSection) {
      if (currentKey && currentList) {
        (root[currentSection] as Record<string, unknown>)[currentKey] = currentList;
        currentList = null;
        currentKey = null;
      }
      const colonIdx = line.indexOf(":");
      if (colonIdx === -1) continue;
      const key = line.slice(0, colonIdx).trim();
      const value = line.slice(colonIdx + 1).trim();
      if (value === "") {
        currentKey = key;
        currentList = [];
      } else {
        (root[currentSection] as Record<string, unknown>)[key] = value;
      }
      continue;
    }

    if (indent === 4 && currentList !== null) {
      const item = line.trim().replace(/^-\s*/, "").replace(/^['"]|['"]$/g, "");
      currentList.push(item);
      continue;
    }
  }

  if (currentKey && currentList && currentSection) {
    (root[currentSection] as Record<string, unknown>)[currentKey] = currentList;
  }

  return root;
}

export function loadConfig(searchDir: string, cliOverrides: Partial<DnsIntelligenceConfig> = {}): DnsIntelligenceConfig {
  const configPath = findConfigFile(searchDir);
  if (!configPath) return { ...DEFAULTS, ...cliOverrides };

  let fileConfig: Partial<DnsIntelligenceConfig> = {};
  try {
    const raw = readFileSync(configPath, "utf8");
    const parsed = parseYaml(raw);
    const section = parsed["dns-intelligence"] as Record<string, unknown> | undefined;
    if (section) {
      if (typeof section["fail-on"] === "string") fileConfig.failOn = section["fail-on"];
      if (typeof section["concurrency"] === "string") fileConfig.concurrency = parseInt(section["concurrency"], 10);
      if (Array.isArray(section["domains"])) fileConfig.domains = section["domains"] as string[];
    }
  } catch {
    // ignore parse errors, use defaults
  }

  return { ...DEFAULTS, ...fileConfig, ...cliOverrides };
}

export function configFilePath(searchDir: string): string | null {
  return findConfigFile(searchDir);
}
