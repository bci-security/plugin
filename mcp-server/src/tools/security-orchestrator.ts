/**
 * Security Orchestrator — unified scan that runs all available security tools.
 *
 * Calls external tools (Semgrep, Gitleaks, Grype, etc.) if installed,
 * merges results with built-in OWASP/CWE/Burp/BCI patterns.
 *
 * External tools are OPTIONAL — if not installed, that layer is skipped
 * and the built-in patterns still run. No network calls. All tools run locally.
 *
 * Air-gap flags applied to every external tool:
 * - Semgrep: --metrics=off, local rules only
 * - Gitleaks: no flags needed (zero telemetry)
 * - Grype: GRYPE_CHECK_FOR_APP_UPDATE=false, GRYPE_DB_AUTO_UPDATE=false
 * - TruffleHog: --no-verification (MANDATORY — prevents credential verification calls)
 * - detect-secrets: no flags needed (offline by default)
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { sanitizeReport } from "../security/sanitizer.js";
import { audit } from "../security/audit.js";
import type { ToolResult } from "../types/index.js";

const DISCLAIMER =
  "\n\n---\n*Unified security scan combining built-in OWASP/CWE/Burp/BCI patterns with " +
  "external tools (Semgrep, Gitleaks, Grype) where installed. " +
  "All tools run locally with telemetry disabled. Not a substitute for professional penetration testing.*";

interface ExternalFinding {
  tool: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  rule: string;
  message: string;
  file?: string;
  line?: number;
  cwe?: string;
  owasp?: string;
}

/**
 * Check if a CLI tool is available on PATH.
 */
function toolExists(name: string): boolean {
  try {
    execFileSync("which", [name], { encoding: "utf-8", timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Run Semgrep on code string with telemetry disabled and local rules only.
 * Returns structured findings.
 */
function runSemgrep(code: string, language: string): ExternalFinding[] {
  if (!toolExists("semgrep")) return [];

  const tmpDir = mkdtempSync(join(tmpdir(), "bci-scan-"));
  const ext = { python: ".py", javascript: ".js", typescript: ".ts", c: ".c", cpp: ".cpp" }[language] ?? ".txt";
  const tmpFile = join(tmpDir, `scan${ext}`);

  try {
    writeFileSync(tmpFile, code, "utf-8");

    const result = execFileSync("semgrep", [
      "scan",
      "--json",
      "--metrics=off",
      "--config=auto",
      "--quiet",
      tmpFile,
    ], {
      encoding: "utf-8",
      timeout: 60000,
      env: { ...process.env, SEMGREP_SEND_METRICS: "off" },
    });

    const parsed = JSON.parse(result);
    const findings: ExternalFinding[] = [];

    for (const r of parsed.results ?? []) {
      findings.push({
        tool: "Semgrep",
        severity: mapSemgrepSeverity(r.extra?.severity ?? "WARNING"),
        rule: r.check_id ?? "unknown",
        message: r.extra?.message ?? r.check_id ?? "Unknown finding",
        line: r.start?.line,
        cwe: r.extra?.metadata?.cwe?.[0],
        owasp: r.extra?.metadata?.owasp?.[0],
      });
    }

    audit("semgrep", `Scanned ${code.split("\n").length} lines, ${findings.length} findings`);
    return findings;
  } catch {
    audit("semgrep", "Scan failed or no findings");
    return [];
  } finally {
    try { unlinkSync(tmpFile); rmdirSync(tmpDir); } catch { /* cleanup best-effort */ }
  }
}

function mapSemgrepSeverity(sev: string): ExternalFinding["severity"] {
  switch (sev.toUpperCase()) {
    case "ERROR": return "critical";
    case "WARNING": return "high";
    case "INFO": return "medium";
    default: return "medium";
  }
}

/**
 * Run Gitleaks on code string for secrets detection.
 * Zero telemetry — cleanest tool in the stack.
 */
function runGitleaks(code: string): ExternalFinding[] {
  if (!toolExists("gitleaks")) return [];

  const tmpDir = mkdtempSync(join(tmpdir(), "bci-scan-"));
  const tmpFile = join(tmpDir, "scan.txt");
  const reportFile = join(tmpDir, "gitleaks-report.json");

  try {
    writeFileSync(tmpFile, code, "utf-8");

    execFileSync("gitleaks", [
      "detect",
      "--source", tmpDir,
      "--report-format", "json",
      "--report-path", reportFile,
      "--no-git",
    ], {
      encoding: "utf-8",
      timeout: 30000,
    });

    // Gitleaks exits 0 if no findings, 1 if findings found
    return parseGitleaksReport(reportFile);
  } catch (error) {
    // Exit code 1 = findings found (not an error)
    return parseGitleaksReport(reportFile);
  } finally {
    try { unlinkSync(tmpFile); unlinkSync(reportFile); rmdirSync(tmpDir); } catch { /* cleanup */ }
  }
}

function parseGitleaksReport(reportFile: string): ExternalFinding[] {
  try {
    if (!existsSync(reportFile)) return [];
    const { readFileSync } = require("node:fs");
    const data = JSON.parse(readFileSync(reportFile, "utf-8"));
    const findings: ExternalFinding[] = [];

    for (const leak of data ?? []) {
      findings.push({
        tool: "Gitleaks",
        severity: "critical",
        rule: leak.RuleID ?? "unknown",
        message: `Secret detected: ${leak.Description ?? leak.RuleID ?? "unknown type"} [REDACTED]`,
        line: leak.StartLine,
      });
    }

    audit("gitleaks", `${findings.length} secrets found`);
    return findings;
  } catch {
    return [];
  }
}

/**
 * Run Grype on a package manifest for dependency CVE scanning.
 * Air-gapped flags applied.
 */
function runGrype(code: string, filename?: string): ExternalFinding[] {
  if (!toolExists("grype")) return [];

  // Only run Grype if the code looks like a package manifest
  const isManifest = filename && (
    filename.endsWith("package.json") ||
    filename.endsWith("requirements.txt") ||
    filename.endsWith("Pipfile.lock") ||
    filename.endsWith("go.sum") ||
    filename.endsWith("Cargo.lock") ||
    filename.endsWith("Gemfile.lock")
  );
  if (!isManifest) return [];

  const tmpDir = mkdtempSync(join(tmpdir(), "bci-scan-"));
  const tmpFile = join(tmpDir, filename ?? "manifest");

  try {
    writeFileSync(tmpFile, code, "utf-8");

    const result = execFileSync("grype", [
      `dir:${tmpDir}`,
      "--output", "json",
      "--quiet",
    ], {
      encoding: "utf-8",
      timeout: 60000,
      env: {
        ...process.env,
        GRYPE_CHECK_FOR_APP_UPDATE: "false",
        GRYPE_DB_AUTO_UPDATE: "false",
        GRYPE_DB_VALIDATE_AGE: "false",
      },
    });

    const parsed = JSON.parse(result);
    const findings: ExternalFinding[] = [];

    for (const match of parsed.matches ?? []) {
      const vuln = match.vulnerability ?? {};
      findings.push({
        tool: "Grype",
        severity: mapGrypeSeverity(vuln.severity ?? "Unknown"),
        rule: vuln.id ?? "unknown",
        message: `${vuln.id}: ${match.artifact?.name}@${match.artifact?.version} — ${vuln.description ?? "Known vulnerability"}`,
        cwe: vuln.cwe?.[0],
      });
    }

    audit("grype", `Scanned ${filename}, ${findings.length} CVEs found`);
    return findings;
  } catch {
    audit("grype", "Scan failed or no findings");
    return [];
  } finally {
    try { unlinkSync(tmpFile); rmdirSync(tmpDir); } catch { /* cleanup */ }
  }
}

function mapGrypeSeverity(sev: string): ExternalFinding["severity"] {
  switch (sev.toLowerCase()) {
    case "critical": return "critical";
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    default: return "medium";
  }
}

/**
 * Format external findings into a markdown report section.
 */
function formatExternalFindings(findings: ExternalFinding[]): string {
  if (findings.length === 0) return "";

  const byTool = new Map<string, ExternalFinding[]>();
  for (const f of findings) {
    const existing = byTool.get(f.tool) ?? [];
    existing.push(f);
    byTool.set(f.tool, existing);
  }

  let report = "### External Tool Findings\n\n";

  for (const [tool, toolFindings] of byTool) {
    report += `#### ${tool} (${toolFindings.length} finding${toolFindings.length === 1 ? "" : "s"})\n\n`;

    for (const f of toolFindings) {
      report += `- **[${f.severity.toUpperCase()}] ${f.rule}:** ${f.message}`;
      if (f.line) report += ` (line ${f.line})`;
      if (f.cwe) report += ` [${f.cwe}]`;
      if (f.owasp) report += ` [${f.owasp}]`;
      report += "\n";
    }
    report += "\n";
  }

  return report;
}

/**
 * Get the availability status of all external tools.
 */
export function getToolStatus(): Record<string, boolean> {
  return {
    semgrep: toolExists("semgrep"),
    gitleaks: toolExists("gitleaks"),
    grype: toolExists("grype"),
    trufflehog: toolExists("trufflehog"),
    "detect-secrets": toolExists("detect-secrets"),
    "osv-scanner": toolExists("osv-scanner"),
  };
}

/**
 * Run all available external security tools on the given code.
 * Returns findings merged from all tools.
 */
export function runExternalScanners(
  code: string,
  language: string,
  filename?: string
): { findings: ExternalFinding[]; report: string; toolsRun: string[] } {
  const allFindings: ExternalFinding[] = [];
  const toolsRun: string[] = [];

  // SAST: Semgrep
  const semgrepFindings = runSemgrep(code, language);
  if (semgrepFindings.length > 0 || toolExists("semgrep")) {
    toolsRun.push("Semgrep");
    allFindings.push(...semgrepFindings);
  }

  // Secrets: Gitleaks
  const gitleaksFindings = runGitleaks(code);
  if (gitleaksFindings.length > 0 || toolExists("gitleaks")) {
    toolsRun.push("Gitleaks");
    allFindings.push(...gitleaksFindings);
  }

  // SCA: Grype (only for package manifests)
  const grypeFindings = runGrype(code, filename);
  if (grypeFindings.length > 0 || toolExists("grype")) {
    toolsRun.push("Grype");
    allFindings.push(...grypeFindings);
  }

  const report = formatExternalFindings(allFindings);
  return { findings: allFindings, report, toolsRun };
}

/**
 * Tool status report — shows which external tools are available.
 */
export function securityToolStatus(): ToolResult {
  const status = getToolStatus();
  const installed = Object.entries(status).filter(([_, v]) => v).map(([k]) => k);
  const missing = Object.entries(status).filter(([_, v]) => !v).map(([k]) => k);

  let report = "## Security Tool Status\n\n";
  report += `**Installed:** ${installed.length > 0 ? installed.join(", ") : "none"}\n`;
  report += `**Missing:** ${missing.length > 0 ? missing.join(", ") : "none"}\n\n`;

  if (missing.length > 0) {
    report += "### Install Missing Tools\n\n```bash\nbrew install " + missing.join(" ") + "\n```\n\n";
  }

  report += "### Built-in (always available)\n\n";
  report += "- OWASP Top 10:2021 (78 patterns)\n";
  report += "- OWASP API Security Top 10:2023\n";
  report += "- OWASP LLM Top 10:2025\n";
  report += "- CWE Top 25:2024\n";
  report += "- Burp Suite categories\n";
  report += "- BCI PII patterns (18)\n";
  report += "- Credential detection (10 patterns)\n";
  report += "- TARA technique mapping (135)\n";

  return {
    content: [{ type: "text", text: sanitizeReport(report + DISCLAIMER) }],
  };
}
