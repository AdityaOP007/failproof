import path from "node:path";
import fs from "node:fs";
import { CONTRACT_DIR, EVENTS_FILE } from "./contract.js";

/**
 * Append an event to .scopegate/events.jsonl.
 * Security rule: Never log file contents or secret values.
 *
 * @param {string} repoRoot
 * @param {{ tool: string, summary: string, decision: "allow"|"deny"|"warn", rule: string }} event
 */
export function logEvent(repoRoot, event) {
  try {
    if (!repoRoot || typeof repoRoot !== "string") return;

    const dir = path.resolve(repoRoot, CONTRACT_DIR);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const eventsPath = path.resolve(repoRoot, EVENTS_FILE);
    const summary = (event.summary || "")
      .replace(/[\r\n]+/g, " ")
      .slice(0, 200);

    const record = {
      ts: new Date().toISOString(),
      tool: String(event.tool || "unknown"),
      summary,
      decision: event.decision || "deny",
      rule: event.rule || "unknown",
    };

    fs.appendFileSync(eventsPath, JSON.stringify(record) + "\n", "utf8");
  } catch (err) {
    // Logging errors should not crash the host harness
    console.error(`[ScopeGate log error] ${err.message}`);
  }
}

/**
 * Read all events from .scopegate/events.jsonl.
 *
 * @param {string} repoRoot
 * @returns {Array<{ ts: string, tool: string, summary: string, decision: string, rule: string }>}
 */
export function readEvents(repoRoot) {
  try {
    const eventsPath = path.resolve(repoRoot, EVENTS_FILE);
    if (!fs.existsSync(eventsPath)) {
      return [];
    }
    const lines = fs.readFileSync(eventsPath, "utf8").split("\n");
    const events = [];
    for (const line of lines) {
      if (line.trim()) {
        try {
          events.push(JSON.parse(line.trim()));
        } catch {
          // ignore malformed lines
        }
      }
    }
    return events;
  } catch {
    return [];
  }
}
