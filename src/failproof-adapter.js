import path from "node:path";
import { loadContract } from "./contract.js";
import { evaluate } from "./evaluate.js";
import { logEvent } from "./log.js";

/**
 * Adapter that connects a Failproof AI policy hook context to ScopeGate's pure evaluation engine.
 *
 * @param {object} ctx - Failproof PreToolUse context
 * @param {string} [overrideRepoRoot] - Optional override for repoRoot
 * @returns {Promise<{ decision: "allow" | "deny" | "warn", rule: string, reason: string, summary?: string }>}
 */
export async function evaluateFromCtx(ctx, overrideRepoRoot) {
  let repoRoot = overrideRepoRoot || (ctx && (ctx.repoRoot || ctx.cwd || ctx.workspace)) || process.env.SCOPE_REPO_ROOT || process.cwd();
  repoRoot = path.resolve(repoRoot);

  try {
    const contractResult = loadContract(repoRoot);

    // Inert: no contract file exists
    if (contractResult.status === "inert") {
      return {
        decision: "allow",
        rule: "contract.inert",
        reason: "ScopeGate is inert (no contract found).",
        summary: "Inert: no contract",
      };
    }

    // Invalid / corrupt contract: fail closed
    if (contractResult.status === "invalid") {
      const errReason = `ScopeGate: Contract in ${repoRoot} is corrupt or unreadable: ${contractResult.error}`;
      logEvent(repoRoot, {
        tool: (ctx && (ctx.tool || ctx.tool_name)) || "unknown",
        summary: "Contract corrupt",
        decision: "deny",
        rule: "contract.invalid",
      });
      return {
        decision: "deny",
        rule: "contract.invalid",
        reason: errReason,
        summary: "Contract corrupt",
      };
    }

    // Map harness ctx to ScopeGate call shape
    const tool = (ctx && (ctx.tool || ctx.tool_name || ctx.name || ctx.toolName)) || "";
    const input = (ctx && (ctx.input || ctx.tool_input || ctx.parameters || ctx.args)) || {};

    const decision = evaluate(contractResult.contract, { tool, input });

    // Log the decision event
    logEvent(repoRoot, {
      tool,
      summary: decision.summary || `${tool} invocation`,
      decision: decision.decision,
      rule: decision.rule,
    });

    return decision;
  } catch (err) {
    // Fail closed on unhandled internal error
    const errReason = `ScopeGate internal error: ${err.message}`;
    logEvent(repoRoot, {
      tool: (ctx && (ctx.tool || ctx.tool_name)) || "unknown",
      summary: `Internal error: ${err.message}`,
      decision: "deny",
      rule: "scopegate.internal-error",
    });
    return {
      decision: "deny",
      rule: "scopegate.internal-error",
      reason: errReason,
      summary: "Internal error",
    };
  }
}
