import { evaluateFromCtx } from "../../src/failproof-adapter.js";

/**
 * Failproof AI Custom Policy: ScopeGate
 *
 * Intercepts tool calls before execution (PreToolUse) and evaluates them against
 * the active .scopegate/contract.json task contract.
 */
let failproofModule;
try {
  failproofModule = await import("failproofai");
} catch {
  // Graceful fallback for standalone / test environments
  failproofModule = {
    customPolicies: {
      add: (policy) => {
        // Registered policy
        if (process.env.DEBUG_SCOPE) {
          console.log(`[ScopeGate] Registered policy: ${policy.name}`);
        }
      },
    },
    deny: (reason) => ({ action: "deny", reason }),
    allow: () => ({ action: "allow" }),
  };
}

const { customPolicies, deny, allow } = failproofModule;

export const policyDefinition = {
  name: "scopegate",
  description: "Task-scoped dynamic least-privilege boundary for AI coding agents",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    const d = await evaluateFromCtx(ctx);
    if (d.decision === "deny") {
      return deny(d.reason);
    }
    return allow();
  },
};

if (customPolicies && typeof customPolicies.add === "function") {
  customPolicies.add(policyDefinition);
}

export default policyDefinition;
