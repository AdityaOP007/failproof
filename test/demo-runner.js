import path from "node:path";
import { evaluateFromCtx } from "../src/failproof-adapter.js";

async function main() {
  const repo = path.resolve("./demo-repo");

  console.log("\n🎬 Running Simulated Agent Demo against ScopeGate Policy...\n");

  // Step 1: Agent tries allowed in-scope edit
  const r1 = await evaluateFromCtx(
    {
      tool: "Edit",
      input: {
        path: "src/auth/login.js",
        content: "export function getRedirectUrl() { return '/dashboard'; }",
      },
    },
    repo
  );
  console.log(`1. Edit src/auth/login.js:       [${r1.decision.toUpperCase()}] (${r1.rule})`);

  // Step 2: Agent runs allowed test
  const r2 = await evaluateFromCtx(
    {
      tool: "Bash",
      input: { command: "npm test" },
    },
    repo
  );
  console.log(`2. Execute command "npm test":    [${r2.decision.toUpperCase()}] (${r2.rule})`);

  // Step 3: Agent tries out-of-scope edit to billing/invoice.js
  const r3 = await evaluateFromCtx(
    {
      tool: "Edit",
      input: {
        path: "billing/invoice.js",
        content: "// modified invoice calculations",
      },
    },
    repo
  );
  console.log(`3. Edit billing/invoice.js:      [${r3.decision.toUpperCase()}] (${r3.rule})`);
  console.log(`   ↳ Denial reason: ${r3.reason}`);

  // Step 4: Agent tries to tamper with .scopegate/contract.json
  const r4 = await evaluateFromCtx(
    {
      tool: "Write",
      input: {
        path: ".scopegate/contract.json",
        content: "{}",
      },
    },
    repo
  );
  console.log(`4. Write .scopegate/contract.json: [${r4.decision.toUpperCase()}] (${r4.rule})`);
  console.log(`   ↳ Denial reason: ${r4.reason}`);

  // Step 5: Agent tries to read .env secret
  const r5 = await evaluateFromCtx(
    {
      tool: "View",
      input: { path: ".env" },
    },
    repo
  );
  console.log(`5. Read .env secrets:             [${r5.decision.toUpperCase()}] (${r5.rule})`);
  console.log(`   ↳ Denial reason: ${r5.reason}`);

  // Step 6: Agent tries to run scopegate widen via shell
  const r6 = await evaluateFromCtx(
    {
      tool: "Bash",
      input: { command: "scopegate widen --write 'billing/**'" },
    },
    repo
  );
  console.log(`6. Shell "scopegate widen":       [${r6.decision.toUpperCase()}] (${r6.rule})`);
  console.log(`   ↳ Denial reason: ${r6.reason}\n`);
}

main().catch(console.error);
