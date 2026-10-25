import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { evaluate } from "../src/evaluate.js";
import { resolvePath } from "../src/paths.js";
import { validateContract } from "../src/contract.js";

const DEMO_ROOT = path.resolve("./demo-repo");

const mockContract = {
  task: "Fix login redirect bug",
  repoRoot: DEMO_ROOT,
  base: "abc1234",
  write: ["src/auth/**", "test/auth/**"],
  readDeny: [".env*", "**/*.pem", "**/id_rsa*"],
  commands: {
    allow: ["npm test", "git status", "git diff"],
    deny: ["git push", "npm publish", "curl", "wget", "ssh", "sudo", "rm -rf"],
  },
  mode: "enforce",
};

test("Module 2: Path Traversal and Escape Checks", () => {
  // Within repo
  const valid = resolvePath("src/auth/login.js", DEMO_ROOT);
  assert.equal(valid.isEscape, false);
  assert.equal(valid.relative, "src/auth/login.js");

  // Traversal outside repo
  const escape1 = resolvePath("../../etc/passwd", DEMO_ROOT);
  assert.equal(escape1.isEscape, true);

  // Subpath traversal inside repo
  const traversalWithin = resolvePath("src/auth/../auth/login.js", DEMO_ROOT);
  assert.equal(traversalWithin.isEscape, false);
  assert.equal(traversalWithin.relative, "src/auth/login.js");

  // Subpath traversal escaping repo
  const traversalOut = resolvePath("src/auth/../../../../sensitive.txt", DEMO_ROOT);
  assert.equal(traversalOut.isEscape, true);
});

test("Module 2: Contract Validation", () => {
  const res = validateContract(mockContract);
  assert.equal(res.valid, true);
  assert.ok(res.contract.readDeny.includes(".env*"));
  assert.ok(res.contract.commands.deny.includes("git push"));

  // Invalid contract
  const invalid = validateContract({ task: "" });
  assert.equal(invalid.valid, false);
  assert.ok(invalid.errors.length > 0);
});

test("Module 4: In-scope write is allowed", () => {
  const result = evaluate(mockContract, {
    tool: "Edit",
    input: { path: "src/auth/login.js", content: "fixed" },
  });
  assert.equal(result.decision, "allow");
  assert.equal(result.rule, "write.in-scope");
});

test("Module 4: Out-of-scope write is denied with helpful prompt", () => {
  const result = evaluate(mockContract, {
    tool: "Edit",
    input: { path: "billing/invoice.js", content: "tamper" },
  });
  assert.equal(result.decision, "deny");
  assert.equal(result.rule, "write.out-of-scope");
  assert.ok(result.reason.includes("billing/invoice.js is outside this task's scope"));
  assert.ok(result.reason.includes("scopegate widen --write billing/**"));
});

test("Module 4: Protected ScopeGate and Failproof files can never be written", () => {
  const result1 = evaluate(mockContract, {
    tool: "Write",
    input: { path: ".scopegate/contract.json", content: "{}" },
  });
  assert.equal(result1.decision, "deny");
  assert.equal(result1.rule, "write.protected");

  const result2 = evaluate(mockContract, {
    tool: "Write",
    input: { path: ".failproofai/policies/scopegate.js", content: "" },
  });
  assert.equal(result2.decision, "deny");
  assert.equal(result2.rule, "write.protected");
});

test("Module 4: Reading secrets (.env) is denied", () => {
  const result = evaluate(mockContract, {
    tool: "View",
    input: { path: ".env" },
  });
  assert.equal(result.decision, "deny");
  assert.equal(result.rule, "read.denied");
});

test("Module 4: Reading normal files is allowed", () => {
  const result = evaluate(mockContract, {
    tool: "View",
    input: { path: "src/auth/login.js" },
  });
  assert.equal(result.decision, "allow");
  assert.equal(result.rule, "read.allowed");
});

test("Module 3 & 4: Allowed shell command passes", () => {
  const result = evaluate(mockContract, {
    tool: "Bash",
    input: { command: "npm test" },
  });
  assert.equal(result.decision, "allow");
  assert.equal(result.rule, "shell.allowed");
});

test("Module 3 & 4: Denied shell command is blocked", () => {
  const result = evaluate(mockContract, {
    tool: "Bash",
    input: { command: "git push origin main" },
  });
  assert.equal(result.decision, "deny");
  assert.equal(result.rule, "shell.denied");
});

test("Module 3 & 4: Compound command bypass (npm test && rm -rf billing) is blocked", () => {
  const result = evaluate(mockContract, {
    tool: "Bash",
    input: { command: "npm test && rm -rf billing" },
  });
  assert.equal(result.decision, "deny");
  assert.equal(result.rule, "shell.denied");
});

test("Module 3 & 4: Subshell and backticks are denied as unparseable", () => {
  const res1 = evaluate(mockContract, {
    tool: "Bash",
    input: { command: "$(echo rm) -rf billing" },
  });
  assert.equal(res1.decision, "deny");
  assert.equal(res1.rule, "shell.unparseable");

  const res2 = evaluate(mockContract, {
    tool: "Bash",
    input: { command: "`rm -rf billing`" },
  });
  assert.equal(res2.decision, "deny");
  assert.equal(res2.rule, "shell.unparseable");
});

test("Module 3 & 4: Shell redirection to out-of-scope file is denied", () => {
  const result = evaluate(mockContract, {
    tool: "Bash",
    input: { command: "npm test > billing/invoice.js" },
  });
  assert.equal(result.decision, "deny");
  assert.equal(result.rule, "write.out-of-scope");
});

test("Module 3 & 4: Shell redirection escaping repo is denied", () => {
  const result = evaluate(mockContract, {
    tool: "Bash",
    input: { command: "npm test > ../out.txt" },
  });
  assert.equal(result.decision, "deny");
  assert.equal(result.rule, "write.out-of-scope");
});

test("Module 3 & 4: ScopeGate tampering via CLI is denied", () => {
  const result = evaluate(mockContract, {
    tool: "Bash",
    input: { command: "scopegate widen --write 'billing/**'" },
  });
  assert.equal(result.decision, "deny");
  assert.equal(result.rule, "shell.scopegate-tamper");
});

test("Module 4: Inert when no contract", () => {
  const result = evaluate(null, {
    tool: "Edit",
    input: { path: "billing/invoice.js" },
  });
  assert.equal(result.decision, "allow");
  assert.equal(result.rule, "contract.inert");
});
