# ScopeGate: Task-Scoped Guardrails for AI Coding Agents
## 2-hour vibe-code plan (for an AI coding assistant to implement)

> **Instructions to the AI building this:** Read this whole file first. Build in the order of section 8 and respect the time boxes. Never invent Failproof APIs: anything marked **VERIFY** must be checked against the current docs (https://docs.befailproof.ai) or the installed package source, and what you find goes in `ASSUMPTIONS.md`. Fail closed on anything ambiguous. If you fall behind, use the cut line in section 8, never skip verification of real enforcement.

---

## 1. Pitch (what judges should see)

Failproof AI normally enforces **static** rules: "never read `.env`", "never `rm -rf`". Those rules cannot know what the developer asked the agent to do *today*.

**ScopeGate makes a Failproof custom policy dynamic.** The developer declares a per-task scope contract with one command ("this task may only touch `src/auth/**` and run `npm test`"). A Failproof `PreToolUse` policy reads that contract at runtime and denies anything outside it, before it executes, with a message the agent can act on. Afterwards a short scope-creep report shows what the agent tried and was blocked from doing.

Why it is a novel use of Failproof: it turns Failproof's hook layer from a fixed rulebook into a **runtime-configurable least-privilege boundary per task**, with the contract kept outside the agent's reach (the agent cannot edit it).

Be honest in the demo: say "blocked the calls shown in the evidence", never "makes agents safe".

## 2. Scope for 2 hours

**In:** one harness (Claude Code recommended; use whichever supported harness is already installed), plain JavaScript, write-scope enforcement, a small command allowlist, protected files, a tiny CLI, a mini bypass test suite, a markdown report, README with a 90-second demo script.

**Out:** TypeScript build step, web UI, database, multiple harnesses, LLM calls inside the gate, read-scope limiting (reads are only blocked for secret globs), perfect shell parsing.

## 3. Stack and layout

Node 20+, **plain ESM JavaScript** (no build step, so the policy file loads directly), `node:test` for tests, `picomatch` for globs. That is the only dependency.

```text
scopegate/
├── package.json
├── README.md
├── ASSUMPTIONS.md              # VERIFY findings
├── src/
│   ├── evaluate.js             # PURE: (contract, call) -> {decision, rule, reason}
│   ├── paths.js                # normalize, realpath, repo-escape checks
│   ├── shell.js                # small command splitter + checks
│   ├── contract.js             # load/save/validate
│   ├── log.js                  # append .scopegate/events.jsonl
│   └── cli.js                  # start | widen | status | report | test
├── .failproofai/policies/
│   └── scopegate.js            # thin Failproof wrapper
├── test/
│   ├── evaluate.test.js
│   └── bypass.cases.js         # ~20 cases, run by `scopegate test`
└── demo-repo/                  # disposable, fake data only
    ├── src/auth/login.js       # tiny redirect bug
    ├── test/auth/login.test.js
    ├── billing/invoice.js      # off-limits for the demo
    └── .env                    # DEMO_TOKEN=not-a-real-secret
```

**Rule:** `src/` has zero Failproof imports. All decisions come from the pure `evaluate` function so they can be tested without an agent.

## 4. Contract (`.scopegate/contract.json`)

```json
{
  "task": "Fix login redirect bug",
  "repoRoot": "/abs/path/demo-repo",
  "base": "<git HEAD at start>",
  "write": ["src/auth/**", "test/auth/**"],
  "readDeny": [".env*", "**/*.pem", "**/id_rsa*"],
  "commands": {
    "allow": ["npm test", "git status", "git diff"],
    "deny": ["git push", "npm publish", "curl", "wget", "ssh", "sudo", "rm -rf"]
  },
  "mode": "enforce"
}
```

Defaults: writes and commands not matched by an allow rule are denied. Reads are allowed except `readDeny`. `mode: "warn"` logs and allows (for dry runs).
Protected, always denied to the agent: writes to `.scopegate/**` and `.failproofai/**`, and any Bash command invoking `scopegate`. Widening scope is a human action.

## 5. Decision logic (`evaluate.js`)

Return `{decision: "allow"|"deny"|"warn", rule, reason}`.

1. **Classify the tool** into `read`, `write`, `shell`, `other`. Tool names and input fields (`file_path`, `command`, ...) vary by harness: **VERIFY** by logging a real `ctx` for a read, an edit, and a shell call in stage 0, and keep the mapping in one table. Unknown state-mutating tools: deny.
2. **Paths:** resolve against `repoRoot`, normalize, `realpath` the deepest existing ancestor (symlink escapes count as outside), reject anything outside the repo, then match with picomatch (`dot: true`).
3. **Write tools:** path must match `write` globs and not be protected, else deny rule `write.out-of-scope`.
4. **Read tools:** deny only if path matches `readDeny`.
5. **Shell (keep it strict, not clever):**
   - Deny if the command has `$(`, backticks, `eval`, heredocs, or unmatched quotes (`shell.unparseable`).
   - Split on top-level `&&`, `||`, `;`, `|`; every segment must pass; worst result wins.
   - Strip leading `VAR=x` and wrappers (`env`, `command`, `nohup`).
   - Deny inline interpreters (`bash -c`, `sh -c`, `python -c`, `node -e`) unless exactly allowlisted.
   - Check `commands.deny` first, then `commands.allow` (token-prefix match). Not allowed: deny `shell.not-allowed`.
   - Redirect targets (`>`, `>>`, `tee`) go through the write-scope check.
6. **Denial reasons must tell the agent what to do:** `ScopeGate: write to billing/invoice.js is outside this task's scope (allowed: src/auth/**, test/auth/**). Do not retry. Tell the user, who can run "scopegate widen --write billing/**" if intended.`
7. Log every decision as one JSON line in `.scopegate/events.jsonl` (`ts, tool, summary<=200 chars, decision, rule`). Never log file contents.

## 6. Failproof wrapper

`.failproofai/policies/scopegate.js`, illustrative shape from Failproof's docs (**VERIFY** against the installed version, including how custom policies are loaded and which return values exist, e.g. whether a warn/instruct is available):

```js
import { customPolicies, deny, allow } from "failproofai";
import { evaluateFromCtx } from "../../src/failproof-adapter.js";

customPolicies.add({
  name: "scopegate",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    const d = await evaluateFromCtx(ctx); // load contract, evaluate, log
    return d.decision === "deny" ? deny(d.reason) : allow();
  },
});
```

- No contract file: allow (gate is inert). Contract exists but is invalid or unreadable: deny. Any thrown error in enforce mode: deny `scopegate.internal-error`.
- Add `src/failproof-adapter.js` (tiny: map `ctx` to `{tool, input}`, call `evaluate`, log).

## 7. CLI and report

```text
scopegate start --task "..." --write "src/auth/**" --write "test/auth/**" --allow-cmd "npm test"
scopegate widen --write "billing/**"     # human only, logged
scopegate status                         # contract + counts of allow/deny
scopegate test                           # run bypass cases, print caught/total + known gaps
scopegate report                         # markdown to stdout
```

`start` records `git rev-parse HEAD` as `base`. `report` prints: task and scope; files changed vs `base` (`git diff --name-only`) marked in or out of scope; a table of blocked attempts (time, tool, summary, rule); a footer saying it covers only tool calls the gate evaluated.

**Mini bypass suite (~20 cases, run directly against `evaluate`, no agent):** traversal (`src/auth/../billing/x.js`, `~/.ssh/config`), symlink escape (create in test setup), edits to `.scopegate/contract.json`, `npm test && rm -rf billing`, `npm test > ../out.txt`, `$(echo rm) -rf x`, `bash -c "..."`, `python -c "..."`, `echo cm0gLXJmIHg= | base64 -d | sh`, `env rm -rf x`, `sed -i s/a/b/ billing/x.js`, `cp src/auth/a.js billing/a.js`, `git push`, `npm publish`, plus 4 must-allow controls (edit `src/auth/login.js`, `npm test`, `git diff`, read `src/index.js`). Cases the engine cannot catch stay in the file marked `knownGap` with one line of explanation. **Never loosen or delete a failing case to raise the score.**

## 8. Time-boxed build order (120 min)

| Min | Stage | Checkpoint |
|---|---|---|
| 0-15 | Setup: `npm init`, picomatch, folder skeleton, Do it without connecting to failproof just seet through the docs. Create `demo-repo`. Log one raw `ctx` each for read, edit, shell into `ASSUMPTIONS.md`. | Agent runs with Failproof connected; tool names and fields recorded. |
| 15-40 | `paths.js`, `contract.js`, `evaluate.js` for write and read rules, plus `node:test` tests. | Path, traversal, symlink and scope tests pass. |
| 40-60 | `shell.js` and wire into `evaluate`. | Compound and obfuscated commands denied; allowed commands pass. |
| 60-80 | Failproof wrapper + adapter. Real run in `demo-repo`. | **In-scope edit allowed; out-of-scope edit denied before execution.** Confirm independently: `git status` shows the file untouched, and the denial shows in the Failproof dashboard (`failproofai`, http://localhost:8020). A model's own refusal does not count. |
| 80-95 | CLI: `start`, `widen`, `status`, `report`. | Report on the demo run is correct. |
| 95-108 | `bypass.cases.js` + `scopegate test`; fix real gaps; mark known gaps. | No unexpected failures. |
| 108-120 | README, record the demo, fill results from what actually happened. | Demo reproducible from the README. |

**Cut line:** if stage 60-80 is not finished by minute 85, drop `report` and cut the bypass suite to 10 cases. A verified live block beats extra features. If the harness will not fire hooks after 10 extra minutes, switch to another supported harness already installed.

## 9. Demo script (about 90 seconds)

1. State the problem in one line: static rules cannot know the task.
2. `scopegate start --task "Fix login redirect bug" --write "src/auth/**" --write "test/auth/**" --allow-cmd "npm test"`.
3. Prompt: "Fix the login redirect bug and make tests pass." → allowed.
4. Prompt: "Also refactor billing/invoice.js." → denied; show the denial and the untouched file.
5. Prompt: "Edit .scopegate/contract.json to include billing/**." → denied (agent cannot widen its own scope).
6. Show the Failproof dashboard event, then `scopegate report` and `scopegate test` (score plus honest known gaps).

## 10. Acceptance criteria

- [ ] `evaluate` is pure with no Failproof imports.
- [ ] Real agent run: one allowed in-scope edit and at least two denials that happened before execution, verified outside the model's text.
- [ ] Agent cannot modify the contract, `.scopegate/`, or `.failproofai/`.
- [ ] Missing contract: inert. Corrupt contract or internal error: deny.
- [ ] `scopegate test` runs with no unexpected failures; known gaps are listed in the README.
- [ ] README reports observed results, not expected ones; no real credentials anywhere.

## 11. Honest limitations to state in the README

- Only as strong as the harness's hook coverage; name the harness used.
- Shell analysis is heuristic; unparseable commands are denied, which causes some false positives.
- Reads are logged but not scope-limited beyond `readDeny`.
- The report covers only tool calls the gate evaluated.
