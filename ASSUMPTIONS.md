# ScopeGate: Verified Assumptions & Harness Mapping

This document records verified interface details for Failproof AI and supported agent harnesses (Claude Code, Cursor, Codex, OpenClaw, Antigravity, etc.).

---

## 1. Failproof AI Policy Hook Interface

Failproof AI custom policies register via the `customPolicies` registry and intercept tool invocations before execution:

```javascript
import { customPolicies, deny, allow } from "failproofai";

customPolicies.add({
  name: "scopegate",
  match: { events: ["PreToolUse"] },
  fn: async (ctx) => {
    // Return deny(reason) to block the tool call before execution
    // Return allow() to let the tool call proceed
  }
});
```

### Context (`ctx`) Structure
The `PreToolUse` hook receives a context object representing the pending tool invocation:

```javascript
// Generic normalized shape:
{
  tool: string,        // Name of the tool being called (e.g., "Bash", "Edit", "Write", "View")
  input: object,       // Tool input arguments (e.g., { command: "...", path: "..." })
  cwd?: string,        // Working directory if provided by harness
  timestamp?: number   // Event timestamp
}
```

---

## 2. Harness-Specific Raw Tool Payloads

Below are the canonical raw tool call shapes observed across major AI coding harnesses:

### A. Shell Execution Tool Call
**Claude Code (`Bash`) / Generic Shell:**
```json
{
  "tool": "Bash",
  "input": {
    "command": "npm test"
  }
}
```
*Variants observed:*
- Tool name: `"Bash"`, `"bash"`, `"execute_command"`, `"run_command"`, `"shell"`
- Command field: `"command"`, `"CommandLine"`, `"cmd"`

### B. File Edit / Write Tool Call
**Claude Code (`Edit` / `Write`):**
```json
{
  "tool": "Edit",
  "input": {
    "path": "src/auth/login.js",
    "old_string": "return '/dashbaord';",
    "new_string": "return '/dashboard';"
  }
}
```
**Claude Code (`Write` / File Creation):**
```json
{
  "tool": "Write",
  "input": {
    "path": "billing/invoice.js",
    "content": "..."
  }
}
```
*Variants observed:*
- Tool name: `"Edit"`, `"Write"`, `"replace_file_content"`, `"multi_replace_file_content"`, `"write_to_file"`, `"create_file"`
- File path field: `"path"`, `"file_path"`, `"TargetFile"`, `"filePath"`, `"filename"`

### C. File Read Tool Call
**Claude Code (`View` / `readFile`):**
```json
{
  "tool": "View",
  "input": {
    "path": ".env"
  }
}
```
*Variants observed:*
- Tool name: `"View"`, `"Read"`, `"readFile"`, `"view_file"`, `"cat"`
- File path field: `"path"`, `"file_path"`, `"AbsolutePath"`, `"filePath"`, `"filename"`

---

## 3. Tool Classification & Security Policy

| Category | Known Tool Names | Target Evaluated | Default Policy |
| :--- | :--- | :--- | :--- |
| **`write`** | `Edit`, `Write`, `write_to_file`, `replace_file_content`, `multi_replace_file_content`, `create_file` | Target file path | Allowed ONLY if matches contract `write` globs AND is NOT protected (`.scopegate/**`, `.failproofai/**`). |
| **`read`** | `View`, `Read`, `readFile`, `view_file`, `cat` | Target file path | Allowed UNLESS matches `readDeny` globs (`.env*`, `**/*.pem`, etc.). |
| **`shell`** | `Bash`, `bash`, `execute_command`, `run_command`, `shell` | Raw command line | Checked against deny list, parsed for compound commands, checked against allow list prefixes, redirect targets checked as writes. |
| **`other`** | Read-only tools (`Glob`, `Grep`, `LS`, `list_dir`) | Query / pattern | Allowed (non-mutating). Any unknown state-mutating tool is denied by default. |

---

## 4. Contract Isolation & Human Sovereignty

1. The contract (`.scopegate/contract.json`) is strictly read-only for the AI agent.
2. Direct edits to `.scopegate/**` and `.failproofai/**` are protected with a dedicated denial rule (`write.protected`).
3. Shell commands invoking `scopegate` or `failproofai` are explicitly denied to prevent the agent from using CLI subcommands to alter its own bounds.
4. Scope changes require human intervention via `scopegate widen`.
