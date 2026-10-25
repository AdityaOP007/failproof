import { resolvePath, matchesGlobs, isProtectedPath } from "./paths.js";
import { evaluateShellCommand } from "./shell.js";

/**
 * Normalized tool classifications across AI agent harnesses.
 */
export const TOOL_MAP = {
  // Write tools
  edit: "write",
  write: "write",
  write_to_file: "write",
  replace_file_content: "write",
  multi_replace_file_content: "write",
  create_file: "write",
  strreplace: "write",
  str_replace_editor: "write",
  patch: "write",

  // Read tools
  view: "read",
  read: "read",
  readfile: "read",
  view_file: "read",
  cat: "read",

  // Shell execution tools
  bash: "shell",
  execute_command: "shell",
  run_command: "shell",
  shell: "shell",
  exec: "shell",

  // Read-only inspection tools
  glob: "inspect",
  grep: "inspect",
  grep_search: "inspect",
  ls: "inspect",
  list_dir: "inspect",
  dir: "inspect",
  find: "inspect",
};

/**
 * Classify a tool name into a canonical category: write | read | shell | inspect | unknown.
 */
export function classifyTool(toolName) {
  if (!toolName || typeof toolName !== "string") return "unknown";
  const norm = toolName.trim().toLowerCase();
  return TOOL_MAP[norm] || "unknown";
}

/**
 * Extract target file path from tool input across different harness conventions.
 */
export function extractFilePath(input) {
  if (!input) return "";
  if (typeof input === "string") return input.trim();
  if (typeof input !== "object") return "";

  const candidates = [
    input.path,
    input.file_path,
    input.TargetFile,
    input.filePath,
    input.target_file,
    input.targetFile,
    input.AbsolutePath,
    input.absolute_path,
    input.filename,
    input.file,
  ];

  for (const c of candidates) {
    if (typeof c === "string" && c.trim()) {
      return c.trim();
    }
  }

  return "";
}

/**
 * Extract shell command string from tool input across different harness conventions.
 */
export function extractCommand(input) {
  if (!input) return "";
  if (typeof input === "string") return input.trim();
  if (typeof input !== "object") return "";

  const candidates = [
    input.command,
    input.CommandLine,
    input.cmd,
    input.script,
    input.input,
  ];

  for (const c of candidates) {
    if (typeof c === "string" && c.trim()) {
      return c.trim();
    }
  }

  return "";
}

/**
 * Suggest a wildcard pattern for the widen prompt based on relative path.
 * e.g., "billing/invoice.js" -> "billing/**"
 */
function suggestWidenPattern(relPath) {
  const parts = relPath.replace(/\\/g, "/").split("/");
  if (parts.length > 1) {
    return `${parts[0]}/**`;
  }
  return relPath;
}

/**
 * Pure evaluation function:
 * (contract, call) -> { decision: "allow" | "deny" | "warn", rule: string, reason: string }
 *
 * Guaranteed ZERO dependencies on Failproof AI or network.
 *
 * @param {object | null} contract - Validated ScopeGate contract
 * @param {{ tool: string, input: any }} call - Tool call object
 * @returns {{ decision: "allow" | "deny" | "warn", rule: string, reason: string, summary?: string }}
 */
export function evaluate(contract, call) {
  try {
    // 1. Missing contract: gate is inert
    if (!contract) {
      return {
        decision: "allow",
        rule: "contract.inert",
        reason: "ScopeGate is inert (no active contract found).",
        summary: "Inert: no contract",
      };
    }

    if (!contract.repoRoot || !Array.isArray(contract.write)) {
      return {
        decision: "deny",
        rule: "contract.invalid",
        reason: "ScopeGate: Active contract is missing required fields.",
        summary: "Contract invalid",
      };
    }

    if (!call || typeof call !== "object") {
      return {
        decision: "deny",
        rule: "call.invalid",
        reason: "ScopeGate: Tool call payload is invalid.",
        summary: "Invalid call payload",
      };
    }

    const toolName = call.tool || call.tool_name || call.name || "";
    const category = classifyTool(toolName);
    const mode = contract.mode || "enforce";

    // 2. Evaluate Write Tool
    if (category === "write") {
      const rawPath = extractFilePath(call.input);
      if (!rawPath) {
        return {
          decision: "deny",
          rule: "write.missing-path",
          reason: "ScopeGate: Write tool call did not specify a target file path.",
          summary: `write without path [${toolName}]`,
        };
      }

      const res = resolvePath(rawPath, contract.repoRoot);

      // Traversal or symlink escape
      if (res.isEscape) {
        return {
          decision: "deny",
          rule: "write.out-of-scope",
          reason: `ScopeGate: write to "${rawPath}" escapes the repository root (${res.reason || "escape detected"}).`,
          summary: `write escape: ${rawPath}`,
        };
      }

      // Protected ScopeGate & Failproof files
      if (isProtectedPath(res.relative)) {
        return {
          decision: "deny",
          rule: "write.protected",
          reason: `ScopeGate: modification of protected file "${res.relative}" is strictly denied. Agents cannot alter ScopeGate configuration or Failproof policies.`,
          summary: `write protected: ${res.relative}`,
        };
      }

      // Check against task write globs
      const inScope = matchesGlobs(res.relative, contract.write);
      if (inScope) {
        return {
          decision: "allow",
          rule: "write.in-scope",
          reason: `ScopeGate: write to "${res.relative}" is within task scope.`,
          summary: `write allowed: ${res.relative}`,
        };
      }

      // Out of scope write
      const allowedStr = contract.write.length > 0 ? contract.write.join(", ") : "none";
      const suggestion = suggestWidenPattern(res.relative);
      const reason = `ScopeGate: write to ${res.relative} is outside this task's scope (allowed: ${allowedStr}). Do not retry. Tell the user, who can run "scopegate widen --write ${suggestion}" if intended.`;

      return {
        decision: mode === "warn" ? "warn" : "deny",
        rule: "write.out-of-scope",
        reason,
        summary: `write out-of-scope: ${res.relative}`,
      };
    }

    // 3. Evaluate Read Tool
    if (category === "read") {
      const rawPath = extractFilePath(call.input);
      if (!rawPath) {
        return {
          decision: "allow",
          rule: "read.allowed",
          reason: "ScopeGate: Read tool call without specific path allowed.",
          summary: `read [${toolName}]`,
        };
      }

      const res = resolvePath(rawPath, contract.repoRoot);
      if (res.isEscape) {
        return {
          decision: "deny",
          rule: "read.out-of-scope",
          reason: `ScopeGate: reading path outside repository root is denied: "${rawPath}".`,
          summary: `read escape: ${rawPath}`,
        };
      }

      // Check against readDeny globs
      if (matchesGlobs(res.relative, contract.readDeny)) {
        return {
          decision: "deny",
          rule: "read.denied",
          reason: `ScopeGate: reading secret or sensitive file "${res.relative}" is denied by contract policy.`,
          summary: `read secret denied: ${res.relative}`,
        };
      }

      return {
        decision: "allow",
        rule: "read.allowed",
        reason: `ScopeGate: read allowed for "${res.relative}".`,
        summary: `read: ${res.relative}`,
      };
    }

    // 4. Evaluate Shell Tool
    if (category === "shell") {
      const rawCommand = extractCommand(call.input);
      const shellResult = evaluateShellCommand(rawCommand, contract);
      return {
        ...shellResult,
        summary: `shell [${rawCommand.slice(0, 80)}]`,
      };
    }

    // 5. Evaluate Inspection / Non-mutating Tools
    if (category === "inspect") {
      return {
        decision: "allow",
        rule: "inspect.allowed",
        reason: `ScopeGate: read-only inspection tool [${toolName}] allowed.`,
        summary: `inspect [${toolName}]`,
      };
    }

    // 6. Unknown state-mutating tool: fail closed
    return {
      decision: "deny",
      rule: "tool.unknown-mutating",
      reason: `ScopeGate: tool "${toolName}" is unrecognized and denied by default.`,
      summary: `unknown tool: ${toolName}`,
    };
  } catch (err) {
    // Fail closed on internal error
    return {
      decision: "deny",
      rule: "scopegate.internal-error",
      reason: `ScopeGate internal evaluation error: ${err.message}`,
      summary: `internal error: ${err.message}`,
    };
  }
}
