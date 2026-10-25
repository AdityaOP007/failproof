import { resolvePath, matchesGlobs, isProtectedPath } from "./paths.js";

/**
 * Split command line into segments by top-level operators: &&, ||, ;, |
 * Respects single and double quotes.
 *
 * @param {string} cmd
 * @returns {{ segments: string[], unclosedQuote: boolean }}
 */
export function splitTopLevelCommands(cmd) {
  const segments = [];
  let curr = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let i = 0;

  while (i < cmd.length) {
    const ch = cmd[i];
    const next = cmd[i + 1];

    if (ch === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      curr += ch;
      i++;
      continue;
    }

    if (ch === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      curr += ch;
      i++;
      continue;
    }

    if (!inSingleQuote && !inDoubleQuote) {
      // Check top-level operators: &&, ||, ;, |
      if ((ch === "&" && next === "&") || (ch === "|" && next === "|")) {
        if (curr.trim()) segments.push(curr.trim());
        curr = "";
        i += 2;
        continue;
      }
      if (ch === ";" || ch === "|") {
        if (curr.trim()) segments.push(curr.trim());
        curr = "";
        i++;
        continue;
      }
    }

    curr += ch;
    i++;
  }

  if (curr.trim()) {
    segments.push(curr.trim());
  }

  return {
    segments,
    unclosedQuote: inSingleQuote || inDoubleQuote,
  };
}

/**
 * Check if the command line contains unparseable / high-risk shell constructs:
 * - Subshells: $(...)
 * - Backticks: `...`
 * - Eval: eval ...
 * - Heredocs: <<
 * - Encoded piping to shells: base64 -d | sh/bash
 */
export function checkUnparseableConstructs(cmd) {
  // Check for $ (
  if (/\$\s*\(/.test(cmd)) {
    return { unparseable: true, reason: "Command contains subshell execution ($(...))" };
  }

  // Check for backticks
  if (cmd.includes("`")) {
    return { unparseable: true, reason: "Command contains backtick subshell execution (`...`)" };
  }

  // Check for heredocs
  if (/<<\s*\w+/.test(cmd)) {
    return { unparseable: true, reason: "Command contains heredoc syntax (<<)" };
  }

  // Check for eval
  if (/\beval\b/.test(cmd)) {
    return { unparseable: true, reason: "Command contains eval execution" };
  }

  // Check for encoded shell execution patterns (e.g., base64 -d | sh)
  if (/base64\s+(-d|--decode)\s*\|\s*(sh|bash|zsh)/i.test(cmd)) {
    return { unparseable: true, reason: "Command attempts obfuscated base64 pipe to shell" };
  }

  return { unparseable: false };
}

/**
 * Extract redirection targets (>, >>) from a command segment outside quotes.
 * Returns the cleaned command and list of target file paths.
 */
export function extractRedirections(segment) {
  const targets = [];
  let cleaned = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let i = 0;

  while (i < segment.length) {
    const ch = segment[i];
    const next = segment[i + 1];

    if (ch === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote;
      cleaned += ch;
      i++;
      continue;
    }
    if (ch === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote;
      cleaned += ch;
      i++;
      continue;
    }

    if (!inSingleQuote && !inDoubleQuote) {
      // Check for > or >>
      if (ch === ">") {
        let skip = 1;
        if (next === ">") skip = 2;

        // Collect the filename after > or >>
        let targetPart = "";
        let j = i + skip;
        while (j < segment.length && /\s/.test(segment[j])) j++;
        while (j < segment.length && !/[\s;&|><]/.test(segment[j])) {
          targetPart += segment[j];
          j++;
        }
        if (targetPart) {
          // Remove surrounding quotes if any
          const cleanTarget = targetPart.replace(/^['"]|['"]$/g, "");
          targets.push(cleanTarget);
        }
        i = j;
        continue;
      }
    }

    cleaned += ch;
    i++;
  }

  return {
    cleanedCmd: cleaned.trim(),
    redirectTargets: targets,
  };
}

/**
 * Strip leading VAR=val definitions and wrapper binaries (env, nohup, command).
 */
export function stripWrappersAndEnv(cmdStr) {
  let tokens = cmdStr.trim().split(/\s+/);
  const wrappers = new Set(["env", "nohup", "command"]);

  let changed = true;
  while (changed && tokens.length > 0) {
    changed = false;
    const first = tokens[0];

    // Strip VAR=val (must contain = and valid var name)
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(first)) {
      tokens.shift();
      changed = true;
      continue;
    }

    // Strip wrappers
    if (wrappers.has(first)) {
      tokens.shift();
      changed = true;
      continue;
    }
  }

  return tokens.join(" ").trim();
}

/**
 * Check if a command is an inline interpreter invocation:
 * e.g. bash -c "...", node -e "...", python -c "..."
 */
export function isInlineInterpreter(cmdStr) {
  return /^(bash|sh|zsh|python|python3|node|perl|ruby)\s+(-c|-e)\b/i.test(cmdStr);
}

/**
 * Check if command tokens match an allowed command prefix.
 * e.g. allowed: "npm test" -> matches "npm test", "npm test -- --bail"
 */
export function matchesCommandPrefix(cmdStr, allowedPrefix) {
  const normCmd = cmdStr.trim();
  const normPrefix = allowedPrefix.trim();
  if (normCmd === normPrefix) return true;
  if (normCmd.startsWith(normPrefix + " ")) return true;
  return false;
}

/**
 * Evaluate a shell command against the contract.
 *
 * @param {string} rawCommand
 * @param {object} contract
 * @returns {{ decision: "allow" | "deny" | "warn", rule: string, reason: string }}
 */
export function evaluateShellCommand(rawCommand, contract) {
  if (!rawCommand || typeof rawCommand !== "string" || !rawCommand.trim()) {
    return {
      decision: "deny",
      rule: "shell.empty",
      reason: "ScopeGate: Empty shell command is not allowed",
    };
  }

  const trimmed = rawCommand.trim();

  // 1. Check unclosed quotes or unparseable constructs
  const { segments, unclosedQuote } = splitTopLevelCommands(trimmed);
  if (unclosedQuote) {
    return {
      decision: "deny",
      rule: "shell.unparseable",
      reason: `ScopeGate: command contains unclosed quotes: "${trimmed}"`,
    };
  }

  const unparseableCheck = checkUnparseableConstructs(trimmed);
  if (unparseableCheck.unparseable) {
    return {
      decision: "deny",
      rule: "shell.unparseable",
      reason: `ScopeGate: ${unparseableCheck.reason}. Shell commands must be simple and directly allowlisted.`,
    };
  }

  // 2. Evaluate each top-level segment
  for (const seg of segments) {
    const { cleanedCmd, redirectTargets } = extractRedirections(seg);

    // Check redirect targets against write rules
    for (const target of redirectTargets) {
      const res = resolvePath(target, contract.repoRoot);
      if (res.isEscape) {
        return {
          decision: "deny",
          rule: "write.out-of-scope",
          reason: `ScopeGate: redirect target "${target}" escapes repository root.`,
        };
      }
      if (isProtectedPath(res.relative)) {
        return {
          decision: "deny",
          rule: "write.protected",
          reason: `ScopeGate: redirect to protected path "${res.relative}" is strictly denied.`,
        };
      }
      if (!matchesGlobs(res.relative, contract.write)) {
        return {
          decision: "deny",
          rule: "write.out-of-scope",
          reason: `ScopeGate: redirect to "${res.relative}" is outside write scope (allowed: ${contract.write.join(", ")}).`,
        };
      }
    }

    // Now evaluate the executable command
    const coreCmd = stripWrappersAndEnv(cleanedCmd);
    if (!coreCmd) {
      continue; // only variable assignment or redirection, handled
    }

    // Deny ScopeGate self-tampering
    if (/^(\.\/bin\/)?scopegate\b/i.test(coreCmd) || /\bnpx\s+scopegate\b/i.test(coreCmd)) {
      return {
        decision: "deny",
        rule: "shell.scopegate-tamper",
        reason: "ScopeGate: Agents cannot invoke ScopeGate commands. Widening scope is a human action.",
      };
    }

    // Deny inline interpreters unless the exact command is allowlisted
    if (isInlineInterpreter(coreCmd)) {
      const isExplicitlyAllowed = (contract.commands.allow || []).some(
        (allowed) => allowed.trim() === coreCmd || allowed.trim() === cleanedCmd
      );
      if (!isExplicitlyAllowed) {
        return {
          decision: "deny",
          rule: "shell.inline-interpreter",
          reason: `ScopeGate: inline interpreter "${coreCmd}" is denied to prevent uninspected code execution.`,
        };
      }
    }

    // Check commands.deny first
    const denyList = contract.commands.deny || [];
    for (const denied of denyList) {
      if (matchesCommandPrefix(coreCmd, denied) || matchesCommandPrefix(cleanedCmd, denied)) {
        return {
          decision: "deny",
          rule: "shell.denied",
          reason: `ScopeGate: command "${coreCmd}" is explicitly denied by contract policy (${denied}).`,
        };
      }
    }

    // Check commands.allow
    const allowList = contract.commands.allow || [];
    const isAllowed = allowList.some((allowed) => matchesCommandPrefix(coreCmd, allowed));

    if (!isAllowed) {
      const allowedMsg = allowList.length > 0 ? allowList.join(", ") : "none";
      const reason = `ScopeGate: command "${coreCmd}" is not in the allowed commands list (allowed: ${allowedMsg}). Do not retry. Tell the user, who can run "scopegate widen --allow-cmd \\"${coreCmd}\\"" if intended.`;
      if (contract.mode === "warn") {
        return { decision: "warn", rule: "shell.not-allowed", reason };
      }
      return { decision: "deny", rule: "shell.not-allowed", reason };
    }
  }

  return {
    decision: "allow",
    rule: "shell.allowed",
    reason: `ScopeGate: command passed all scope checks.`,
  };
}
