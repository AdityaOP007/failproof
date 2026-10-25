#!/usr/bin/env node
import path from "node:path";
import fs from "node:fs";
import { execSync } from "node:child_process";
import {
  loadContract,
  saveContract,
  widenContract,
  CONTRACT_FILE,
  EVENTS_FILE,
} from "./contract.js";
import { readEvents, logEvent } from "./log.js";
import { matchesGlobs, resolvePath } from "./paths.js";
import { runBypassTests } from "../test/bypass.cases.js";

/**
 * Get current git HEAD commit hash, or return fallback.
 */
function getGitHead(repoRoot) {
  try {
    return execSync("git rev-parse HEAD", {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
  } catch {
    return "uncommitted-initial";
  }
}

/**
 * Get files modified against base git commit.
 */
function getGitDiffFiles(repoRoot, base) {
  const normRepoRoot = path.resolve(repoRoot).replace(/\\/g, "/");
  let gitTopLevel = normRepoRoot;
  try {
    gitTopLevel = execSync("git rev-parse --show-toplevel", {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim()
      .replace(/\\/g, "/");
  } catch {}

  const files = new Set();

  // 1. Track untracked and modified working-tree files
  try {
    const status = execSync("git status --porcelain -uall -- .", {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
    if (status) {
      status.split("\n").forEach((line) => {
        const raw = line.trim().slice(2).trim().replace(/^"|"$/g, "");
        if (raw) {
          const abs = path.resolve(gitTopLevel, raw).replace(/\\/g, "/");
          const relToRepo = path.relative(normRepoRoot, abs).replace(/\\/g, "/");
          if (!relToRepo.startsWith("..") && !relToRepo.startsWith(".scopegate")) {
            files.add(relToRepo);
          }
        }
      });
    }
  } catch {}

  // 2. Track diff against base commit
  if (base && base !== "uncommitted-initial") {
    try {
      const diff = execSync(`git diff --name-only ${base} -- .`, {
        cwd: repoRoot,
        stdio: ["ignore", "pipe", "ignore"],
      })
        .toString()
        .trim();
      if (diff) {
        diff.split("\n").forEach((raw) => {
          if (raw.trim()) {
            const abs = path.resolve(gitTopLevel, raw.trim()).replace(/\\/g, "/");
            const relToRepo = path.relative(normRepoRoot, abs).replace(/\\/g, "/");
            if (!relToRepo.startsWith("..") && !relToRepo.startsWith(".scopegate")) {
              files.add(relToRepo);
            }
          }
        });
      }
    } catch {}
  }

  return Array.from(files);
}

/**
 * CLI Argument Parser supporting repeated flags (--write, --allow-cmd).
 */
function parseArgs(args) {
  const result = {
    command: "",
    task: "",
    write: [],
    allowCmd: [],
    denyCmd: [],
    readDeny: [],
    mode: "enforce",
    repo: process.cwd(),
  };

  let i = 0;
  if (args.length > 0 && !args[0].startsWith("-")) {
    result.command = args[0];
    i = 1;
  }

  while (i < args.length) {
    const arg = args[i];
    const next = args[i + 1];

    if (arg === "--task" && next) {
      result.task = next;
      i += 2;
    } else if (arg === "--write" && next) {
      result.write.push(next);
      i += 2;
    } else if (arg === "--allow-cmd" && next) {
      result.allowCmd.push(next);
      i += 2;
    } else if (arg === "--deny-cmd" && next) {
      result.denyCmd.push(next);
      i += 2;
    } else if (arg === "--read-deny" && next) {
      result.readDeny.push(next);
      i += 2;
    } else if (arg === "--mode" && next) {
      result.mode = next;
      i += 2;
    } else if (arg === "--repo" && next) {
      result.repo = path.resolve(next);
      i += 2;
    } else {
      i++;
    }
  }

  return result;
}

// -----------------------------------------------------------------------------
// Command Handlers
// -----------------------------------------------------------------------------

function handleStart(options) {
  const repoRoot = path.resolve(options.repo);
  const task = options.task || "Task-scoped boundary";
  const base = getGitHead(repoRoot);

  const contractData = {
    task,
    repoRoot,
    base,
    write: options.write.length > 0 ? options.write : ["src/**"],
    readDeny: options.readDeny.length > 0 ? options.readDeny : [".env*", "**/*.pem", "**/id_rsa*"],
    commands: {
      allow: options.allowCmd.length > 0 ? options.allowCmd : ["npm test", "git status", "git diff"],
      deny: options.denyCmd.length > 0 ? options.denyCmd : ["git push", "npm publish", "curl", "wget", "ssh", "sudo", "rm -rf"],
    },
    mode: options.mode || "enforce",
  };

  const saved = saveContract(repoRoot, contractData);

  // Clear previous session events if starting fresh
  const eventsFile = path.resolve(repoRoot, EVENTS_FILE);
  if (fs.existsSync(eventsFile)) {
    fs.writeFileSync(eventsFile, "", "utf8");
  }

  logEvent(repoRoot, {
    tool: "scopegate",
    summary: `ScopeGate initialized for task: "${task}"`,
    decision: "allow",
    rule: "contract.start",
  });

  console.log("\n🛡️  ScopeGate contract created successfully!");
  console.log(`📁 Contract: ${path.resolve(repoRoot, CONTRACT_FILE)}`);
  console.log(`🎯 Task:     "${saved.task}"`);
  console.log(`📌 Base:     ${saved.base}`);
  console.log(`✍️  Write:    ${saved.write.join(", ")}`);
  console.log(`🔒 Commands: ${saved.commands.allow.join(", ")}`);
  console.log(`⚙️  Mode:     ${saved.mode}\n`);
}

function handleWiden(options) {
  const repoRoot = path.resolve(options.repo);
  if (options.write.length === 0 && options.allowCmd.length === 0) {
    console.error("❌ Error: Specify --write <glob> or --allow-cmd <cmd> to widen scope.");
    process.exit(1);
  }

  try {
    const updated = widenContract(repoRoot, {
      write: options.write,
      allowCmd: options.allowCmd,
    });

    logEvent(repoRoot, {
      tool: "human.widen",
      summary: `Human widened scope: write=[${options.write.join(", ")}], allowCmd=[${options.allowCmd.join(", ")}]`,
      decision: "allow",
      rule: "human.widen",
    });

    console.log("\n🔓 ScopeGate widened (Human Authorized):");
    console.log(`✍️  Updated Write:    ${updated.write.join(", ")}`);
    console.log(`🔒 Updated Commands: ${updated.commands.allow.join(", ")}\n`);
  } catch (err) {
    console.error(`❌ Error widening contract: ${err.message}`);
    process.exit(1);
  }
}

function handleStatus(options) {
  const repoRoot = path.resolve(options.repo);
  const loaded = loadContract(repoRoot);

  if (loaded.status === "inert") {
    console.log("\n⚪ ScopeGate status: INERT (no contract found in current directory).\n");
    return;
  }

  if (loaded.status === "invalid") {
    console.log(`\n❌ ScopeGate status: CORRUPT / INVALID (${loaded.error})\n`);
    return;
  }

  const c = loaded.contract;
  const events = readEvents(repoRoot);
  const allows = events.filter((e) => e.decision === "allow").length;
  const denies = events.filter((e) => e.decision === "deny").length;
  const warns = events.filter((e) => e.decision === "warn").length;

  console.log("\n=======================================================");
  console.log("🛡️  ScopeGate Status Report");
  console.log("=======================================================");
  console.log(`Task:        ${c.task}`);
  console.log(`Repo Root:   ${c.repoRoot}`);
  console.log(`Base Commit: ${c.base || "(none)"}`);
  console.log(`Mode:        ${c.mode}`);
  console.log(`Write Scope: ${c.write.join(", ")}`);
  console.log(`Read Deny:   ${c.readDeny.join(", ")}`);
  console.log(`Cmds Allow:  ${c.commands.allow.join(", ")}`);
  console.log(`Cmds Deny:   ${c.commands.deny.join(", ")}`);
  console.log("-------------------------------------------------------");
  console.log(`Logged Tool Decisions:  ${events.length} total`);
  console.log(`  ✅ Allowed: ${allows}`);
  console.log(`  🚫 Denied:  ${denies}`);
  console.log(`  ⚠️  Warned:  ${warns}`);
  console.log("=======================================================\n");
}

function handleReport(options) {
  const repoRoot = path.resolve(options.repo);
  const loaded = loadContract(repoRoot);

  if (loaded.status !== "active") {
    console.error(`❌ Cannot generate report: contract is ${loaded.status}`);
    process.exit(1);
  }

  const c = loaded.contract;
  const events = readEvents(repoRoot);
  const blocked = events.filter((e) => e.decision === "deny");
  const changedFiles = getGitDiffFiles(repoRoot, c.base);

  console.log(`# ScopeGate Scope-Enforcement Report\n`);
  console.log(`**Task:** ${c.task}  `);
  console.log(`**Base Commit:** \`${c.base || "HEAD"}\`  `);
  console.log(`**Mode:** \`${c.mode}\`  `);
  console.log(`**Allowed Write Scope:** \`${c.write.join(", ")}\`  `);
  console.log(`**Allowed Commands:** \`${c.commands.allow.join(", ")}\`\n`);

  console.log(`## 1. Repository Changes (vs Base)\n`);
  if (changedFiles.length === 0) {
    console.log(`_No file modifications detected in repository._\n`);
  } else {
    console.log(`| File | Scope Gate Verdict |`);
    console.log(`| :--- | :--- |`);
    for (const f of changedFiles) {
      const inScope = matchesGlobs(f, c.write);
      const verdict = inScope ? "✅ IN-SCOPE (Allowed)" : "❌ OUT-OF-SCOPE (Anomaly)";
      console.log(`| \`${f}\` | ${verdict} |`);
    }
    console.log("");
  }

  console.log(`## 2. Blocked Agent Attempts (PreToolUse Interceptions)\n`);
  if (blocked.length === 0) {
    console.log(`_No out-of-scope actions attempted or blocked._\n`);
  } else {
    console.log(`| Timestamp | Tool | Rule | Action / Target Summary |`);
    console.log(`| :--- | :--- | :--- | :--- |`);
    for (const b of blocked) {
      const time = b.ts ? b.ts.split("T")[1].replace("Z", "") : "";
      console.log(`| ${time} | \`${b.tool}\` | \`${b.rule}\` | ${b.summary} |`);
    }
    console.log("");
  }

  console.log(`---`);
  console.log(`*Note: ScopeGate covers only tool calls evaluated before execution. Static shell analysis is heuristic.*`);
}

function printUsage() {
  console.log(`
ScopeGate: Task-Scoped Guardrails for AI Coding Agents

Usage:
  scopegate start --task "..." --write "src/**" --allow-cmd "npm test"
  scopegate widen --write "billing/**" --allow-cmd "npm run build"
  scopegate status
  scopegate report
  scopegate test
`);
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------
const parsed = parseArgs(process.argv.slice(2));

switch (parsed.command) {
  case "start":
    handleStart(parsed);
    break;
  case "widen":
    handleWiden(parsed);
    break;
  case "status":
    handleStatus(parsed);
    break;
  case "report":
    handleReport(parsed);
    break;
  case "test":
    runBypassTests(parsed.repo);
    break;
  case "help":
  case "--help":
  case "-h":
    printUsage();
    break;
  default:
    if (!parsed.command) {
      printUsage();
    } else {
      console.error(`Unknown command: ${parsed.command}`);
      printUsage();
      process.exit(1);
    }
}
