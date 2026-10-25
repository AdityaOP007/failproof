import path from "node:path";
import fs from "node:fs";

export const CONTRACT_DIR = ".scopegate";
export const CONTRACT_FILE = ".scopegate/contract.json";
export const EVENTS_FILE = ".scopegate/events.jsonl";

export const DEFAULT_READ_DENY = [
  ".env*",
  "**/.env*",
  "**/*.pem",
  "**/id_rsa*",
  "**/.ssh/**",
  "**/.aws/**",
];

export const DEFAULT_COMMANDS_DENY = [
  "git push",
  "npm publish",
  "curl",
  "wget",
  "ssh",
  "sudo",
  "rm -rf",
  "scopegate",
];

/**
 * Validate and normalize a contract object.
 *
 * @param {object} raw
 * @returns {{ valid: boolean, errors: string[], contract?: object }}
 */
export function validateContract(raw) {
  const errors = [];

  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { valid: false, errors: ["Contract must be a JSON object"] };
  }

  if (!raw.task || typeof raw.task !== "string" || raw.task.trim() === "") {
    errors.push("Missing or invalid 'task' description string");
  }

  if (!raw.repoRoot || typeof raw.repoRoot !== "string") {
    errors.push("Missing or invalid 'repoRoot' string");
  }

  const write = Array.isArray(raw.write)
    ? raw.write.filter((w) => typeof w === "string" && w.trim() !== "")
    : [];

  const readDeny = Array.isArray(raw.readDeny)
    ? Array.from(new Set([...DEFAULT_READ_DENY, ...raw.readDeny.filter((r) => typeof r === "string")]))
    : [...DEFAULT_READ_DENY];

  const commands = raw.commands && typeof raw.commands === "object" ? raw.commands : {};
  const allowCmds = Array.isArray(commands.allow)
    ? commands.allow.filter((c) => typeof c === "string" && c.trim() !== "")
    : [];
  const denyCmds = Array.isArray(commands.deny)
    ? Array.from(new Set([...DEFAULT_COMMANDS_DENY, ...commands.deny.filter((c) => typeof c === "string")]))
    : [...DEFAULT_COMMANDS_DENY];

  const mode = raw.mode === "warn" ? "warn" : "enforce";

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  const normalized = {
    task: raw.task.trim(),
    repoRoot: path.resolve(raw.repoRoot),
    base: typeof raw.base === "string" ? raw.base.trim() : "",
    write,
    readDeny,
    commands: {
      allow: allowCmds,
      deny: denyCmds,
    },
    mode,
  };

  return { valid: true, errors: [], contract: normalized };
}

/**
 * Load contract from a given repository root.
 *
 * @param {string} repoRoot
 * @returns {{ status: "inert" | "active" | "invalid", contract: object | null, error?: string }}
 */
export function loadContract(repoRoot) {
  const contractPath = path.resolve(repoRoot, CONTRACT_FILE);

  if (!fs.existsSync(contractPath)) {
    return { status: "inert", contract: null };
  }

  let rawText;
  try {
    rawText = fs.readFileSync(contractPath, "utf8");
  } catch (err) {
    return {
      status: "invalid",
      contract: null,
      error: `Failed to read contract: ${err.message}`,
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    return {
      status: "invalid",
      contract: null,
      error: `Contract JSON is corrupted: ${err.message}`,
    };
  }

  const result = validateContract(parsed);
  if (!result.valid) {
    return {
      status: "invalid",
      contract: null,
      error: `Contract validation failed: ${result.errors.join("; ")}`,
    };
  }

  return {
    status: "active",
    contract: result.contract,
  };
}

/**
 * Save contract to disk.
 *
 * @param {string} repoRoot
 * @param {object} contractData
 */
export function saveContract(repoRoot, contractData) {
  const result = validateContract(contractData);
  if (!result.valid) {
    throw new Error(`Invalid contract: ${result.errors.join("; ")}`);
  }

  const contractDir = path.resolve(repoRoot, CONTRACT_DIR);
  if (!fs.existsSync(contractDir)) {
    fs.mkdirSync(contractDir, { recursive: true });
  }

  const contractPath = path.resolve(repoRoot, CONTRACT_FILE);
  fs.writeFileSync(contractPath, JSON.stringify(result.contract, null, 2) + "\n", "utf8");
  return result.contract;
}

/**
 * Widen an existing contract (Human only).
 *
 * @param {string} repoRoot
 * @param {{ write?: string[], allowCmd?: string[] }} additions
 */
export function widenContract(repoRoot, additions = {}) {
  const loaded = loadContract(repoRoot);
  if (loaded.status !== "active") {
    throw new Error(`Cannot widen: contract is ${loaded.status} (${loaded.error || "missing"})`);
  }

  const current = loaded.contract;
  if (additions.write && Array.isArray(additions.write)) {
    const set = new Set([...current.write, ...additions.write]);
    current.write = Array.from(set);
  }

  if (additions.allowCmd && Array.isArray(additions.allowCmd)) {
    const set = new Set([...current.commands.allow, ...additions.allowCmd]);
    current.commands.allow = Array.from(set);
  }

  return saveContract(repoRoot, current);
}
