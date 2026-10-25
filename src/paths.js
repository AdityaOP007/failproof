import path from "node:path";
import fs from "node:fs";
import picomatch from "picomatch";

/**
 * Standard protected path globs that can never be modified by the agent.
 */
export const PROTECTED_GLOBS = [
  ".scopegate/**",
  ".scopegate",
  ".failproofai/**",
  ".failproofai",
  "**/.scopegate/**",
  "**/.failproofai/**",
];

/**
 * Normalize path to POSIX style (forward slashes) and lowercase drive letter on Windows.
 */
export function normalizeSlashes(p) {
  if (!p) return "";
  let normalized = p.replace(/\\/g, "/");
  // Normalize Windows drive letter: C:/ -> c:/
  if (/^[A-Za-z]:\//.test(normalized)) {
    normalized = normalized[0].toLowerCase() + normalized.slice(1);
  }
  return normalized;
}

/**
 * Find the deepest existing ancestor of a given path.
 */
export function getDeepestExistingAncestor(targetPath) {
  let curr = path.resolve(targetPath);
  while (!fs.existsSync(curr)) {
    const parent = path.dirname(curr);
    if (parent === curr) break;
    curr = parent;
  }
  return curr;
}

/**
 * Resolve a path against repoRoot and ensure it does not escape repoRoot via
 * path traversal (../) or symlinks.
 *
 * @param {string} rawPath - Target path (relative or absolute)
 * @param {string} repoRoot - Absolute path to repository root
 * @returns {{ resolved: string, relative: string, isEscape: boolean, reason?: string }}
 */
export function resolvePath(rawPath, repoRoot) {
  if (!rawPath || typeof rawPath !== "string") {
    return { resolved: "", relative: "", isEscape: true, reason: "path.empty" };
  }

  // Reject paths containing null bytes
  if (rawPath.includes("\0")) {
    return { resolved: "", relative: "", isEscape: true, reason: "path.null-byte" };
  }

  const normRepoRoot = normalizeSlashes(path.resolve(repoRoot));
  let canonicalRepoRoot = normRepoRoot;
  try {
    if (fs.existsSync(normRepoRoot)) {
      canonicalRepoRoot = normalizeSlashes(fs.realpathSync(normRepoRoot));
    }
  } catch {
    canonicalRepoRoot = normRepoRoot;
  }

  // Resolve target path against repoRoot
  const resolvedTarget = path.isAbsolute(rawPath)
    ? path.resolve(rawPath)
    : path.resolve(normRepoRoot, rawPath);
  const normResolved = normalizeSlashes(resolvedTarget);

  // 1. Basic path traversal check
  const relFromRoot = path.relative(normRepoRoot, normResolved);
  if (relFromRoot.startsWith("..") || path.isAbsolute(relFromRoot)) {
    return {
      resolved: normResolved,
      relative: relFromRoot,
      isEscape: true,
      reason: "path.traversal-outside-repo",
    };
  }

  // 2. Symlink escape check: realpath deepest existing ancestor
  try {
    const existingAncestor = getDeepestExistingAncestor(normResolved);
    if (fs.existsSync(existingAncestor)) {
      const canonicalAncestor = normalizeSlashes(fs.realpathSync(existingAncestor));
      const relAncestor = path.relative(canonicalRepoRoot, canonicalAncestor);
      if (relAncestor.startsWith("..") || path.isAbsolute(relAncestor)) {
        return {
          resolved: normResolved,
          relative: relFromRoot,
          isEscape: true,
          reason: "path.symlink-escape",
        };
      }
    }
  } catch (err) {
    // If realpath fails unexpectedly, fail closed
    return {
      resolved: normResolved,
      relative: relFromRoot,
      isEscape: true,
      reason: `path.symlink-check-error: ${err.message}`,
    };
  }

  const cleanRel = normalizeSlashes(relFromRoot);
  return {
    resolved: normResolved,
    relative: cleanRel,
    isEscape: false,
  };
}

/**
 * Check if a relative path matches any of the given globs.
 */
export function matchesGlobs(relPath, globs) {
  if (!globs || !Array.isArray(globs) || globs.length === 0) {
    return false;
  }
  const cleanRel = normalizeSlashes(relPath);
  const isMatch = picomatch(globs, { dot: true });
  return isMatch(cleanRel);
}

/**
 * Check if a relative path matches protected files that agents can never touch.
 */
export function isProtectedPath(relPath) {
  return matchesGlobs(relPath, PROTECTED_GLOBS);
}
