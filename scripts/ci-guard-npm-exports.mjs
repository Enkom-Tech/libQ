#!/usr/bin/env node
/**
 * Guard: every file a wasm-pack npm package actually ships (per `files[]`/`npm pack`) must be
 * reachable through its `exports` map — not just declared present in the tarball.
 *
 * Two independent checks, because the structural one alone is a "gate that cannot fail": a shape
 * assertion can pass while real resolution still breaks on Node's condition-nesting rules.
 *
 *   1. Structural — every packaged `.wasm` has a matching `exports` key; `./package.json` is
 *      exported.
 *   2. Behavioural (the one that matters) — `npm pack` the package for real, install the tarball
 *      into an ISOLATED throwaway consumer (unique scope, so an ancestor `node_modules/@lib-q`
 *      cannot shadow it — see the isolation note below), then `import.meta.resolve()` every
 *      packaged `.wasm` subpath plus `./package.json`, and confirm the resolved `.wasm` file's
 *      first four bytes are the real WebAssembly magic (`\0asm` = 0061736d).
 *
 * Usage: node scripts/ci-guard-npm-exports.mjs <package-root> [<package-root> ...]
 * Exits non-zero and prints every violation if any package fails either check.
 *
 * ISOLATION NOTE: Node's `node_modules` resolution walks every ancestor directory of the
 * consumer, so a throwaway consumer created anywhere under a user's home (including the OS temp
 * dir, which is itself a home subdirectory on Windows) can silently resolve a same-named package
 * out of a *real, already-installed* `@lib-q/*` tree higher up the tree instead of the tarball
 * this guard just built. That produces a false pass/fail that has nothing to do with the package
 * under test. To defeat it unconditionally, this guard renames the package to a per-run unique
 * scope (`@ci-guard-npm-exports-<random>/<name>`) before installing it, so there is no real
 * package anywhere on disk with that name to collide with.
 */
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const WASM_MAGIC = Buffer.from([0x00, 0x61, 0x73, 0x6d]);

const IS_WINDOWS = process.platform === "win32";

// Windows requires `shell: true` to spawn `.cmd`/`.bat` shims (npm/npx) at all — spawning them
// directly is a Windows API restriction, not a Node choice. With `shell: true`, Node passes an
// args *array* straight to cmd.exe without quoting (hence its DEP0190 warning), so we quote each
// argument ourselves and join into one command string; every argument here is a fixed script
// literal or a path we generated, never external/attacker input.
function quoteForWindowsShell(arg) {
  if (/^[A-Za-z0-9_.:/\\-]+$/.test(arg)) return arg;
  return `"${arg.replace(/"/g, '""')}"`;
}

function run(cmd, args, opts = {}) {
  const needsShell = IS_WINDOWS && (cmd === "npm" || cmd === "npx");
  if (needsShell) {
    const commandLine = [cmd, ...args].map(quoteForWindowsShell).join(" ");
    return execFileSync(commandLine, { encoding: "utf8", shell: true, ...opts });
  }
  return execFileSync(cmd, args, { encoding: "utf8", ...opts });
}

function checkPackage(root) {
  const absRoot = path.resolve(root);
  const pkgPath = path.join(absRoot, "package.json");
  if (!fs.existsSync(pkgPath)) {
    return [`${root}: no package.json at ${pkgPath}`];
  }
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  const name = pkg.name;
  if (!name) return [`${root}: package.json has no "name"`];

  // What actually gets packed (respects `files[]`/.npmignore), from npm itself — not our own
  // re-derivation of the files[] glob, which could drift from npm's real behaviour.
  const packJson = JSON.parse(run("npm", ["pack", "--dry-run", "--json"], { cwd: absRoot }));
  const packedFiles = packJson[0].files.map((f) => f.path.split(path.sep).join("/"));
  const wasmRelPaths = packedFiles.filter((f) => f.endsWith(".wasm"));

  const violations = [];

  // --- 1. structural -----------------------------------------------------------------------
  const exportsObj = pkg.exports && typeof pkg.exports === "object" ? pkg.exports : {};
  const exportKeys = new Set(Object.keys(exportsObj));
  for (const rel of wasmRelPaths) {
    const key = `./${rel}`;
    if (!exportKeys.has(key)) {
      violations.push(
        `${name}: packaged wasm "${rel}" has no matching "exports" key ("${key}" missing)`,
      );
    }
  }
  if (!exportKeys.has("./package.json")) {
    violations.push(`${name}: "./package.json" is not in "exports"`);
  }

  // --- 2. behavioural ------------------------------------------------------------------------
  const uniqueScope = `ci-guard-npm-exports-${crypto.randomBytes(6).toString("hex")}`;
  const unscopedName = name.startsWith("@") ? name.split("/")[1] : name;
  const uniqueName = `@${uniqueScope}/${unscopedName}`;

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "libq-npm-exports-guard-"));
  let tgzPath;
  try {
    // Pack the real tarball, then rewrite its name to the unique scope so no ancestor
    // node_modules can ever shadow it (see ISOLATION NOTE above), then repack.
    const tgzName = run("npm", ["pack", "--silent"], { cwd: absRoot }).trim().split("\n").pop();
    tgzPath = path.join(absRoot, tgzName);
    const extractDir = path.join(workDir, "extracted");
    fs.mkdirSync(extractDir, { recursive: true });
    // --force-local: GNU tar on Windows otherwise misparses a "C:\..." path's drive-letter colon
    // as remote host syntax ("host:path").
    run("tar", ["--force-local", "-xzf", tgzPath, "-C", extractDir]);
    fs.rmSync(tgzPath, { force: true });

    const extractedPkgDir = path.join(extractDir, "package");
    const extractedPkgJsonPath = path.join(extractedPkgDir, "package.json");
    const extractedPkg = JSON.parse(fs.readFileSync(extractedPkgJsonPath, "utf8"));
    extractedPkg.name = uniqueName;
    fs.writeFileSync(extractedPkgJsonPath, JSON.stringify(extractedPkg, null, 2));

    const renamedTgzName = run("npm", ["pack", "--silent"], { cwd: extractedPkgDir })
      .trim()
      .split("\n")
      .pop();
    const renamedTgzPath = path.join(extractedPkgDir, renamedTgzName);

    const consumerDir = path.join(workDir, "consumer");
    fs.mkdirSync(consumerDir, { recursive: true });
    fs.writeFileSync(
      path.join(consumerDir, "package.json"),
      JSON.stringify({ name: "ci-guard-npm-exports-consumer", version: "0.0.0", type: "module", private: true }, null, 2),
    );
    run("npm", ["install", "--no-audit", "--no-fund", "--no-save", renamedTgzPath], {
      cwd: consumerDir,
    });

    const installedRoot = path.join(consumerDir, "node_modules", uniqueScope.startsWith("@") ? uniqueScope : `@${uniqueScope}`, unscopedName);
    if (!fs.existsSync(installedRoot)) {
      violations.push(`${name}: install did not land at expected path ${installedRoot}`);
    } else {
      const probeTargets = [...wasmRelPaths.map((r) => `./${r}`), "./package.json"];
      const probeScript = `
        const targets = ${JSON.stringify(probeTargets)};
        const name = ${JSON.stringify(uniqueName)};
        const results = [];
        for (const t of targets) {
          const spec = t === "." ? name : \`\${name}/\${t.slice(2)}\`;
          try {
            const resolved = import.meta.resolve(spec);
            results.push({ t, ok: true, resolved });
          } catch (e) {
            results.push({ t, ok: false, error: e.code || e.message });
          }
        }
        console.log(JSON.stringify(results));
      `;
      const probeFile = path.join(consumerDir, "probe.mjs");
      fs.writeFileSync(probeFile, probeScript);
      const raw = run("node", ["probe.mjs"], { cwd: consumerDir });
      const results = JSON.parse(raw.trim().split("\n").pop());
      for (const r of results) {
        if (!r.ok) {
          violations.push(`${name}: import.meta.resolve('${uniqueName}${r.t.slice(1)}') failed: ${r.error}`);
          continue;
        }
        if (r.t.endsWith(".wasm")) {
          const resolvedPath = new URL(r.resolved).pathname
            .replace(/^\/([a-zA-Z]):/, "$1:"); // strip leading slash before a Windows drive letter
          if (!fs.existsSync(resolvedPath)) {
            violations.push(`${name}: resolved path for ${r.t} does not exist on disk: ${resolvedPath}`);
            continue;
          }
          const fd = fs.openSync(resolvedPath, "r");
          const buf = Buffer.alloc(4);
          fs.readSync(fd, buf, 0, 4, 0);
          fs.closeSync(fd);
          if (!buf.equals(WASM_MAGIC)) {
            violations.push(
              `${name}: resolved ${r.t} does not have wasm magic bytes (got ${buf.toString("hex")})`,
            );
          }
        }
      }
    }
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
    // The initial `npm pack` in absRoot is normally already removed right after extraction
    // (above); this also cleans it up if an error happened before that point.
    if (tgzPath) {
      fs.rmSync(tgzPath, { force: true });
    }
  }

  return violations;
}

const roots = process.argv.slice(2);
if (roots.length === 0) {
  console.error("usage: node scripts/ci-guard-npm-exports.mjs <package-root> [<package-root> ...]");
  process.exit(2);
}

let allViolations = [];
for (const root of roots) {
  const violations = checkPackage(root);
  allViolations = allViolations.concat(violations);
}

if (allViolations.length > 0) {
  console.error("npm exports guard: FAILED");
  for (const v of allViolations) {
    console.error(`  - ${v}`);
  }
  process.exit(1);
}

console.log(`npm exports guard: OK (${roots.length} package(s))`);
