#!/usr/bin/env node
/**
 * Finalize package.json for @lib-q/* wasm-pack tarballs: deterministic entrypoints,
 * conditional exports (browser vs node) when web/ + nodejs/ subtrees exist, files[],
 * and integrity-manifest.json (SHA-384, SRI-style) for all packaged .wasm files.
 *
 * Run with cwd = npm package root (e.g. lib-q/pkg). Reads STEM from env NPM_PUBLISH_STEM
 * (Rust [lib].name) when set; otherwise falls back to index.js layout.
 */
import crypto from "crypto";
import fs from "fs";
import path from "path";

const cwd = process.cwd();
const pkgPath = path.join(cwd, "package.json");
const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));

const stem = (process.env.NPM_PUBLISH_STEM || "").trim();

function findWasmFiles() {
  const out = [];
  function walk(d) {
    if (!fs.existsSync(d)) return;
    for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, ent.name);
      if (ent.isDirectory()) walk(p);
      else if (ent.name.endsWith(".wasm")) out.push(p);
    }
  }
  walk(cwd);
  return out;
}

const wasmFiles = findWasmFiles();
const hasWasm = wasmFiles.length > 0;

const dual =
  stem &&
  fs.existsSync(path.join(cwd, "web", `${stem}.js`)) &&
  fs.existsSync(path.join(cwd, "nodejs", `${stem}.js`));

const flatStem =
  stem &&
  fs.existsSync(path.join(cwd, `${stem}.js`)) &&
  fs.existsSync(path.join(cwd, `${stem}.d.ts`));

if (dual) {
  pkg.main = `./nodejs/${stem}.js`;
  pkg.module = `./web/${stem}.js`;
  pkg.types = `./web/${stem}.d.ts`;
  pkg.exports = {
    ".": {
      types: `./web/${stem}.d.ts`,
      browser: `./web/${stem}.js`,
      node: `./nodejs/${stem}.js`,
      default: `./web/${stem}.js`,
    },
  };
  if (hasWasm) {
    pkg.files = ["web", "nodejs", "README.md", "integrity-manifest.json"];
  } else {
    pkg.files = ["web", "nodejs", "README.md"];
  }
} else if (flatStem) {
  pkg.main = `./${stem}.js`;
  pkg.module = `./${stem}.js`;
  pkg.types = `./${stem}.d.ts`;
  pkg.exports = {
    ".": {
      types: `./${stem}.d.ts`,
      import: `./${stem}.js`,
      default: `./${stem}.js`,
    },
  };
  delete pkg.exports.require;
  if (hasWasm) {
    pkg.files = ["*.js", "*.d.ts", "*.wasm", "README.md", "integrity-manifest.json"];
  } else {
    pkg.files = ["*.js", "*.d.ts", "README.md"];
  }
} else if (fs.existsSync(path.join(cwd, "index.js"))) {
  pkg.main = "./index.js";
  pkg.module = "./index.js";
  pkg.types = "./index.d.ts";
  pkg.exports = {
    ".": {
      types: "./index.d.ts",
      import: "./index.js",
      default: "./index.js",
    },
  };
  pkg.files = ["index.js", "index.d.ts", "README.md"];
} else {
  console.error(
    "npm-publish-annotate: could not resolve entry layout (need web/nodejs, flat stem, or index.js)",
  );
  process.exit(1);
}

if (wasmFiles.length > 0) {
  const integrity = {};
  for (const f of wasmFiles.sort()) {
    const rel = path.relative(cwd, f).split(path.sep).join("/");
    const digest = crypto.createHash("sha384").update(fs.readFileSync(f)).digest("base64");
    integrity[rel] = `sha384-${digest}`;
  }
  fs.writeFileSync(path.join(cwd, "integrity-manifest.json"), `${JSON.stringify({ integrity }, null, 2)}\n`);
}

fs.writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
console.log("npm-publish-annotate: OK", { dual, stem: stem || "(index)", hasWasm });
