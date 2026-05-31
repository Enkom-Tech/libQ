#!/usr/bin/env node
/**
 * Post-release smoke: install each @lib-q package at LIBQ_NPM_VERSION, dynamically import,
 * and run wasm-pack's async module initializer (`default` or `init`) so the .wasm is linked.
 * `@lib-q/types` is types-only (no wasm).
 */
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

const VERSION = process.env.LIBQ_NPM_VERSION;
if (!VERSION) {
  console.error("LIBQ_NPM_VERSION is required");
  process.exit(1);
}

const pkgs = [
  "@lib-q/core",
  "@lib-q/ml-kem",
  "@lib-q/kem",
  "@lib-q/sig",
  "@lib-q/hash",
  "@lib-q/utils",
  "@lib-q/fn-dsa",
  "@lib-q/aead",
  "@lib-q/hpke",
  "@lib-q/zkp",
  "@lib-q/random",
  "@lib-q/hqc",
  "@lib-q/slh-dsa",
  "@lib-q/cb-kem",
  "@lib-q/ring-sig",
  "@lib-q/prf",
  "@lib-q/types",
];

function verifyOne(pkg) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "libq-npm-"));
  try {
    const ir = spawnSync(
      "npm",
      ["install", `${pkg}@${VERSION}`, "--ignore-scripts", "--no-fund", "--no-audit"],
      { cwd: dir, stdio: "inherit", shell: process.platform === "win32" },
    );
    if (ir.status !== 0) throw new Error(`npm install failed for ${pkg}`);

    const runnerPath = path.join(dir, "run.mjs");
    const quotedPkg = JSON.stringify(pkg);
    const runner = `import * as m from ${quotedPkg};
async function main() {
  if (${quotedPkg} === "@lib-q/types") {
    console.log("OK", ${quotedPkg});
    return;
  }
  if (typeof m.default === "function") {
    await m.default();
    console.log("OK", ${quotedPkg}, "default()");
    return;
  }
  if (typeof m.init === "function") {
    await m.init();
    console.log("OK", ${quotedPkg}, "init()");
    return;
  }
  if (typeof m.initSync === "function") {
    m.initSync();
    console.log("OK", ${quotedPkg}, "initSync()");
    return;
  }
  if (typeof m.init_wasm === "function") {
    m.init_wasm();
    console.log("OK", ${quotedPkg}, "init_wasm()");
    return;
  }
  // Node dual-target glue (nodejs/*.js) loads WASM at import time.
  if (Object.keys(m).length > 0) {
    console.log("OK", ${quotedPkg}, "auto-init node glue");
    return;
  }
  throw new Error("No wasm initializer (default/init/initSync/init_wasm) on " + ${quotedPkg});
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
`;
    fs.writeFileSync(runnerPath, runner);
    const rr = spawnSync(process.execPath, [runnerPath], {
      cwd: dir,
      stdio: "inherit",
    });
    if (rr.status !== 0) throw new Error(`runtime smoke failed for ${pkg}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

for (const pkg of pkgs) {
  console.log("==>", pkg, `@${VERSION}`);
  verifyOne(pkg);
}
console.log("All npm post-release smoke checks passed.");
