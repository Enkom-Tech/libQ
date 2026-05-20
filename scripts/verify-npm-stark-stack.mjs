#!/usr/bin/env node
/**
 * Smoke-check @lib-q/stark stack + research pilots (registry or local pkg/nodejs).
 *   node scripts/verify-npm-stark-stack.mjs
 *   USE_LOCAL=1 node scripts/verify-npm-stark-stack.mjs
 */
import { pathToFileURL } from "node:url";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const useLocal = process.env.USE_LOCAL === "1";

const packages = [
  {
    name: "@lib-q/stark",
    file: "lib_q_stark.js",
    dir: "lib-q-stark/pkg/nodejs",
    check(m) {
      const v = m.starkPackageVersion?.();
      if (typeof v !== "string" || !v.length) throw new Error("starkPackageVersion empty");
      return v;
    },
  },
  {
    name: "@lib-q/plonky",
    file: "lib_q_plonky.js",
    dir: "lib-q-plonky/pkg/nodejs",
    check(m) {
      const v = m.plonkyPackageVersion?.();
      if (typeof v !== "string" || !v.length) throw new Error("plonkyPackageVersion empty");
      return v;
    },
  },
  {
    name: "@lib-q/poseidon",
    file: "lib_q_poseidon.js",
    dir: "lib-q-poseidon/pkg/nodejs",
    check(m) {
      const hex = m.poseidon128Hash12Hex?.();
      if (typeof hex !== "string" || hex.length !== 16) throw new Error("poseidon128Hash12Hex invalid");
      return `${hex.slice(0, 16)}…`;
    },
  },
  {
    name: "@lib-q/lattice-zkp",
    file: "lib_q_lattice_zkp.js",
    dir: "lib-q-lattice-zkp/pkg/nodejs",
    check(m) {
      const hex = m.latticeZkpPilotCommitHex?.();
      if (typeof hex !== "string" || hex.length < 16) throw new Error("latticeZkpPilotCommitHex invalid");
      return `${hex.slice(0, 16)}…`;
    },
  },
  {
    name: "@lib-q/ring",
    file: "lib_q_ring.js",
    dir: "lib-q-ring/pkg/nodejs",
    check(m) {
      const n = m.ringCoefficientCount?.();
      const q = m.ringModulusQ?.();
      if (n !== 256) throw new Error(`ringCoefficientCount expected 256, got ${n}`);
      if (q !== 8380417) throw new Error(`ringModulusQ expected 8380417, got ${q}`);
      return `N=${n}, q=${q}`;
    },
  },
];

let failed = 0;
for (const pkg of packages) {
  try {
    const modPath = useLocal
      ? path.join(root, pkg.dir, pkg.file)
      : pkg.name;
    const href = useLocal ? pathToFileURL(modPath).href : pkg.name;
    const m = await import(href);
    const detail = pkg.check(m);
    console.log(`OK ${pkg.name}${useLocal ? " (local)" : ""}: ${detail}`);
  } catch (e) {
    console.error(`FAIL ${pkg.name}:`, e.message || e);
    failed++;
  }
}

if (failed) process.exit(1);
