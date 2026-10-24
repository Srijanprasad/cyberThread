// Compile contracts with solc-js (no network access to solc binaries needed).
const fs = require("fs");
const path = require("path");
const solc = require("solc");

const root = __dirname;
const names = ["EvidenceAnchor", "ModelRegistry"];
const sources = {};
for (const n of names) {
  sources[`contracts/${n}.sol`] = { content: fs.readFileSync(path.join(root, "contracts", `${n}.sol`), "utf8") };
}

function findImports(p) {
  const candidates = [path.join(root, "node_modules", p), path.join(root, p)];
  for (const c of candidates) if (fs.existsSync(c)) return { contents: fs.readFileSync(c, "utf8") };
  return { error: `File not found: ${p}` };
}

const input = {
  language: "Solidity",
  sources,
  settings: {
    evmVersion: "paris", // avoids PUSH0 so it runs on any EVM client
    optimizer: { enabled: true, runs: 200 },
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
  },
};

const out = JSON.parse(solc.compile(JSON.stringify(input), { import: findImports }));
let failed = false;
for (const e of out.errors || []) {
  console.error(e.formattedMessage);
  if (e.severity === "error") failed = true;
}
if (failed) process.exit(1);

fs.mkdirSync(path.join(root, "build"), { recursive: true });
for (const n of names) {
  const c = out.contracts[`contracts/${n}.sol`][n];
  fs.writeFileSync(
    path.join(root, "build", `${n}.json`),
    JSON.stringify({ contractName: n, abi: c.abi, bytecode: "0x" + c.evm.bytecode.object }, null, 2)
  );
  console.log(`compiled ${n}: ${c.evm.bytecode.object.length / 2} bytes`);
}
