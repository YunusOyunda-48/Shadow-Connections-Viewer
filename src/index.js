#!/usr/bin/env node

import {
  parseArgs,
  printConnections,
  printHelp,
  printSummary,
  scanConnections
} from "./lib/scanner.js";

async function main() {
  const options = parseArgs(process.argv.slice(2));

  if (options.help) {
    printHelp();
    return;
  }

  const report = await scanConnections(options);

  if (options.json) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  printSummary(report.summary);
  printConnections(report.connections, options.limit);
}

main().catch((error) => {
  console.error(`Fatal error: ${error.message}`);
  process.exit(1);
});
