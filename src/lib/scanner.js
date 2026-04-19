import dns from "node:dns/promises";
import fs from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const COMMON_PORTS = new Set([20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995]);
const HISTORY_DIR = path.join(process.cwd(), ".shadow");
const HISTORY_PATH = path.join(HISTORY_DIR, "last-scan.json");

export async function scanConnections(options = {}) {
  const mergedOptions = {
    resolve: false,
    history: true,
    all: false,
    limit: 25,
    process: null,
    state: null,
    port: null,
    ...options
  };

  const rawConnections = await collectConnections();
  const connectionCounts = countBy(rawConnections, (entry) => String(entry.pid));
  const previousScan = mergedOptions.history ? await loadHistory() : [];
  const previousKeys = new Set(previousScan.map(toConnectionKey));

  let connections = await Promise.all(
    rawConnections.map(async (entry) =>
      enrichConnection(entry, {
        resolveHostnames: mergedOptions.resolve,
        processConnectionCount: connectionCounts.get(String(entry.pid)) || 0,
        isNew: mergedOptions.history ? !previousKeys.has(toConnectionKey(entry)) : false
      })
    )
  );

  connections = applyFilters(connections, mergedOptions);
  connections.sort(sortConnections);

  const report = buildReport(connections, mergedOptions);

  if (mergedOptions.history) {
    await saveHistory(rawConnections);
  }

  return report;
}

export function parseArgs(args) {
  const options = {
    json: false,
    resolve: false,
    history: true,
    all: false,
    limit: 25,
    process: null,
    state: null,
    port: null,
    help: false
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];

    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--resolve") {
      options.resolve = true;
    } else if (arg === "--no-history") {
      options.history = false;
    } else if (arg === "--all") {
      options.all = true;
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else if (arg === "--process") {
      options.process = args[index + 1] || null;
      index += 1;
    } else if (arg === "--state") {
      options.state = (args[index + 1] || "").toUpperCase();
      index += 1;
    } else if (arg === "--port") {
      options.port = Number(args[index + 1]);
      index += 1;
    } else if (arg === "--limit") {
      options.limit = Math.max(1, Number(args[index + 1]) || 25);
      index += 1;
    }
  }

  return options;
}

export function printHelp() {
  console.log("Shadow Connections Viewer");
  console.log("CLI: node ./src/index.js [--resolve] [--json] [--all]");
  console.log("UI : node ./src/server.js");
  console.log("Options:");
  console.log("  --resolve          Attempt reverse DNS lookups for remote IPs");
  console.log("  --json             Print machine-readable output");
  console.log("  --process <name>   Filter by process name");
  console.log("  --state <state>    Filter by TCP state");
  console.log("  --port <number>    Filter by local or remote port");
  console.log("  --limit <number>   Number of rows to print in text mode");
  console.log("  --all              Show all rows in text mode");
  console.log("  --no-history       Do not compare against previous scan");
}

export function printSummary(summary) {
  console.log("SHADOW CONNECTIONS VIEWER");
  console.log(`  Scanned At: ${summary.scannedAt}`);
  console.log(`  Total Connections: ${summary.totalConnections}`);
  console.log(`  New Connections: ${summary.newConnections}`);
  console.log(`  High Risk: ${summary.highRisk}`);
  console.log(`  Medium Risk: ${summary.mediumRisk}`);
  console.log(`  Low Risk: ${summary.lowRisk}`);
}

export function printConnections(connections, limit) {
  if (!connections.length) {
    console.log("\nNo matching connections found.");
    return;
  }

  console.log(`\nTOP CONNECTIONS (${Math.min(limit, connections.length)} shown)`);

  for (const entry of connections) {
    const badge = entry.isNew ? "NEW" : "   ";
    const reasons = entry.risk.reasons.length ? entry.risk.reasons.join(", ") : "normal baseline";
    console.log(
      `  [${badge}] ${entry.risk.level.toUpperCase()} ${entry.processName} (PID ${entry.pid}) ${entry.localAddress}:${entry.localPort} -> ${entry.remoteAddress}:${entry.remotePort}`
    );
    console.log(`        State: ${entry.state} | Host: ${entry.hostLabel} | Score: ${entry.risk.score}`);
    console.log(`        Notes: ${reasons}`);
  }
}

async function collectConnections() {
  const [netstatOutput, tasklistOutput] = await Promise.all([
    execFileAsync("netstat.exe", ["-ano", "-p", "tcp"], { maxBuffer: 10 * 1024 * 1024 }),
    execFileAsync("tasklist.exe", ["/FO", "CSV", "/NH"], { maxBuffer: 10 * 1024 * 1024 })
  ]);

  const processMap = parseTasklist(tasklistOutput.stdout);
  return parseNetstat(netstatOutput.stdout, processMap);
}

async function enrichConnection(entry, context) {
  const hostnames = context.resolveHostnames ? await reverseLookup(entry.remoteAddress) : [];
  const risk = scoreConnection(entry, context.processConnectionCount);

  return {
    ...entry,
    hostnames,
    hostLabel: hostnames[0] || "unresolved",
    risk,
    isNew: context.isNew
  };
}

async function reverseLookup(ipAddress) {
  if (!isPublicIp(ipAddress)) {
    return [];
  }

  try {
    return await dns.reverse(ipAddress);
  } catch {
    return [];
  }
}

function scoreConnection(entry, processConnectionCount) {
  if (entry.state === "TIME_WAIT" || Number(entry.pid) === 0) {
    return {
      score: 0,
      level: "low",
      reasons: []
    };
  }

  let score = 0;
  const reasons = [];
  const remotePort = Number(entry.remotePort);
  const processName = (entry.processName || "unknown").toLowerCase();
  const isExternal = isPublicIp(entry.remoteAddress);

  if (entry.state !== "LISTENING" && isExternal && !COMMON_PORTS.has(remotePort)) {
    score += 30;
    reasons.push("uncommon remote port");
  }

  if (processConnectionCount >= 12) {
    score += 15;
    reasons.push("high connection count for process");
  }

  if (["svchost", "runtimebroker", "rundll32", "regsvr32", "wscript", "cscript"].includes(processName)) {
    score += 10;
    reasons.push("living-off-the-land process");
  }

  if (!isExternal || entry.state === "LISTENING") {
    score = Math.max(0, score - 15);
  }

  const level = score >= 45 ? "high" : score >= 20 ? "medium" : "low";

  return {
    score,
    level,
    reasons
  };
}

function buildReport(connections, options) {
  const rows = options.all ? connections : connections.slice(0, options.limit);
  const summary = {
    scannedAt: new Date().toISOString(),
    totalConnections: connections.length,
    visibleRows: rows.length,
    newConnections: connections.filter((entry) => entry.isNew).length,
    highRisk: connections.filter((entry) => entry.risk.level === "high").length,
    mediumRisk: connections.filter((entry) => entry.risk.level === "medium").length,
    lowRisk: connections.filter((entry) => entry.risk.level === "low").length
  };

  return {
    summary,
    connections: rows
  };
}

function applyFilters(connections, options) {
  return connections.filter((entry) => {
    if (options.process && !entry.processName.toLowerCase().includes(options.process.toLowerCase())) {
      return false;
    }

    if (options.state && entry.state !== options.state) {
      return false;
    }

    if (
      Number.isFinite(options.port) &&
      Number(entry.localPort) !== options.port &&
      Number(entry.remotePort) !== options.port
    ) {
      return false;
    }

    return true;
  });
}

async function loadHistory() {
  try {
    const data = await fs.readFile(HISTORY_PATH, "utf8");
    const parsed = JSON.parse(data);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function saveHistory(connections) {
  await fs.mkdir(HISTORY_DIR, { recursive: true });
  await fs.writeFile(HISTORY_PATH, JSON.stringify(connections, null, 2));
}

function toConnectionKey(entry) {
  return [
    entry.protocol,
    entry.pid,
    entry.localAddress,
    entry.localPort,
    entry.remoteAddress,
    entry.remotePort
  ].join("|");
}

function sortConnections(left, right) {
  if (left.isNew !== right.isNew) {
    return left.isNew ? -1 : 1;
  }

  if (left.risk.score !== right.risk.score) {
    return right.risk.score - left.risk.score;
  }

  return String(left.processName).localeCompare(String(right.processName));
}

function countBy(entries, selector) {
  const map = new Map();

  for (const entry of entries) {
    const key = selector(entry);
    map.set(key, (map.get(key) || 0) + 1);
  }

  return map;
}

function isPublicIp(value) {
  if (!value || value === "0.0.0.0" || value === "::" || value === "127.0.0.1" || value === "::1") {
    return false;
  }

  if (value.startsWith("10.") || value.startsWith("192.168.") || value.startsWith("169.254.")) {
    return false;
  }

  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(value)) {
    return false;
  }

  if (value.startsWith("fe80:") || value.startsWith("fc") || value.startsWith("fd")) {
    return false;
  }

  return true;
}

function parseNetstat(output, processMap) {
  const lines = output.split(/\r?\n/);
  const rows = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line.startsWith("TCP")) {
      continue;
    }

    const parts = line.split(/\s+/);
    if (parts.length < 5) {
      continue;
    }

    const [protocol, local, remote, state, pidValue] = parts;
    const localEndpoint = parseEndpoint(local);
    const remoteEndpoint = parseEndpoint(remote);
    const pid = Number(pidValue);

    if (!localEndpoint || !remoteEndpoint) {
      continue;
    }

    rows.push({
      protocol,
      state,
      localAddress: localEndpoint.address,
      localPort: localEndpoint.port,
      remoteAddress: remoteEndpoint.address,
      remotePort: remoteEndpoint.port,
      pid,
      processName: processMap.get(pid) || "unknown"
    });
  }

  return rows;
}

function parseEndpoint(value) {
  if (!value) {
    return null;
  }

  if (value.startsWith("[")) {
    const match = value.match(/^\[(.*)\]:(\d+|\*)$/);
    if (!match) {
      return null;
    }

    return {
      address: match[1],
      port: match[2] === "*" ? 0 : Number(match[2])
    };
  }

  const lastColon = value.lastIndexOf(":");
  if (lastColon === -1) {
    return null;
  }

  return {
    address: value.slice(0, lastColon),
    port: value.slice(lastColon + 1) === "*" ? 0 : Number(value.slice(lastColon + 1))
  };
}

function parseTasklist(output) {
  const map = new Map();
  const lines = output.split(/\r?\n/).filter(Boolean);

  for (const line of lines) {
    const columns = line
      .split(/","/)
      .map((part) => part.replace(/^"/, "").replace(/"$/, ""));

    if (columns.length < 2) {
      continue;
    }

    const processName = columns[0];
    const pid = Number(columns[1]);

    if (Number.isFinite(pid)) {
      map.set(pid, processName);
    }
  }

  return map;
}
