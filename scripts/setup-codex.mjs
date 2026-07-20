#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const serverName = "okta-workspace";
const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const entrypoint = path.join(rootDir, "scripts", "okta-mcp.mjs");
const codexHome =
  process.env.CODEX_HOME?.trim() || path.join(os.homedir(), ".codex");
const codexCommand = process.env.CODEX_CLI_PATH?.trim() || "codex";
const checkOnly = process.argv.slice(2).includes("--check");
const startupTimeoutSeconds = 30;
const toolTimeoutSeconds = 900;
const configPath = path.join(codexHome, "config.toml");

if (!fs.existsSync(entrypoint)) {
  console.error(`Okta MCP entrypoint was not found: ${entrypoint}`);
  process.exit(1);
}

fs.mkdirSync(codexHome, { recursive: true });

function runCodex(args, { showOutput = false } = {}) {
  const result = spawnSync(codexCommand, args, {
    cwd: rootDir,
    env: { ...process.env, CODEX_HOME: codexHome },
    encoding: "utf8",
    timeout: 30_000,
    windowsHide: true,
  });

  if (result.error) {
    const hint =
      result.error.code === "ENOENT"
        ? " Install Codex or set CODEX_CLI_PATH to its executable."
        : "";
    console.error(`Unable to run Codex: ${result.error.message}.${hint}`);
    process.exit(1);
  }

  if (showOutput) {
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
  }

  return result;
}

function hasExpectedRegistration(result) {
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  return (
    result.status === 0 &&
    output.toLowerCase().includes(entrypoint.toLowerCase())
  );
}

function hasExpectedTimeouts(result) {
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  return (
    new RegExp(`startup_timeout_sec:\\s*${startupTimeoutSeconds}(?:\\.0)?`).test(
      output
    ) &&
    new RegExp(`tool_timeout_sec:\\s*${toolTimeoutSeconds}(?:\\.0)?`).test(
      output
    )
  );
}

function hasCompleteRegistration(result) {
  return hasExpectedRegistration(result) && hasExpectedTimeouts(result);
}

function writeTimeoutSettings() {
  const config = fs.readFileSync(configPath, "utf8");
  const tableHeader = `[mcp_servers.${serverName}]`;
  const headerIndex = config.indexOf(tableHeader);
  if (headerIndex < 0) {
    throw new Error(`Codex config is missing ${tableHeader}.`);
  }

  const headerEnd = headerIndex + tableHeader.length;
  const afterHeader = config.slice(headerEnd);
  const nextTable = /\r?\n(?=\s*\[)/.exec(afterHeader);
  const blockEnd =
    nextTable === null ? config.length : headerEnd + nextTable.index;
  const newline = config.includes("\r\n") ? "\r\n" : "\n";
  const body = config.slice(headerEnd, blockEnd).replace(/^\r?\n/, "");
  const bodyLines = body
    .split(/\r?\n/)
    .filter(
      (line) =>
        !/^\s*(?:startup_timeout_sec|tool_timeout_sec)\s*=/.test(line)
    );
  while (bodyLines.at(-1)?.trim() === "") bodyLines.pop();

  const replacement = [
    tableHeader,
    ...bodyLines,
    `startup_timeout_sec = ${startupTimeoutSeconds}`,
    `tool_timeout_sec = ${toolTimeoutSeconds}`,
  ].join(newline);
  const updated =
    config.slice(0, headerIndex) +
    replacement +
    newline +
    config.slice(blockEnd).replace(/^\r?\n/, newline);

  fs.writeFileSync(configPath, updated, "utf8");
}

const current = runCodex(["mcp", "get", serverName]);

if (hasCompleteRegistration(current)) {
  console.log(`Codex MCP '${serverName}' is registered correctly.`);
  console.log(`Entrypoint: ${entrypoint}`);
  process.exit(0);
}

if (checkOnly) {
  console.error(`Codex MCP '${serverName}' is missing or points elsewhere.`);
  console.error("Run: npm run setup:codex");
  process.exit(1);
}

if (current.status === 0 && !hasExpectedRegistration(current)) {
  const removed = runCodex(["mcp", "remove", serverName], {
    showOutput: true,
  });
  if (removed.status !== 0) {
    console.error(`Could not replace Codex MCP '${serverName}'.`);
    process.exit(1);
  }
}

if (!hasExpectedRegistration(current)) {
  const added = runCodex(
    ["mcp", "add", serverName, "--", "node", entrypoint],
    { showOutput: true }
  );

  if (added.status !== 0) {
    console.error(`Could not register Codex MCP '${serverName}'.`);
    process.exit(1);
  }
}

writeTimeoutSettings();

const verified = runCodex(["mcp", "get", serverName]);
if (!hasCompleteRegistration(verified)) {
  console.error(
    `Codex reported success, but '${serverName}' did not retain the expected entrypoint.`
  );
  process.exit(1);
}

console.log(`Codex MCP '${serverName}' is registered correctly.`);
console.log(`Entrypoint: ${entrypoint}`);
console.log("Restart Codex once, then ask: Start Okta MCP");
