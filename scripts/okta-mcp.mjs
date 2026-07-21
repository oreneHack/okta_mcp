#!/usr/bin/env node

const command = process.argv[2];
const cliCommands = new Set([
  "configure",
  "setup",
  "init",
  "login",
  "status",
  "logout",
  "reset",
  "config-path",
  "help",
  "--help",
  "-h",
]);

if (cliCommands.has(command)) {
  await import("../build/cli.js");
} else {
  if (["start", "stdio", "serve"].includes(command)) {
    process.argv.splice(2, 1);
  }
  process.env.OKTA_MCP_AUTHORIZED_LAB = "1";
  await import("./lab-mcp.mjs");
}
