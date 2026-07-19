import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const envPath = path.join(rootDir, ".env");
const cliPath = path.join(rootDir, "build", "cli.js");

function stripQuotes(value) {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function loadEnvFile(file) {
  if (!fs.existsSync(file)) return;

  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;

    const key = trimmed.slice(0, eq).trim();
    const value = stripQuotes(trimmed.slice(eq + 1));
    if (key && process.env[key] === undefined) process.env[key] = value;
  }
}

loadEnvFile(envPath);

if (!fs.existsSync(cliPath)) {
  process.stderr.write(
    `[lab] Missing ${cliPath}. Run "npm install" and "npm run build" first.\n`
  );
  process.exit(1);
}

if (!process.argv[2]) process.argv[2] = "serve";

await import(pathToFileURL(cliPath).href);
