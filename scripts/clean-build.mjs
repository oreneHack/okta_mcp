import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const buildDir = path.resolve(rootDir, "build");

if (path.dirname(buildDir) !== rootDir || path.basename(buildDir) !== "build") {
  throw new Error(`Refusing to clean unexpected build path: ${buildDir}`);
}

fs.rmSync(buildDir, { recursive: true, force: true });
