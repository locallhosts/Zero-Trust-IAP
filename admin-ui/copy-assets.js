// Tiny build helper: tsc only emits compiled JS into dist/, so this copies
// the static public/ assets (index.html, styles.css) alongside it. Kept as
// a plain Node script (no bundler) since the UI has no build-time deps
// beyond the TypeScript compiler itself.
const fs = require("fs");
const path = require("path");

const publicDir = path.join(__dirname, "public");
const distDir = path.join(__dirname, "dist");

fs.mkdirSync(distDir, { recursive: true });
for (const file of fs.readdirSync(publicDir)) {
  fs.copyFileSync(path.join(publicDir, file), path.join(distDir, file));
}
console.log(`copied ${fs.readdirSync(publicDir).length} static asset(s) into dist/`);
