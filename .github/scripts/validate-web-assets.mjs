import fs from "node:fs";
import path from "node:path";

const webDir = path.resolve(process.cwd(), "web");
const indexPath = path.join(webDir, "index.html");

if (!fs.existsSync(indexPath)) {
  console.error(`Missing required file: ${indexPath}`);
  process.exit(1);
}

const html = fs.readFileSync(indexPath, "utf8");
const refs = new Set();
const attributePattern = /\b(?:src|href)\s*=\s*["']([^"']+)["']/gi;

let match;
while ((match = attributePattern.exec(html)) !== null) {
  refs.add(match[1]);
}

const ignoredPrefixes = ["http://", "https://", "//", "data:", "mailto:", "tel:", "#"];
const missing = [];
const outsideWebRoot = [];

for (const rawRef of refs) {
  if (ignoredPrefixes.some((prefix) => rawRef.startsWith(prefix))) {
    continue;
  }

  const cleanRef = rawRef.split("#")[0].split("?")[0];
  if (cleanRef.length === 0) {
    continue;
  }

  const resolved = path.resolve(webDir, cleanRef);
  if (!resolved.startsWith(`${webDir}${path.sep}`) && resolved !== webDir) {
    outsideWebRoot.push(rawRef);
    continue;
  }

  if (!fs.existsSync(resolved)) {
    missing.push(rawRef);
  }
}

if (outsideWebRoot.length > 0 || missing.length > 0) {
  if (outsideWebRoot.length > 0) {
    console.error("Found references outside web root:");
    for (const ref of outsideWebRoot) {
      console.error(`  - ${ref}`);
    }
  }

  if (missing.length > 0) {
    console.error("Missing referenced assets:");
    for (const ref of missing) {
      console.error(`  - ${ref}`);
    }
  }

  process.exit(1);
}

console.log(`Validated ${refs.size} asset references in web/index.html.`);
