const fs = require("fs");
const path = require("path");
const winattr = require("winattr");
const { analyzeJS } = require("./jsAnalyzer");

function isWindowsHidden(filePath) {
  if (!fs.existsSync(filePath)) return false;
  try {
    const attr = winattr.getSync(filePath);
    return attr.hidden || attr.system;
  } catch {
    return false;
  }
}

function isInsideHiddenFolder(filePath) {
  if (!fs.existsSync(filePath)) return false;

  let current = path.parse(filePath).root;
  const relative = path.relative(current, filePath);
  const parts = relative.split(path.sep);

  for (const part of parts.slice(0, -1)) {
    current = path.join(current, part);
    if (isWindowsHidden(current)) {
      return true;
    }
  }
  return false;
}

function analyzeManifest(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  const lines = content.split(/\r?\n/);
  const issues = [];

  let currentBlock = null;
  let inBlock = false;
  const baseDir = path.dirname(filePath);

  lines.forEach((line, index) => {
    const trimmed = line.trim();

    if (/^(server_scripts|shared_scripts)\s*=?\s*\{/.test(trimmed)) {
      currentBlock = trimmed.startsWith("server")
        ? "server_scripts"
        : "shared_scripts";
      inBlock = true;
      return;
    }

    if (inBlock && trimmed.startsWith("}")) {
      currentBlock = null;
      inBlock = false;
      return;
    }

    if (!currentBlock) return;

    const jsMatches = [...trimmed.matchAll(/["']([^"']+\.js)["']/gi)];
    if (jsMatches.length === 0) return;

    jsMatches.forEach((match) => {
      const jsPath = match[1];
      const fullJsPath = path.resolve(baseDir, jsPath);
      const exists = fs.existsSync(fullJsPath);

      const hidden =
        exists &&
        (isWindowsHidden(fullJsPath) || isInsideHiddenFolder(fullJsPath));

      if (currentBlock === "shared_scripts" && hidden) {
        issues.push({
          type: "manifest_backdoor",
          file: filePath,
          line: index + 1,
          jsPath,
          exists,
          risk: "critical",
          reason: "JS en shared_scripts ubicado en archivo o carpeta oculta",
        });
        return;
      }

      if (currentBlock === "server_scripts") {
        let risk = "warning";
        let reason = "Ruta de un archivo JS dentro de server_scripts";

        if (exists) {
          const jsIssues = analyzeJS(fullJsPath);

          const hasCritical = jsIssues.some(
            (issue) => issue.risk === "critical"
          );

          if (hasCritical) {
            risk = "critical";
            reason =
              "JS en server_scripts con firmas maliciosas críticas detectadas";
          }
        }

        issues.push({
          type: "manifest_backdoor",
          file: filePath,
          line: index + 1,
          jsPath,
          exists,
          risk,
          reason,
        });
      }
    });
  });

  return issues;
}

module.exports = { analyzeManifest };
