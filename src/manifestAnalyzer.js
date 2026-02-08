const fs = require("fs");
const path = require("path");
const winattr = require("winattr");
const { analyzeJS } = require("./jsAnalyzer");
const { globSync } = require("glob");

function resolveJsPaths(baseDir, jsPath) {
  if (!jsPath.includes("*")) {
    const full = path.resolve(baseDir, jsPath);
    return fs.existsSync(full) ? [full] : [];
  }

  return globSync(jsPath, {
    cwd: baseDir,
    absolute: true,
    nodir: true,
  });
}

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
      const resolvedFiles = resolveJsPaths(baseDir, jsPath);

      if (resolvedFiles.length === 0) {
        issues.push({
          type: "manifest_backdoor",
          file: filePath,
          line: index + 1,
          jsPath,
          exists: false,
          risk: "warning",
          reason: "El patrón JS no coincide con ningún archivo",
        });
        return;
      }

      resolvedFiles.forEach((fullJsPath) => {
        const hidden =
          isWindowsHidden(fullJsPath) || isInsideHiddenFolder(fullJsPath);

        let risk = "warning";
        let reason = `Ruta de un archivo JS dentro de ${currentBlock}`;
        
        const jsIssues = analyzeJS(fullJsPath);
        const hasCritical = jsIssues.some(
          (issue) => issue.risk === "critical"
        );

        if (hasCritical) {
          risk = "critical";
          reason = `JS en ${currentBlock} con firmas maliciosas críticas detectadas`;
        }

        if (currentBlock === "shared_scripts" && hidden) {
          risk = "critical";
          reason =
            "JS en shared_scripts con firmas maliciosas y ubicado en archivo o carpeta oculta";
        }

        issues.push({
          type: "manifest_backdoor",
          file: filePath,
          line: index + 1,
          jsPath,
          resolvedFile: fullJsPath,
          exists: true,
          risk,
          reason,
        });
      });
    });
  });

  return issues;
}

module.exports = { analyzeManifest };
