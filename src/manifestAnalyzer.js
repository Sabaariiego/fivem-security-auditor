const fs = require("fs");
const path = require("path");
const winattr = require("winattr");
const { analyzeJS } = require("./jsAnalyzer");
const { analyzeDLL } = require("./dllAnalyzer");
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

function analyzeDllReference(filePath, baseDir, currentBlock, dllPath, lineNumber) {
  const fullDllPath = path.resolve(baseDir, dllPath);
  const exists = fs.existsSync(fullDllPath);
  const dllName = path.basename(dllPath).toLowerCase();

  const issue = {
    type: "manifest_dll_reference",
    file: filePath,
    line: lineNumber,
    dllPath,
    resolvedFile: fullDllPath,
    exists,
    risk: "warning",
    reason: `Archivo .net.dll referenciado en ${currentBlock} — archivo no encontrado en disco`,
  };

  if (!exists) return issue;

  const dllIssues = analyzeDLL(fullDllPath);
  const hasKnownBackdoor = dllIssues.some((i) => i.type === "dll_known_backdoor");
  const hasCritical = dllIssues.some((i) => i.risk === "critical");

  if (hasKnownBackdoor) {
    issue.risk = "critical";
    issue.reason = `⚠️ BACKDOOR CONOCIDO EN DLL: '${dllPath}' en ${currentBlock} — ${dllIssues.find((i) => i.type === "dll_known_backdoor").reason}`;
  } else if (hasCritical) {
    issue.risk = "critical";
    issue.reason = `DLL con indicadores críticos referenciado en ${currentBlock}: '${dllPath}'`;
  } else {
    issue.risk = "warning";
    issue.reason = `Archivo .net.dll referenciado en ${currentBlock} — sin indicadores maliciosos detectados`;
  }

  issue.dllAnalysis = dllIssues;
  return issue;
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

    let isSingleLine = false;

    if (/^(server_scripts|shared_scripts)\s*=?\s*\{/.test(trimmed)) {
      currentBlock = trimmed.startsWith("server")
        ? "server_scripts"
        : "shared_scripts";
      if (trimmed.includes("}")) {
        isSingleLine = true;
        inBlock = false;
      } else {
        inBlock = true;
        return;
      }
    }

    if (inBlock && trimmed.startsWith("}")) {
      currentBlock = null;
      inBlock = false;
      return;
    }

    if (!currentBlock) return;

    const dllMatches = [
      ...trimmed.matchAll(/["']([^"']+\.net\.dll)["']/gi),
    ];

    dllMatches.forEach((match) => {
      const dllPath = match[1];
      issues.push(
        analyzeDllReference(filePath, baseDir, currentBlock, dllPath, index + 1)
      );
    });

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
        const hasCritical = jsIssues.some((issue) => issue.risk === "critical");

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

    if (isSingleLine) currentBlock = null;
  });

  return issues;
}

module.exports = { analyzeManifest };