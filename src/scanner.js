const fs = require("fs");
const path = require("path");
const winattr = require("winattr");
const { walk } = require("./utils");
const { analyzeManifest } = require("./manifestAnalyzer");
const { analyzeLua } = require("./luaAnalyzer");
const config = require("../config/config.json");
const { analyzeJS } = require("./jsAnalyzer");
const { analyzeHTML } = require("./htmlAnalyzer");
const { analyzeDLL } = require("./dllAnalyzer");

const EXCLUDED_PATH_SEGMENTS = [
  path.join("citizen", "clr2"),
];

const DLL_EXCLUDED_SEGMENTS = [
  ...EXCLUDED_PATH_SEGMENTS,
  "server-artifacts",
];

function isExcludedDLL(fullPath) {
  const normalized = fullPath.replace(/\\/g, "/");
  return DLL_EXCLUDED_SEGMENTS.some((seg) =>
    normalized.includes(seg.replace(/\\/g, "/"))
  );
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

function isDotFile(filePath) {
  return path.basename(filePath).startsWith(".");
}

function containsCitizenObfuscatedPattern(filePath) {
  if (!fs.existsSync(filePath)) return false;
  const content = fs.readFileSync(filePath, "utf-8");
  const regex = /\/\*\s*\[cfg\]\s*\*\/[\s\S]*function\s+_ro\(/;
  return regex.test(content);
}

function isInsideCitizenFolder(filePath) {
  const parts = filePath.split(path.sep);
  return parts.includes("citizen");
}

function containsFolderPattern(filePath) {
  if (!fs.existsSync(filePath)) return false;
  const content = fs.readFileSync(filePath, "utf-8");
  const parts = filePath.split(path.sep);
  const folders = parts.slice(0, -1);

  for (const folder of folders) {
    if (!folder) continue;
    const safeFolder = folder.replace(/[-\/\\^$*+?.()|[\]{}]/g, "\\$&");
    const regex = new RegExp(`/\\*\\[\\s*${safeFolder}\\s*\\]\\*/`, "i");
    if (regex.test(content)) {
      return {
        type: "folder_obfuscated_pattern",
        file: filePath,
        risk: "critical",
        reason: `El archivo contiene un comentario de ofuscación que coincide con la carpeta: [${folder}]`,
      };
    }
  }
  return false;
}

function containsObfuscatedGlobalThis(filePath) {
  if (!fs.existsSync(filePath)) return false;
  const content = fs.readFileSync(filePath, "utf-8");
  const regex = /globalThis\s*\[\s*\w+\s*\(\s*["'].*?["']\s*\)\s*\]/;
  return regex.test(content);
}

function containsSuspiciousStartPattern(filePath) {
  if (!fs.existsSync(filePath)) return false;
  const content = fs.readFileSync(filePath, "utf-8");
  return /^\s*\/\*\s*\[/.test(content);
}

function isInsideHiddenFolder(filePath) {
  const parts = filePath.split(path.sep);
  let current = parts[0];
  for (let i = 1; i < parts.length; i++) {
    current = path.join(current, parts[i]);
    if (isWindowsHidden(current)) return true;
  }
  return false;
}

function scan(root) {
  const issues = [];
  let scannedFiles = 0;

  walk(root, (fullPath, isDir) => {
    const name = path.basename(fullPath);

    if (fullPath.split(path.sep).includes("node_modules")) return;

    if (isDir) {
      if (isWindowsHidden(fullPath)) {
        issues.push({
          type: "hidden_folder",
          file: fullPath,
          risk: "critical",
          reason: "Carpeta ocultada con attrib +h +s",
        });
      }
      return;
    }

    scannedFiles++;

    if (name.endsWith(".net.dll")) {
      if (isExcludedDLL(fullPath)) return;

      const dllIssues = analyzeDLL(fullPath);
      const relevant = dllIssues.filter((i) => i.risk !== "info");
      if (relevant.length > 0) {
        issues.push(...relevant);
      }
      return;
    }

    if (name.endsWith(".lua") && isInsideHiddenFolder(fullPath)) {
      issues.push({
        type: "lua_in_hidden_folder",
        file: fullPath,
        risk: "critical",
        reason: "Archivo Lua dentro de carpeta ocultada con attrib +h +s",
      });
    }

    if (
      (name.endsWith(".js") || name.endsWith(".lua")) &&
      containsObfuscatedGlobalThis(fullPath)
    ) {
      issues.push({
        type: "obfuscated_globalThis",
        file: fullPath,
        risk: "critical",
        reason:
          "Archivo contiene globalThis con código ofuscado (posible backdoor)",
      });
    }

    if (name === "fxmanifest.lua") {
      let manifestIssues = analyzeManifest(fullPath);
      manifestIssues = manifestIssues.map((issue) => {
        if (issue.jsPath) {
          const jsFullPath = path.resolve(path.dirname(fullPath), issue.jsPath);
          issue.jsFullPath = jsFullPath;
          issue.jsExists = fs.existsSync(jsFullPath);
        }
        return issue;
      });
      issues.push(...manifestIssues);
      return;
    }

    if (name.endsWith(".js")) {
      const jsIssues = analyzeJS(fullPath);
      if (jsIssues.length > 0) issues.push(...jsIssues);

      if (containsSuspiciousStartPattern(fullPath)) {
        issues.push({
          type: "js_suspicious_start",
          file: fullPath,
          risk: "critical",
          reason: "Archivo JS comienza con patrón sospechoso (/* [)",
        });
      }

      if (isInsideCitizenFolder(fullPath) && containsCitizenObfuscatedPattern(fullPath)) {
        issues.push({
          type: "citizen_obfuscated_js",
          file: fullPath,
          risk: "critical",
          reason:
            "Archivo JS en carpeta 'citizen' contiene patrón ofuscado sospechoso",
        });
      }

      if (isWindowsHidden(fullPath) || isDotFile(fullPath)) {
        issues.push({
          type: "hidden_js_file",
          file: fullPath,
          risk: "critical",
          reason:
            "Archivo JS oculto o con nombre sospechoso (empieza con .)",
        });
      }
    }

    if (name.endsWith(".lua")) {
      if (containsFolderPattern(fullPath)) {
        issues.push({
          type: "folder_obfuscated_pattern",
          file: fullPath,
          risk: "critical",
          reason:
            "Archivo contiene patrón ofuscado que coincide con alguna carpeta de su ruta",
        });
        return;
      }
      issues.push(...analyzeLua(fullPath, config));
    }

    if (name.endsWith(".html")) {
      const htmlIssues = analyzeHTML(fullPath);
      if (htmlIssues.length > 0) issues.push(...htmlIssues);
    }
  });

  const seen = new Map();
  for (const issue of issues) {
    const key = [issue.type, issue.file, issue.jsPath || "", issue.reason].join("|");
    if (!seen.has(key)) seen.set(key, issue);
  }

  return {
    summary: {
      scannedFiles,
      totalIssues: seen.size,
    },
    issues: Array.from(seen.values()),
  };
}

module.exports = { scan };