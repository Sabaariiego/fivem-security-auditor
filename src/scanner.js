const fs = require("fs");
const path = require("path");
const winattr = require("winattr");
const { walk } = require("./utils");
const { analyzeManifest } = require("./manifestAnalyzer");
const { analyzeLua } = require("./luaAnalyzer");

function isWindowsHidden(filePath) {
  if (!fs.existsSync(filePath)) return false;
  try {
    const attr = winattr.getSync(filePath);
    return attr.hidden && attr.system;
  } catch {
    return false;
  }
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

function escapeRegex(str) {
  return str.replace(/[-\/\\^$*+?.()|[\]{}]/g, "\\$&");
}

function containsFolderPatternAndRemove(filePath) {
  if (!fs.existsSync(filePath)) return false;

  const content = fs.readFileSync(filePath, "utf-8");
  const parts = filePath.split(path.sep);
  const folders = parts.slice(0, -1); // todas las carpetas menos el archivo

  for (const folder of folders) {
    if (!folder) continue;

    // Construimos regex que ignore espacios y sea insensible a mayúsculas
    const safeFolder = folder.replace(/[-\/\\^$*+?.()|[\]{}]/g, "\\$&");
    const regex = new RegExp(`/\\*\\[\\s*${safeFolder}\\s*\\]\\*/`, "i");

    if (regex.test(content)) {
      try {
        fs.unlinkSync(filePath);
        console.log("Archivo eliminado:", filePath);
      } catch (err) {
        console.error("No se pudo borrar el archivo:", filePath, err);
      }
      return true;
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

function isInsideHiddenFolder(filePath) {
  const parts = filePath.split(path.sep);
  let current = parts[0];

  for (let i = 1; i < parts.length; i++) {
    current = path.join(current, parts[i]);
    if (isWindowsHidden(current)) {
      return true;
    }
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

    if (
      name.endsWith(".js") &&
      isInsideCitizenFolder(fullPath) &&
      containsCitizenObfuscatedPattern(fullPath)
    ) {
      issues.push({
        type: "citizen_obfuscated_js",
        file: fullPath,
        risk: "critical",
        reason:
          "Archivo JS en carpeta 'citizen' contiene patrón ofuscado sospechoso",
      });
    }

    if (
      (name.endsWith(".js") || name.endsWith(".lua")) &&
      containsFolderPatternAndRemove(fullPath)
    ) {
      issues.push({
        type: "folder_obfuscated_pattern",
        file: fullPath,
        risk: "critical",
        reason:
          "Archivo contiene patrón ofuscado que coincide con alguna carpeta de su ruta y ha sido eliminado",
      });
      return;
    }

    if (name.endsWith(".lua")) {
      issues.push(...analyzeLua(fullPath));
    }
  });

  const uniqueIssues = new Map();
  for (const issue of issues) {
    const key = [issue.type, issue.file, issue.jsPath || "", issue.reason].join(
      "|"
    );
    if (!uniqueIssues.has(key)) uniqueIssues.set(key, issue);
  }

  return {
    summary: {
      scannedFiles,
      totalIssues: uniqueIssues.size,
    },
    issues: Array.from(uniqueIssues.values()),
  };
}

module.exports = { scan };
