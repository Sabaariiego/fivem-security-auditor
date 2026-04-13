const fs = require("fs");

function getLineNumber(content, index) {
  return content.slice(0, index).split("\n").length;
}

function detectBundlerFingerprint(content, normalizedPath) {
  const isNextJs =
    content.includes("__NEXT_DATA__") ||
    content.includes("next/dist/") ||
    content.includes("__nextjs_") ||
    (content.includes("__webpack_require__") &&
      (content.includes("/_next/") || content.includes("next-server")));

  const isVite =
    content.includes("import.meta.env.") ||
    content.includes("__vite_ssr_import__") ||
    content.includes("__vite_ssr_dynamic_import__") ||
    (content.includes("createRequire") && content.includes("import.meta.url")) ||
    normalizedPath.includes("/.vite/") ||
    normalizedPath.includes("/vite/");

  const isWebpack =
    !isNextJs &&
    (content.includes("__webpack_require__") ||
      content.includes("webpackChunk") ||
      content.includes("webpackJsonp"));

  const isRollup =
    /\/\*\*?\s*@license\s[\s\S]{0,200}rollup/i.test(content) ||
    content.includes("/*! rollup") ||
    /Object\.defineProperty\(exports,\s*["']__esModule["']/i.test(content.slice(0, 500));

  const isEsbuild =
    content.includes("// node_modules/") &&
    /var \w+ = __toESM\(require\(/.test(content);

  const isBuildFolder =
    normalizedPath.includes("/.next/") ||
    normalizedPath.includes("/__sapper__/") ||
    normalizedPath.includes("/nuxt/") ||
    (normalizedPath.includes("/dist/") && (isNextJs || isVite || isWebpack || isRollup || isEsbuild)) ||
    (normalizedPath.includes("/build/") && (isNextJs || isVite || isWebpack));

  if (isNextJs) return "nextjs";
  if (isVite) return "vite";
  if (isWebpack) return "webpack";
  if (isRollup) return "rollup";
  if (isEsbuild) return "esbuild";
  if (isBuildFolder) return "build_folder";
  return null;
}

function checkTxAdminIntegrity(filePath, content) {
  const normalizedPath = filePath.replace(/\\/g, "/");

  const isInMonitorResource =
    normalizedPath.includes("/monitor/") && normalizedPath.endsWith(".js");

  if (!isInMonitorResource) return null;

  const hexArrayRegex = /const\s+_0x[a-f0-9]+\s*=\s*\[/i;
  const hexShiftRegex = /\(function\(_0x[a-f0-9]+,\s*_0x[a-f0-9]+\)\{/i;

  if (hexArrayRegex.test(content) && hexShiftRegex.test(content)) {
    return {
      type: "critical_core_injection",
      file: filePath,
      risk: "critical",
      reason:
        "Se detectó código ofuscado inyectado en un archivo del recurso txAdmin (monitor).",
    };
  }

  return null;
}

function checkTxAdminPlayersDBExport(filePath, content) {
  const stripped = content
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");
  const normalized = stripped.toLowerCase().replace(/\s+/g, "");

  const usesFsPromises =
    normalized.includes("require('fs').promises") ||
    normalized.includes('require("fs").promises');

  const usesPath =
    normalized.includes("require('path')") ||
    normalized.includes('require("path")');

  const usesGlobalExports = normalized.includes("global.exports(");

  const accessesPlayersDB =
    normalized.includes("playersdb.json") ||
    (normalized.includes("txdata") &&
      normalized.includes("default") &&
      normalized.includes("data") &&
      normalized.includes("playersdb.json"));

  if (usesFsPromises && usesPath && usesGlobalExports && accessesPlayersDB) {
    return {
      type: "txadmin_playersdb_export",
      file: filePath,
      risk: "critical",
      reason:
        "Export expone acceso a playersDB.json de txAdmin (txData) mediante filesystem",
    };
  }

  return null;
}

function analyzeJS(filePath) {
  if (!fs.existsSync(filePath)) return [];

  const content = fs.readFileSync(filePath, "utf-8");
  const issues = [];
  const normalizedPath = filePath.replace(/\\/g, "/");

  const bundler = detectBundlerFingerprint(content, normalizedPath);
  const isBundlerBuild = bundler !== null;

  const isLegacyFiltered =
    normalizedPath.includes("/yarn/") ||
    normalizedPath.includes("/screenshot-basic/") ||
    normalizedPath.includes("/monitor/") ||
    normalizedPath.includes("/monitor/core/");

  const customfilter = isLegacyFiltered || isBundlerBuild;

  const normalizedContent = content.replace(/\s+/g, "");

  if (
    normalizedContent.includes("global.exports") &&
    normalizedContent.includes("fs.") &&
    normalizedContent.includes("GetResourcePath")
  ) {
    const safeOrigenPolice =
      normalizedContent.includes('GetResourcePath("origen_police")') ||
      normalizedContent.includes("GetResourcePath('origen_police')");

    if (!safeOrigenPolice) {
      issues.push({
        type: "filesystem_export_backdoor",
        file: filePath,
        risk: "critical",
        reason: "Exporta acceso completo al sistema de archivos del recurso",
      });
    }
  }

  const txCheck = checkTxAdminIntegrity(filePath, content);
  if (txCheck && txCheck.risk === "critical") {
    return [txCheck];
  }

  const txPlayersDBExport = checkTxAdminPlayersDBExport(filePath, content);
  if (txPlayersDBExport) {
    return [txPlayersDBExport];
  }

  const cleanContent = content.replace(/['"\\s+]/g, "");

  const threats = [
    {
      pattern: "cipher-panel.me",
      name: "Cipher Panel Backdoor (Domain)",
      risk: "critical",
    },
    {
      pattern: "Authentic777/Socket.io",
      name: "Authentic777 Socket Bundle (Malicious Loader)",
      risk: "critical",
    },
    {
      pattern: "https://bookshopa.org",
      name: "Cipher Panel Malicious Host",
      risk: "critical",
    },
  ];

  for (const threat of threats) {
    if (cleanContent.includes(threat.pattern.replace(/['"\\s+]/g, ""))) {
      issues.push({
        type: "js_backdoor_signature",
        file: filePath,
        risk: threat.risk,
        reason: `Detectado patrón ofuscado conocido: ${threat.name}`,
      });
    }
  }

  if (cleanContent.includes("/ojj")) {
    issues.push({
      type: "js_backdoor_signature",
      file: filePath,
      risk: "critical",
      reason: "Detectado endpoint malicioso con patrón Cipher Panel (/OJJ)",
    });
  }

  const dynamicHttpsRequire =
    /require\s*\(\s*['"]htt['"]\s*\+\s*['"]ps['"]\s*\)/i;

  const base64StringDecode =
    /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]+['"]\s*,\s*['"]base64['"]\s*\)\.toString/i;

  const streamCollector =
    /\.on\s*\(\s*['"]da['"]\s*\+\s*['"]ta['"]|\['\x6f\x6e'\]/i;

  const vmViaCharCode =
    /require\s*\(\s*['"]\x76\x6d['"]\s*\)|String\.fromCharCode\s*\(/i;

  const httpsMatch = content.match(dynamicHttpsRequire);

  if (
    httpsMatch &&
    base64StringDecode.test(content) &&
    streamCollector.test(content) &&
    vmViaCharCode.test(content)
  ) {
    const line = getLineNumber(content, httpsMatch.index);
    issues.push({
      type: "remote_vm_loader",
      file: filePath,
      line,
      risk: "critical",
      reason:
        "Backdoor Node.js detectado: descarga código remoto y lo ejecuta dinámicamente (HTTPS + base64 + VM ofuscado)",
    });
  }

  if (!customfilter) {
    const globalThisDynamicRegex =
      /globalThis\s*\[\s*[a-zA-Z_$][\w$]*\s*\(/;

    if (globalThisDynamicRegex.test(content)) {
      issues.push({
        type: "dynamic_global_loader",
        file: filePath,
        risk: "critical",
        reason: "Uso de globalThis con clave dinámica (loader/backdoor típico)",
      });
    }

    const evalRegex = /\beval\s*\(/;
    const unicodeRegex = /\\u[0-9a-fA-F]{4}/;
    const xorRegex = /\^\s*\d+/;

    if (
      evalRegex.test(content) &&
      unicodeRegex.test(content) &&
      xorRegex.test(content)
    ) {
      issues.push({
        type: "obfuscated_eval_loader",
        file: filePath,
        risk: "critical",
        reason:
          "Loader ofuscado con eval + unicode + XOR (ejecución dinámica maliciosa)",
      });
    }

    const intArrayRegex = /const\s+\w+\s*=\s*\[\s*\d+\s*,\s*\d+\s*,\s*\d+/;
    const xorFuncRegex = /String\.fromCharCode\s*\(\s*\w+\[[\w]+\]\s*\^\s*\w+\s*\)/;

    if (evalRegex.test(content) && intArrayRegex.test(content) && xorFuncRegex.test(content)) {
      issues.push({
        type: "obfuscated_eval_loader",
        file: filePath,
        risk: "critical",
        reason: "Loader ofuscado con array de enteros + XOR + eval (ejecución dinámica maliciosa)",
      });
    }

    const hexArrayRegex = /const\s+_0x[a-f0-9]+\s*=\s*\[/i;
    const hexShiftRegex = /\(function\(_0x[a-f0-9]+,\s*_0x[a-f0-9]+\)\{/i;

    if (hexArrayRegex.test(content) && hexShiftRegex.test(content)) {
      const hasNetwork =
        cleanContent.includes("http") ||
        cleanContent.includes("performhttprequest");

      if (hasNetwork) {
        issues.push({
          type: "heavily_obfuscated_network_script",
          file: filePath,
          risk: "critical",
          reason:
            "Script fuertemente ofuscado con capacidades de red (estructura Javascript-Obfuscator)",
        });
      } else {
        issues.push({
          type: "heavily_obfuscated_script",
          file: filePath,
          risk: "warning",
          reason: "Script fuertemente ofuscado (posible evasión de análisis)",
        });
      }
    }
  }

  if (isBundlerBuild && issues.length > 0) {
    issues.forEach((i) => {
      i.bundlerContext = bundler;
      i.note = `Detectado dentro de un build de ${bundler} — confirmar manualmente`;
    });
  }

  return issues;
}

module.exports = { analyzeJS };