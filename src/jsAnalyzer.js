const fs = require("fs");

function getLineNumber(content, index) {
  return content.slice(0, index).split("\n").length;
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
  const normalized = content
  .toLowerCase()
  .replace(/\s+/g, "");


  const usesFsPromises =
    normalized.includes("require('fs').promises") ||
    normalized.includes('require("fs").promises');

  const usesPath =
    normalized.includes("require('path')") ||
    normalized.includes('require("path")');

  const usesGlobalExports =
    normalized.includes("global.exports(");

  const accessesPlayersDB =
    normalized.includes("playersdb.json") ||
    (
      normalized.includes("txdata") &&
      normalized.includes("default") &&
      normalized.includes("data") &&
      normalized.includes("playersdb.json")
    );

  if (
    usesFsPromises &&
    usesPath &&
    usesGlobalExports &&
    accessesPlayersDB
  ) {
    return {
      type: "txadmin_playersdb_export",
      file: filePath,
      risk: "critical",
      reason:
        "Export expone acceso a playersDB.json de txAdmin (txData) mediante filesystem"
    };
  }

  return null;
}


function analyzeJS(filePath) {
  if (!fs.existsSync(filePath)) return [];

  const content = fs.readFileSync(filePath, "utf-8");
  const issues = [];
  const normalizedPath = filePath.replace(/\\/g, "/");

  const customfilter =
    normalizedPath.includes("/yarn/") ||
    normalizedPath.includes("/screenshot-basic/") ||
    normalizedPath.includes("/monitor/") ||
    normalizedPath.includes("/monitor/core/");

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
          reason: "Exporta acceso completo al sistema de archivos del recurso"
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


  const cleanContent = content.replace(/['"\s+]/g, "");

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
    if (cleanContent.includes(threat.pattern.replace(/['"\s+]/g, ""))) {
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
    /\.on\s*\(\s*['"]da['"]\s*\+\s*['"]ta['"]|\['\\x6f\\x6e'\]/i;

  const vmViaCharCode =
    /require\s*\(\s*['"]\\x76\\x6d['"]\s*\)|String\.fromCharCode\s*\(/i;

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


  const globalThisDynamicRegex =
    /globalThis\s*\[\s*[a-zA-Z_$][\w$]*\s*\(/;

  if (!customfilter && globalThisDynamicRegex.test(content)) {
    issues.push({
      type: "dynamic_global_loader",
      file: filePath,
      risk: "critical",
      reason:
        "Uso de globalThis con clave dinámica (loader/backdoor típico)",
    });
  }

  const evalRegex = /\beval\s*\(/;
  const unicodeRegex = /\\u[0-9a-fA-F]{4}/;
  const xorRegex = /\^\s*\d+/;

  if (
    !customfilter &&
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
    } else if (!customfilter) {
      issues.push({
        type: "heavily_obfuscated_script",
        file: filePath,
        risk: "warning",
        reason:
          "Script fuertemente ofuscado (posible evasión de análisis)",
      });
    }
  }

  return issues;
}

module.exports = { analyzeJS };
