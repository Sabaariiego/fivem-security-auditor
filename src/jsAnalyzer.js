const fs = require("fs");

function checkTxAdminIntegrity(filePath, content) {
    const normalizedPath = filePath.replace(/\\/g, '/');
    
    const isInMonitorResource = normalizedPath.includes('/monitor/') && normalizedPath.endsWith('.js');
    
    if (!isInMonitorResource) {
        return null;
    }

    const hexArrayRegex = /const\s+_0x[a-f0-9]+\s*=\s*\[/i;
    const hexShiftRegex = /\(function\(_0x[a-f0-9]+,\s*_0x[a-f0-9]+\)\{/i;
    const hasHexObfuscation = hexArrayRegex.test(content) && hexShiftRegex.test(content);

    if (hasHexObfuscation) {
        return {
            type: "critical_core_injection",
            file: filePath,
            risk: "critical",
            reason: "Se detectó código ofuscado inyectado en un archivo del recurso txAdmin (monitor)."
        };
    }

    return true;
}

function analyzeJS(filePath) {
  if (!fs.existsSync(filePath)) return [];

  const content = fs.readFileSync(filePath, "utf-8");

  const txCheck = checkTxAdminIntegrity(filePath, content);
  if (txCheck) {
      return [];
  }
    
  if (txCheck && txCheck.risk === "critical") {
    return [txCheck]; 
  }

  const issues = [];

  const cleanContent = content.replace(/['"\s+]/g, "");

  const threats = [
    {
      pattern: "cipher-panel.me",
      name: "Cipher Panel Backdoor (Domain)",
      risk: "critical"
    },
    {
      pattern: "Authentic777/Socket.io",
      name: "Authentic777 Socket Bundle (Malicious Loader)",
      risk: "critical"
    },
    {
      pattern: "https://bookshopa.org",
      name: "Cipher Panel Malicious Host",
      risk: "critical"
    }
  ];

  for (const threat of threats) {
    if (cleanContent.includes(threat.pattern.replace(/['"\s+]/g, ""))) {
      issues.push({
        type: "js_backdoor_signature",
        file: filePath,
        risk: threat.risk,
        reason: `Detectado patrón ofuscado conocido: ${threat.name}`
      });
    }
  }

  const globalThisDynamicRegex =
    /globalThis\s*\[\s*[a-zA-Z_$][\w$]*\s*\(/;

  if (globalThisDynamicRegex.test(content)) {
    issues.push({
      type: "dynamic_global_loader",
      file: filePath,
      risk: "critical",
      reason: "Uso de globalThis con clave dinámica (loader/backdoor típico)"
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
        "Loader ofuscado con eval + unicode + XOR (ejecución dinámica maliciosa)"
    });
  }

  const hexArrayRegex = /const\s+_0x[a-f0-9]+\s*=\s*\[/i;
  const hexShiftRegex = /\(function\(_0x[a-f0-9]+,\s*_0x[a-f0-9]+\)\{/i;

  if (hexArrayRegex.test(content) && hexShiftRegex.test(content)) {
    if (cleanContent.includes("http") || cleanContent.includes("performhttprequest")) {
      issues.push({
        type: "heavily_obfuscated_network_script",
        file: filePath,
        risk: "critical",
        reason:
          "Script fuertemente ofuscado con capacidades de red (estructura Javascript-Obfuscator)"
      });
    } else {
      issues.push({
        type: "heavily_obfuscated_script",
        file: filePath,
        risk: "warning",
        reason: "Script fuertemente ofuscado (posible evasión de análisis)"
      });
    }
  }

  return issues;
}

module.exports = { analyzeJS };