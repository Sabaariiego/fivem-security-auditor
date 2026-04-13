const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

function extractStrings(buffer, precomputedBin, minLen = 5) {
  const results = new Set();

  const bin = precomputedBin || buffer.toString("binary");
  const asciiRegex = /[\x20-\x7E]{5,}/g;
  let m;
  while ((m = asciiRegex.exec(bin)) !== null) {
    results.add(m[0]);
  }

  let u16 = [];
  for (let i = 0; i < buffer.length - 1; i += 2) {
    const code = buffer.readUInt16LE(i);
    if (code >= 0x20 && code < 0x7f) {
      u16.push(String.fromCharCode(code));
    } else {
      if (u16.length >= minLen) results.add(u16.join(""));
      u16 = [];
    }
  }

  return [...results];
}

function tryIlspy(filePath) {
  try {
    const r = spawnSync("ilspycmd", [filePath], {
      timeout: 15000,
      maxBuffer: 2 * 1024 * 1024,
    });
    if (r.status === 0 && r.stdout) {
      return r.stdout.toString("utf-8");
    }
  } catch {}
  return null;
}

const RULES = [
  {
    pattern: /controlx_dll_owner/i,
    label: "Firma exacta del backdoor Monitor.net (controlx_dll_owner)",
    risk: "critical",
    category: "known_backdoor",
  },
  {
    pattern: /RegisterFileHandlers/i,
    label: "Método RegisterFileHandlers — patrón del backdoor Monitor.net",
    risk: "critical",
    category: "known_backdoor",
  },
  {
    pattern: /cipher-panel\.me|bookshopa\.org/i,
    label: "Dominio C2 conocido (cipher-panel / bookshopa)",
    risk: "critical",
    category: "known_backdoor",
  },
  {
    pattern: /Authentic777/i,
    label: "Firma Authentic777 Socket (loader malicioso conocido)",
    risk: "critical",
    category: "known_backdoor",
  },

  {
    pattern: /Process\.Start|ProcessStartInfo/i,
    label: "Ejecución de procesos del sistema operativo",
    risk: "critical",
    category: "rce",
  },
  {
    pattern: /cmd\.exe|powershell\.exe|\/bin\/sh|\/bin\/bash/i,
    label: "Referencia a shell del sistema (cmd/PowerShell/bash)",
    risk: "critical",
    category: "rce",
  },
  {
    pattern: /Assembly\.Load(From|File)?/i,
    label: "Carga dinámica de ensamblado en tiempo de ejecución",
    risk: "critical",
    category: "rce",
  },

  {
    pattern: /Directory\.Delete/i,
    label: "Borrado recursivo de directorios",
    risk: "critical",
    category: "filesystem",
  },
  {
    pattern: /File\.(ReadAll|WriteAll)Bytes/i,
    label: "Lectura/escritura binaria arbitraria de archivos",
    risk: "warning",
    category: "filesystem",
  },
  {
    pattern: /Convert\.(FromBase64|ToBase64)String/i,
    label: "Codificación Base64 en runtime (transferencia de binarios)",
    risk: "warning",
    category: "filesystem",
  },

  {
    pattern: /discord\.com\/api\/webhooks/i,
    label: "Webhook de Discord (posible exfiltración de datos)",
    risk: "critical",
    category: "network",
  },
  {
    pattern: /HttpClient|WebClient|HttpWebRequest/i,
    label: "Cliente HTTP .NET (conexiones salientes)",
    risk: "warning",
    category: "network",
  },
  {
    pattern: /TcpClient|UdpClient|new Socket/i,
    label: "Sockets TCP/UDP crudos (posible canal C2 directo)",
    risk: "warning",
    category: "network",
  },

  {
    pattern: /SkipVerification/i,
    label: "SkipVerification — evasión de verificación del CLR",
    risk: "critical",
    category: "evasion",
  },
  {
    pattern: /Reflection\.Emit|ILGenerator/i,
    label: "Generación dinámica de IL en runtime",
    risk: "critical",
    category: "evasion",
  },
  {
    pattern: /DynamicMethod/i,
    label: "DynamicMethod — ejecución de código generado en memoria",
    risk: "warning",
    category: "evasion",
  },

  {
    pattern: /TriggerEvent\b/i,
    label: "TriggerEvent — interacción con otros recursos FiveM",
    risk: "info",
    category: "fivem",
  },
  {
    pattern: /GetConvar|SetConvar/i,
    label: "GetConvar/SetConvar — manipulación de variables del servidor",
    risk: "warning",
    category: "fivem",
  },
  {
    pattern: /BaseScript/i,
    label: "Hereda de BaseScript (recurso server-side FiveM)",
    risk: "info",
    category: "fivem",
  },
];

const COMBOS = [
  {
    requires: ["filesystem", "fivem", "network"],
    label: "Filesystem + red + FiveM (perfil de backdoor RAT completo)",
    risk: "critical",
    type: "dll_combo_rat",
  },
  {
    requires: ["rce", "fivem"],
    label: "Ejecución de comandos OS desde un recurso FiveM",
    risk: "critical",
    type: "dll_combo_rce_fivem",
  },
  {
    requires: ["evasion", "network"],
    label: "Ofuscación/evasión combinada con red (loader sigiloso)",
    risk: "critical",
    type: "dll_combo_evasion_network",
  },
];

function analyzeDLL(filePath) {
  if (!fs.existsSync(filePath)) {
    return [{
      type: "dll_not_found",
      file: filePath,
      risk: "warning",
      reason: "Archivo .dll no encontrado en disco",
    }];
  }

  const buffer = fs.readFileSync(filePath);

  const hasMZ  = buffer[0] === 0x4d && buffer[1] === 0x5a;
  const fullBin = buffer.toString("binary");
  const hasCLR  = fullBin.includes("mscoree") ||
                  fullBin.includes("mscorlib") ||
                  fullBin.includes("CitizenFX.Core");

  if (!hasMZ) {
    return [{
      type: "dll_invalid",
      file: filePath,
      risk: "warning",
      reason: "El archivo no tiene cabecera PE válida",
    }];
  }

  if (!hasCLR) {
    return [{
      type: "dll_native",
      file: filePath,
      risk: "warning",
      reason: "DLL nativo (no .NET). Los recursos FiveM usan .NET — este DLL es inusual. Revisión manual recomendada.",
    }];
  }

  const strings  = extractStrings(buffer, fullBin);
  const ilCode   = tryIlspy(filePath); // null si ilspycmd no está instalado
  const fullText = ilCode ? strings.join("\n") + "\n" + ilCode : strings.join("\n");

  const matched    = RULES.filter((r) => r.pattern.test(fullText));
  const categories = new Set(matched.map((r) => r.category));
  const issues     = [];

  const known = matched.filter((r) => r.category === "known_backdoor");
  if (known.length > 0) {
    issues.push({
      type: "dll_known_backdoor",
      file: filePath,
      risk: "critical",
      reason: `⚠️ FIRMA DE BACKDOOR CONOCIDO: ${known.map((r) => r.label).join(" | ")}`,
    });
    return issues;
  }

  for (const combo of COMBOS) {
    if (combo.requires.every((cat) => categories.has(cat))) {
      issues.push({
        type: combo.type,
        file: filePath,
        risk: combo.risk,
        reason: combo.label,
      });
    }
  }

  const criticals = matched.filter((r) => r.risk === "critical");
  const warnings  = matched.filter((r) => r.risk === "warning");

  if (criticals.length > 0 && issues.length === 0) {
    issues.push({
      type: "dll_critical_indicators",
      file: filePath,
      risk: "critical",
      reason: `DLL con capacidades críticas: ${criticals.map((r) => r.label).join(" | ")}`,
    });
  }

  if (warnings.length >= 2 && issues.length === 0) {
    issues.push({
      type: "dll_suspicious",
      file: filePath,
      risk: "warning",
      reason: `DLL con múltiples indicadores sospechosos (${warnings.length}): ${warnings.map((r) => r.label).join(" | ")}`,
    });
  }

  if (issues.length === 0) {
    issues.push({
      type: matched.length > 0 ? "dll_low_risk" : "dll_clean",
      file: filePath,
      risk: "info",
      reason: matched.length > 0
        ? `DLL .NET con ${matched.length} indicadores menores. Probablemente legítimo.`
        : "DLL .NET sin indicadores de riesgo detectados.",
    });
  }

  if (ilCode) issues.forEach((i) => (i.ilAnalyzed = true));

  return issues;
}

module.exports = { analyzeDLL };