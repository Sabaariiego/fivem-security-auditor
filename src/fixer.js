const fs = require("fs");
const path = require("path");

function removeMaliciousInlineScript(filePath) {
  let content = fs.readFileSync(filePath, "utf8");

  const scriptRegex = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;

  content = content.replace(scriptRegex, (fullMatch, scriptContent) => {
    let score = 0;

    if (/window\.addEventListener\s*\(\s*['"]message['"]/.test(scriptContent)) score++;
    if (/\beval\s*\(/.test(scriptContent)) score++;
    if (/String\.fromCharCode\s*\(/i.test(scriptContent)) score++;
    if (/GetParentResourceName\s*\(/i.test(scriptContent)) score++;
    if (/fetch\s*\(/i.test(scriptContent)) score++;

    if (score >= 4) {
      return "";
    }

    return fullMatch;
  });

  fs.writeFileSync(filePath, content, "utf8");
}


function fixRemoteVMLoader(file) {
  if (!fs.existsSync(file)) return;

  let lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  let removed = 0;

  const suspiciousLine = /(htt['"]\s*\+\s*['"]ps|Buffer\.from|\\x6f\\x6e|String\.fromCharCode|\\x76\\x6d|runInThisContext)/i;

  lines = lines.filter(line => {
    if (suspiciousLine.test(line)) {
      removed++;
      return false; 
    }
    return true;
  });

  if (removed > 0) {
    fs.writeFileSync(file, lines.join("\n"));
    console.log(`✔ Loader remoto eliminado (${removed} líneas):`, file);
  } else {
    console.log(`⚠ No se encontraron líneas del loader en:`, file);
  }
}

function fixLuaSingleLineBackdoor(file) {
  if (!fs.existsSync(file)) return;

  const content = fs.readFileSync(file, "utf8");
  const lines = content.split(/\r?\n/);

  const backdoorSignature = /;\(\(function\(\).*?gsub\("\.\.".*?tonumber\(h,16\).*?_G\[.*?\]\(\).*?end\)\(\)\s*end\s*or\s*function\(\);\(function\(/i;

  let removed = 0;

  const cleaned = lines.filter(line => {
    if (backdoorSignature.test(line)) {
      removed++;
      return false;
    }
    return true;
  });

  if (removed > 0) {
    fs.writeFileSync(file, cleaned.join("\n"));
    console.log(`Backdoor Lua eliminado (${removed} línea):`, file);
  }
}



function applyFix(issue) {
  if (!issue.file || !fs.existsSync(issue.file)) {
    console.log(`[SKIP] El archivo ya no existe o ya fue procesado: ${issue.file}`);
    return;
  }

  console.log("Fix:", issue.type, issue.file);

  try {
    switch (issue.type) {
      case "manifest_backdoor":
        fixManifest(issue);
        break;

      case "remote_vm_loader":
        fixRemoteVMLoader(issue.file);
        break;

      case "citizen_obfuscated_js":
      case "folder_obfuscated_pattern":
      case "obfuscated_globalThis":
      case "lua_in_hidden_folder":
      case "js_suspicious_start":
      case "js_backdoor_signature":
      case "filesystem_export_backdoor":
      case "dynamic_global_loader":
      case "xor_eval_loader":
      case "heavily_obfuscated_network_script":
      case "hidden_js_file":
      case "txadmin_playersdb_export":
      case "critical_core_injection":
      case "obfuscated_eval_loader":
        removeFile(issue.file);
        break;

      case "hidden_folder":
        removeFolder(issue.file);
        break;

      case "lua_single_line_obfuscated_backdoor":
        fixLuaSingleLineBackdoor(issue.file);
        break;

      case "html_nui_eval_backdoor":
        removeMaliciousInlineScript(issue.file);
        break;

      case "dll_known_backdoor":
      case "dll_critical_indicators":
      case "dll_combo_rat":
      case "dll_combo_rce_fivem":
      case "dll_combo_evasion_network":
        removeFile(issue.file);
        break;

      case "manifest_dll_reference":
        fixManifestDll(issue);
        break;

      default:
        removeFile(issue.file);
        break;
    }
  } catch (err) {
    console.error(`[ERROR] No se pudo aplicar el fix en ${issue.file}:`, err.message);
  }
}

function applyFixes(report) {
  const criticalIssues = report.issues.filter(
    issue => issue.risk === "critical"
  );

  console.log(
    "Aplicando fixes a",
    criticalIssues.length,
    "issues críticas"
  );

  criticalIssues.forEach(applyFix);
}

function fixManifestDll(issue) {
  const manifest = issue.file;
  try {
    if (!fs.existsSync(manifest)) return;

    let lines = fs.readFileSync(manifest, "utf8").split(/\r?\n/);

    if (issue.dllPath) {
      const escaped = issue.dllPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const patterns = [
        new RegExp(`['"]${escaped}['"]\\s*,?`, "g"),
        new RegExp(`,\\s*['"]${escaped}['"]`, "g"),
      ];

      lines = lines.map(line => {
        let out = line;
        patterns.forEach(rx => { out = out.replace(rx, ""); });
        return out;
      });

      const dllFile = path.resolve(path.dirname(manifest), issue.dllPath);
      removeFile(dllFile);

      console.log("Referencia DLL eliminada del manifest:", issue.dllPath);
    }

    for (let i = 0; i < lines.length - 1; i++) {
      if (lines[i].trim().endsWith(",") && lines[i + 1].trim().startsWith("}")) {
        lines[i] = lines[i].replace(/,+\s*$/, "");
      }
    }

    fs.writeFileSync(manifest, lines.join("\n"));
    console.log("fxmanifest reparado (DLL eliminado):", manifest);
  } catch (err) {
    console.error("Error reparando manifest DLL:", err.message);
  }
}

function fixManifest(issue) {
  const manifest = issue.file;
  try {
    if (!fs.existsSync(manifest)) return;

    let lines = fs.readFileSync(manifest, "utf8").split(/\r?\n/);

    if (issue.jsPath) {
      const escaped = issue.jsPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const patterns = [
        new RegExp(`['"]${escaped}['"]\\s*,?`, "g"),
        new RegExp(`,\\s*['"]${escaped}['"]`, "g"),
        new RegExp(`${escaped}`, "g")
      ];

      lines = lines.map(line => {
        let out = line;
        let infected = false;
        patterns.forEach(rx => {
          if (rx.test(out)) infected = true;
          out = out.replace(rx, "");
        });
        if (infected) {
          out = out.replace(/--\[\[.*?\]\]/g, "").trim();
        }
        return out;
      });

      console.log("Script eliminado del manifest:", issue.jsPath);

      const jsFile = path.resolve(path.dirname(manifest), issue.jsPath);
      removeFile(jsFile);
    }

    for (let i = 0; i < lines.length - 1; i++) {
      if (
        lines[i].trim().endsWith(",") &&
        lines[i + 1].trim().startsWith("}")
      ) {
        lines[i] = lines[i].replace(/,+\s*$/, "");
      }
    }

    fs.writeFileSync(manifest, lines.join("\n"));
    console.log("fxmanifest reparado correctamente:", manifest);
  } catch (err) {
    console.error("Error reparando manifest:", err.message);
  }
}

function removeFile(file) {
  try {
    if (!file || !fs.existsSync(file)) return;

    if (fs.lstatSync(file).isFile()) {
      fs.unlinkSync(file);
      console.log("Archivo eliminado:", file);
    }
    
    cleanup(path.dirname(file));
  } catch (err) {
    console.error(`Error eliminando archivo ${file}:`, err.message);
  }
}

function cleanup(dir) {
  try {
    if (!dir || !fs.existsSync(dir)) return;
    
    if (fs.readdirSync(dir).length === 0) {
      fs.rmdirSync(dir);
      console.log("Carpeta vacía eliminada:", dir);
      cleanup(path.dirname(dir));
    }
  } catch (err) {
  }
}

function removeFolder(dir) {
  try {
    if (!dir || !fs.existsSync(dir)) return;

    if (!fs.lstatSync(dir).isDirectory()) {
        return removeFile(dir);
    }

    fs.readdirSync(dir).forEach(file => {
      const fullPath = path.join(dir, file);
      try {
          if (fs.lstatSync(fullPath).isDirectory()) {
            removeFolder(fullPath);
          } else {
            fs.unlinkSync(fullPath);
            console.log("Archivo eliminado dentro de carpeta:", fullPath);
          }
      } catch (e) {}
    });

    if (fs.existsSync(dir)) {
        fs.rmdirSync(dir);
        console.log("Carpeta eliminada:", dir);
    }

    const parent = path.dirname(dir);
    if (parent && fs.existsSync(parent) && fs.readdirSync(parent).length === 0) {
      removeFolder(parent);
    }
  } catch (err) {
    console.error(`Error eliminando carpeta ${dir}:`, err.message);
  }
}

module.exports = { applyFixes, applyFix };