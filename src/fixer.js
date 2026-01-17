const fs = require("fs");
const path = require("path");

const OBFUSCATION = [
  /eval\s*\(/i,
  /String\.fromCharCode/i,
  /\\u[0-9a-fA-F]{4}/,
  /\^ *\d+/,
  /globalThis\s*\[.*?\]/
];

function applyFixes(report) {
  console.log("Aplicando fixes a", report.issues.length, "issues");

  report.issues.forEach(issue => {
    console.log("Fix:", issue.type, issue.file);

    switch (issue.type) {
      case "manifest_backdoor":
        fixManifest(issue);
        break;

      case "citizen_obfuscated_js":
      case "folder_obfuscated_pattern":
      case "obfuscated_globalThis":
      case "lua_in_hidden_folder":
        removeFile(issue.file);
        break;
      case "hidden_folder":
        removeFolder(issue.file);
        break;
    }
  });
}

function fixManifest(issue) {
  const manifest = issue.file;
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
}


function removeFile(file) {
  if (!file || !fs.existsSync(file)) return;

  console.log("Archivo eliminado:", file);
  fs.unlinkSync(file);
  cleanup(path.dirname(file));
}

function cleanup(dir) {
  if (!fs.existsSync(dir)) return;
  if (fs.readdirSync(dir).length === 0) {
    fs.rmdirSync(dir);
    cleanup(path.dirname(dir));
  }
}


function removeFolder(dir) {
  if (!dir || !fs.existsSync(dir)) return;

  fs.readdirSync(dir).forEach(file => {
    const fullPath = path.join(dir, file);
    if (fs.lstatSync(fullPath).isDirectory()) {
      removeFolder(fullPath);
    } else {
      fs.unlinkSync(fullPath);
      console.log("Archivo eliminado:", fullPath);
    }
  });

  fs.rmdirSync(dir);
  console.log("Carpeta eliminada:", dir);

  const parent = path.dirname(dir);
  if (fs.existsSync(parent) && fs.readdirSync(parent).length === 0) {
    removeFolder(parent);
  }
}

module.exports = { applyFixes };
