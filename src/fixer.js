const fs = require("fs");
const path = require("path");

const OBFUSCATION = [
  /eval\s*\(/i,
  /String\.fromCharCode/i,
  /\\u[0-9a-fA-F]{4}/,
  /\^ *\d+/
];

function applyFixes(report) {
  report.issues
    .filter(i => i.type === "manifest_backdoor")
    .forEach(issue => {
      const manifest = issue.file;
      const lines = fs.readFileSync(manifest, "utf8").split(/\r?\n/);

      fs.writeFileSync(manifest + ".bak", lines.join("\n"));

      lines[issue.line - 1] = "";
      fs.writeFileSync(manifest, lines.join("\n"));
      console.log("🧹 fxmanifest limpiado:", manifest);

      const jsFile = path.resolve(path.dirname(manifest), issue.jsPath);
      removeJS(jsFile);
    });
}

function removeJS(jsFile) {
  if (!fs.existsSync(jsFile)) return;

  const content = fs.readFileSync(jsFile, "utf8");
  const obfuscated = OBFUSCATION.some(r => r.test(content));

  console.log(
    obfuscated
      ? "🧨 JS malicioso eliminado:"
      : "⚠️ JS sospechoso eliminado:",
    jsFile
  );

  fs.unlinkSync(jsFile);
  cleanup(path.dirname(jsFile));
}

function cleanup(dir) {
  if (!fs.existsSync(dir)) return;
  if (fs.readdirSync(dir).length === 0) {
    fs.rmdirSync(dir);
    cleanup(path.dirname(dir));
  }
}

module.exports = { applyFixes };
