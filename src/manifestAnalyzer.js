const fs = require("fs");

function analyzeManifest(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  const lines = content.split(/\r?\n/);
  const issues = [];

  let insideServerScripts = false;

  lines.forEach((line, index) => {
    const trimmed = line.trim();

    if (/^server_scripts\s*\{/.test(trimmed)) {
      insideServerScripts = true;
      return;
    }

    if (insideServerScripts && trimmed.startsWith("}")) {
      insideServerScripts = false;
      return;
    }

    if (!insideServerScripts) return;

    const hasLuaCommentBlock =
      trimmed.includes("--[[") && trimmed.includes("]]");

    const jsMatch = trimmed.match(/['"]([^'"]+\.js)['"]/i);

    if (hasLuaCommentBlock && jsMatch) {
      const jsPath = jsMatch[1];

      issues.push({
        type: "manifest_backdoor",
        file: filePath,
        line: index + 1,
        jsPath,
        risk: "critical",
        reason:
          "JS oculto dentro de server_scripts usando comentario Lua (--[[ ]])"
      });
    }
  });

  return issues;
}

module.exports = { analyzeManifest };
