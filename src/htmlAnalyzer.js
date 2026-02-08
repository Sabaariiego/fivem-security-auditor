const fs = require("fs");

function extractInlineScripts(html) {
  const scripts = [];
  const regex = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  let match;

  while ((match = regex.exec(html)) !== null) {
    if (match[1] && match[1].trim().length > 0) {
      scripts.push(match[1]);
    }
  }

  return scripts;
}

function detectHtmlNuiEvalBackdoor(filePath, htmlContent) {
  const scripts = extractInlineScripts(htmlContent);

  for (const script of scripts) {
    let score = 0;

    if (/window\.addEventListener\s*\(\s*['"]message['"]/.test(script)) score++;
    if (/\beval\s*\(/.test(script)) score++;
    if (/String\.fromCharCode\s*\(/i.test(script)) score++;
    if (/GetParentResourceName\s*\(/i.test(script)) score++;
    if (/fetch\s*\(\s*`https?:\$\{GetParentResourceName/.test(script)) score++;

    if (
      /['"]eval['"]/.test(script) ||
      /fromCharCode\s*\(\s*116\s*,\s*121\s*,\s*112\s*,\s*101\s*\)/.test(script)
    ) {
      score++;
    }

    if (score >= 4) {
      return {
        type: "html_nui_eval_backdoor",
        file: filePath,
        risk: "critical",
        reason:
          "Backdoor NUI en HTML: ejecución remota vía postMessage + eval (RCE)"
      };
    }
  }

  return null;
}

function analyzeHTML(filePath) {
  const issues = [];
  const content = fs.readFileSync(filePath, "utf8");

  const backdoor = detectHtmlNuiEvalBackdoor(filePath, content);
  if (backdoor) {
    issues.push(backdoor);
  }

  return issues;
}

module.exports = { analyzeHTML };
