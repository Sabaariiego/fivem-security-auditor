const fs = require("fs");

function detectSingleLineLuaBackdoor(filePath, content) {
  const singleLineBackdoorRegex =
    /;\(\(function\(\).*?gsub\("\.\."\s*,\s*function\(h\).*?tonumber\(h,16\).*?_G\[[^\]]+\]\(\).*?end\)\(\)\s*end\s*or\s*function\(\);\(function\(/i;

  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    if (singleLineBackdoorRegex.test(line)) {
      return {
        type: "lua_single_line_obfuscated_backdoor",
        file: filePath,
        risk: "critical",
        reason:
          "Backdoor Lua ofuscado en una sola línea con ejecución remota (firma conocida)"
      };
    }
  }

  return null;
}

function analyzeLua(filePath, patterns = {}) {
  const content = fs.readFileSync(filePath, "utf8");
  const issues = [];

  (patterns.dangerousLuaCalls || []).forEach(call => {
    if (content.includes(call)) {
      issues.push({
        type: "lua_dangerous_call",
        file: filePath,
        risk: "warning",
        reason: `Uso de función sensible (${call})`
      });
    }
  });

  (patterns.extendedPatterns || []).forEach(pattern => {
    const regex = new RegExp(pattern.regex, "is"); 

    if (regex.test(content)) {
      issues.push({
        type: "lua_extended_pattern",
        file: filePath,
        risk: pattern.risk || "warning",
        reason: pattern.reason,
        name: pattern.name
      });
    }
  });

  const singleLineBackdoor = detectSingleLineLuaBackdoor(filePath, content);
  if (singleLineBackdoor) {
    issues.push(singleLineBackdoor);
  }

  return issues;
}

module.exports = { analyzeLua };
