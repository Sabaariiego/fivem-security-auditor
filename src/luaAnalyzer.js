const fs = require("fs");

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
    const regex = new RegExp(pattern.regex, "i");

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

  return issues;
}

module.exports = { analyzeLua };
