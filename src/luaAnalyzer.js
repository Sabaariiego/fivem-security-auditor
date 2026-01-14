const fs = require("fs");

function analyzeLua(filePath, patterns = { dangerousLuaCalls: [] }) {
  const content = fs.readFileSync(filePath, "utf8");
  const issues = [];

  (patterns.dangerousLuaCalls || []).forEach(call => {
    if (content.includes(call)) {
      issues.push({
        type: "lua_risk",
        file: filePath,
        risk: "warning",
        reason: `Uso de función sensible (${call})`
      });
    }
  });

  return issues;
}


module.exports = { analyzeLua };
