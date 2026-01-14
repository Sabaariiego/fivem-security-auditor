const fs = require("fs");
const path = require("path");

function walk(dir, cb) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      cb(full, true);
      walk(full, cb);
    } else {
      cb(full, false);
    }
  }
}

module.exports = { walk };
