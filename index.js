const fs = require("fs");
const path = require("path");
const scanner = require("./src/scanner");
const fixer = require("./src/fixer");

const args = process.argv.slice(2);
const target = args[0] || "./resources";
const fix = args.includes("--fix");

if (!fs.existsSync(target)) {
  console.error("❌ Ruta no encontrada:", target);
  process.exit(1);
}

console.log("🔍 FiveM Security Auditor");
console.log("📂 Escaneando:", path.resolve(target));
console.log("🛠️  Fix:", fix ? "ACTIVADO" : "DESACTIVADO");
console.log("------------------------------------------------");

const report = scanner.scan(target);

fs.mkdirSync("reports", { recursive: true });
const reportPath = path.join("reports", `report-${Date.now()}.json`);
fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

console.log("📄 Reporte:", reportPath);

if (fix) {
  fixer.applyFixes(report);
}

console.log("✅ Finalizado");
