const fs = require("fs");
const path = require("path");
const scanner = require("./src/scanner");
const fixer = require("./src/fixer");
const { runInteractive } = require("./src/interactive");

const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log(`
    FiveM Security Auditor - Uso

    node index.js [ruta] [flags]

    Opciones:
      [ruta]             Ruta de la carpeta de resources a escanear (default: ./resources)
      --fix              Aplica correcciones automáticas a archivos detectados
      --interactive, -i  Muestra cada detección en pantalla y pregunta y/n antes de eliminar
      --help, -h         Muestra esta ayuda

    Ejemplo:
      node index.js ./resources --fix
      node index.js ./resources --interactive
    `);
  process.exit(0);
}

const target = args.find((a) => !a.startsWith("-")) || "./resources";
const fix = args.includes("--fix");
const interactive = args.includes("--interactive") || args.includes("-i");

if (!fs.existsSync(target)) {
  console.error("❌ Ruta no encontrada:", target);
  process.exit(1);
}

console.log("FiveM Security Auditor");
console.log("Escaneando:", path.resolve(target));
console.log("Modo:", interactive ? "INTERACTIVO" : (fix ? "FIX AUTOMÁTICO" : "SOLO REPORTE"));
console.log("------------------------------------------------");

const report = scanner.scan(target);

if (interactive) {
  console.log(`Archivos escaneados: ${report.summary.scannedFiles}`);
  console.log(`Issues detectadas : ${report.summary.totalIssues}`);
  runInteractive(report).then(() => {
    console.log("Finalizado");
  });
} else {
  fs.mkdirSync("reports", { recursive: true });
  const reportPath = path.join("reports", `report-${Date.now()}.json`);
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

  console.log("Reporte:", reportPath);

  if (fix) {
    fixer.applyFixes(report);
  }

  console.log("Finalizado");
}