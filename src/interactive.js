const readline = require("readline");
const { applyFix } = require("./fixer");

function ask(rl, question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => resolve(answer.trim().toLowerCase()));
  });
}

function riskColor(risk) {
  switch (risk) {
    case "critical": return "\x1b[31m"; // red
    case "high":     return "\x1b[35m"; // magenta
    case "medium":   return "\x1b[33m"; // yellow
    case "low":      return "\x1b[36m"; // cyan
    default:         return "\x1b[37m"; // white
  }
}

function printIssue(issue, index, total) {
  const color = riskColor(issue.risk);
  const reset = "\x1b[0m";
  const bold  = "\x1b[1m";

  console.log("");
  console.log("------------------------------------------------");
  console.log(`${bold}[${index}/${total}]${reset} ${color}${(issue.risk || "?").toUpperCase()}${reset}  ${bold}${issue.type}${reset}`);
  console.log("File  :", issue.file);
  if (issue.jsPath)  console.log("jsPath:", issue.jsPath);
  if (issue.dllPath) console.log("dllPath:", issue.dllPath);
  if (issue.reason)  console.log("Reason:", issue.reason);
  console.log("------------------------------------------------");
}

async function runInteractive(report) {
  const issues = report.issues || [];
  if (issues.length === 0) {
    console.log("No se encontraron issues.");
    return;
  }

  console.log(`\nModo interactivo: ${issues.length} detecciones encontradas.`);
  console.log("Para cada una: [y] aplicar fix / eliminar, [n] omitir, [q] salir, [a] aplicar a todo lo restante\n");

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  let applyAll = false;
  let applied = 0;
  let skipped = 0;

  try {
    for (let i = 0; i < issues.length; i++) {
      const issue = issues[i];
      printIssue(issue, i + 1, issues.length);

      let answer = "y";
      if (!applyAll) {
        answer = await ask(rl, "¿Aplicar fix / eliminar? [y/N/q/a]: ");
      }

      if (answer === "q") {
        console.log("Salida solicitada.");
        break;
      }

      if (answer === "a") {
        applyAll = true;
        answer = "y";
      }

      if (answer === "y" || answer === "yes" || answer === "s" || answer === "si") {
        applyFix(issue);
        applied++;
      } else {
        console.log("Omitido.");
        skipped++;
      }
    }
  } finally {
    rl.close();
  }

  console.log("\n------------------------------------------------");
  console.log(`Resumen: ${applied} aplicados, ${skipped} omitidos, ${issues.length - applied - skipped} sin procesar.`);
  console.log("------------------------------------------------");
}

module.exports = { runInteractive };