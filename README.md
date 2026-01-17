# FiveM Security Auditor

**FiveM Security Auditor** es una herramienta de seguridad para
servidores FiveM que permite escanear recursos en busca de backdoors,
scripts ofuscados, archivos ocultos y otros posibles riesgos. Además,
permite aplicar fixes automáticos para eliminar archivos sospechosos de
manera segura.

[Web Oficial](https://fivem-auditor.sabaariiego.dev/)

## 🚀 Características

-   Detección de **archivos Lua y JS ofuscados** con patrones como
    `globalThis[...]`, `eval(...)` y más.
-   Identificación de **carpetas ocultas** creadas con `attrib +h +s` en
    Windows.
-   Análisis de `fxmanifest.lua` y eliminación de referencias a scripts
    maliciosos sin romper la estructura.
-   Escaneo de scripts dentro de **carpetas sospechosas o ocultas**.
-   **Fix automático** para limpiar manifests y eliminar archivos
    maliciosos.
-   Generación de reportes JSON para integración con otras herramientas.

## 📝 Uso

``` bash
node index.js ./resources
node index.js ./resources --fix
node index.js --help
```

### Flags disponibles

  Flag     Descripción
  -------- ---------------------------------------------
  --fix    Aplica automáticamente los fixes detectados
  --help   Muestra información de ayuda

## 📄 Reportes

Los reportes se generan en formato JSON dentro de la carpeta `reports/`.

``` json
{
  "summary": {
    "scannedFiles": 315,
    "totalIssues": 1
  },
  "issues": [
    {
      "type": "hidden_folder",
      "file": "C:/resources/cfg",
      "risk": "critical",
      "reason": "Carpeta ocultada con attrib +h +s"
    }
  ]
}
```

## 🛡️ Servicios recomendados

### ColdHosting

Servidor de hosting profesional de alto rendimiento con más de **200
Tbps** de capacidad de red, optimizado específicamente para servidores
FiveM con **protección DDoS avanzada**.\
👉  [Visita ColdHosting](https://coldhosting.com)

### FlexBacks

Sistema de **backups SQL automáticos** optimizados para no perder
rendimiento. Respaldos inteligentes que protegen tus datos sin afectar
la velocidad de tu servidor.\
👉 [Visita FlexBacks](https://flexbacks.com)

## ⚠️ Advertencias

-   Usa esta herramienta **solo en tus propios servidores**.
-   Se recomienda hacer **backup antes de aplicar fixes automáticos**.

## 📝 Licencia

MIT License
