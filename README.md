# FiveM Security Auditor

**FiveM Security Auditor** es una herramienta de seguridad para
servidores FiveM que permite escanear recursos en busca de backdoors,
scripts ofuscados, archivos ocultos y otros posibles riesgos. Además,
permite aplicar fixes automáticos para eliminar archivos sospechosos de
manera segura.

## 🌿 Rama Beta

Existe una rama llamada `beta` que incluye **nuevas detecciones y mejoras en desarrollo** que aún no han sido completamente testeadas.

> ⚠️ **Importante:**
>
> - Estas funcionalidades pueden contener errores o falsos positivos.
> - El uso de la rama `beta` es **bajo tu propia responsabilidad**.
> - Se recomienda utilizarla únicamente en entornos de prueba y **no en producción**.
> - Siempre realiza un **backup completo** antes de usarla.

### Cómo usar la rama beta

```bash
git clone -b beta https://github.com/Sabaariiego/fivem-security-auditor.git
cd fivem-security-auditor
npm install
node index.js ./resources
```

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

## 🛠️ Requisitos

Para ejecutar FiveM Security Auditor necesitas tener Node.js instalado **(versión 18 o superior recomendada)**.
Descárgalo desde la web oficial: [nodejs](https://nodejs.org/)  

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

## 🛡️ Amenazas detectadas
Esta herramienta está diseñada específicamente para localizar rastros de:
- **Cipher Panel**
- **Blum Panel**

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

Este proyecto está bajo la licencia [CC BY-NC 4.0](LICENSE). Se permite usarlo y modificarlo, pero **no para fines comerciales**.
