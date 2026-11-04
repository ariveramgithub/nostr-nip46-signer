# Registro de Interacción y Prompting con IA (`prompt-history.md`)

Este documento registra la metodología de prompting, e interacción con el agente de IA.

---

## 1. Metodología de Trabajo y Estrategia de Prompting

Se aplicó una estrategia de "Separación de Roles" en 3 fases:

1. **Fase de Arquitectura y Acotación (Prompt Inicial de Síntesis):** A partir del documento oficial de requerimientos, se instruyó a la IA analizar las regla y el alcance del requerimiento, de manera de generar un archivo base de conocimiento y plan de trabajo ([`GEMINI.md`](../GEMINI.md)).
2. **Fase de Implementación Guiada por Pruebas (TDD):** El agente implementador recibió [`GEMINI.md`](../GEMINI.md) como fuente de verdad, construyendo los módulos criptográficos y de red bajo el estándar de pruebas unitarias automatizadas.
3. **Fase de Supervisión Humana (Control de Alcance):** Intervención activa para frenar la tendencia de la IA a sobrediseñar, manteniendo el concepto de MVP y diseño simple para efectos de flujo de prueba.

---

## 2. Hitos Estratégicos de Interacción

### Hito 1: De los Requerimientos Oficiales al Plano Maestro (`GEMINI.md`)

* **Prompt Estratégico del Postulante:**
  > *"Analiza el documento de requerimientos oficiales para la prueba de desarrollador. Necesitamos construir un NIP-46 Remote Signer en Python sin frameworks de frontend (HTML, Javascript y CSS puro) para autenticar en Stacker News. Acota la ambigüedad, define supuestos razonables, manten diseño simple y práctico y con soporte responsivo y genera el archivo `GEMINI.md` con la arquitectura modular y las restricciones de entorno virtual (`.venv` bajo PEP 668)."*

* **Decisiones y Hallazgos Clave:**
  - **Desacoplamiento Modular:** Separación en 4 módulos limpios (`app/crypto.py`, `app/nip46.py`, `app/relay.py`, `app/storage.py`), aislando la criptografía de la capa de transporte y de la interfaz.
  - **Flujo Nativo de Stacker News:** Se identificó que Stacker News web acepta directamente cadenas de conexión `bunker://<pubkey>?relay=...&secret=...` mediante `@nostr-dev-kit/ndk`, además del soporte para extensiones vía [`static/bridge.js`](../static/bridge.js).
  - **Entorno Aislado Obligatorio:** Incorporación de la regla de entorno virtual `.venv` para prevenir el error `externally-managed-environment` (PEP 668) presente en distribuciones modernas de Linux.

---

### Hito 2: Implementación Criptográfica y Resiliencia Multiplataforma

* **Prompt de Ejecución:**
  > *"Lee `GEMINI.md` y comencemos la implementación del NIP-46 Remote Signer en Python siguiendo el plan dentro del entorno `.venv`. Asegura que las dependencias funcionen limpiamente en cualquier versión de Python 3.10+ a 3.14."*

* **Problema Técnico Resuelto:**
  - Al instalar librerías tradicionales de Nostr como `coincurve` o `secp256k1`, la compilación C (`cffi`) falló en Python 3.14 por falta de wheels binarios oficiales.
  - **Solución y Tradeoff:** Se implementó el estándar de firmas **Schnorr BIP-340** y la aritmética `secp256k1` de forma nativa en [`app/crypto.py`](../app/crypto.py) apoyándose en `cryptography` (OpenSSL ABI3 universal). Esto garantizó una instalación en segundos en cualquier sistema operativo sin herramientas de compilación C/C++.
  - **Soporte Dual:** Se dotó al firmante de soporte tanto para **NIP-44 v2** (`ChaCha20` + `HKDF-SHA256`) como para **NIP-04** (`AES-256-CBC`) con autodetección transparente.
  - **Verificación:** 13 pruebas unitarias automatizadas (`pytest`) pasando en `< 0.6s`, validadas contra los vectores oficiales de prueba #0 y #1 de Bitcoin BIP-340 y el vector oficial de NIP-44 v2.

---

### Hito 3: Control de Alcance

* **Contexto de la Intervención:**
  El agente implementador generó inicialmente una interfaz con mucha información para un flujo simple.

* **Prompt de Corrección del Postulante:**
  > *"El panel es complejo para un testing simple, debemos mantener un flujo simple para apegarnos al requerimiento: Expectativas Mínimas. Enfoquémonos estrictamente en el MVP para el usuario tester: guardar nsec, conectar mediante bunker:// y ver el log de firmas en tiempo real."*

* **Ajustes Realizados:**
  1. **Simplificación Radical de la UI ([`static/index.html`](../static/index.html)):**
     - Se eliminaron opciones secundarias.
     - Se redujo a una estructura lineal de 3 pasos claros:
       1. Gestionar clave `nsec` (crear o guardar).
       2. Copiar URI `bunker://` y abrir Stacker News.
       3. Visualizar en vivo las solicitudes NIP-46 recibidas.
  2. **Experiencia de Usuario y Legibilidad:**
     - Se ajustó el ancho del contenedor a `1200px` con tipografía de alto contraste.
     - Se revisó y repaso diseño móvil.
  3. **README Ejecutivo ([`README.md`](../README.md)):**
     - Se condensó a un documento conciso de lectura rápida (< 75 líneas) con instrucciones directas de instalación, supuestos y tradeoffs técnicos.

---

## 📊 3. Resumen de Eficiencia y Criterio

| Criterio Evaluado (Punto 4.4) | Demostración en el Desarrollo |
| :--- | :--- |
| **Manejo de la ambigüedad** | Desacoplamiento de `bunker://` nativo vs puente `bridge.js` para Stacker News, documentando el supuesto en el `README.md`. |
| **Acotación del alcance** | Intervención explícita del postulante para podar el frontend sobrediseñado y entregar un MVP directo. |
| **Claridad del código** | Arquitectura desacoplada en 4 archivos, 100% tipada, testeada y documentada. |
| **Prompting y gestión de IA** | Prompting estructurado en 3 fases; cero ciclos perdidos en iteraciones redundantes. |
| **Fundamentación de decisiones** | Tradeoffs claros: Python universal con OpenSSL ABI3, un solo proceso web sin Node.js, y custodia de claves en memoria. |
