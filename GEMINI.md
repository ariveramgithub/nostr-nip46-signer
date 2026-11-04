# 🧠 Cerebro del Proyecto: Nostr NIP-46 Remote Signer (Bunker)

> **Origen:** Este plano arquitectónico maestro fue generado a partir del análisis del documento oficial de requerimientos técnicos de la **Secretaría de Gobierno Digital / Ministerio de Hacienda (Chile)**, delimitando el alcance, abstrayendo la ambigüedad y definiendo las especificaciones directas para el agente implementador.

---

## 🎯 1. Objetivo y Alcance
Construir una **aplicación mínima en Python** que funcione como **Firmante Remoto de Nostr (NIP-46 / Bunker)**, permitiendo a un usuario custodiar su clave secreta (`nsec`) y utilizarla mediante NIP-46 para autenticarse e iniciar sesión en **Stacker News** (`https://stacker.news/signup?callbackUrl=...&type=nostr`).

### 📌 Criterios de Evaluación Oficiales
1. **Manejo de la ambigüedad:** El problema tiene aristas sin especificar a propósito. Se valoran los supuestos razonables y su documentación.
2. **Acotación del alcance (MVP):** No se busca una billetera universal ni extensiones complejas. Un sistema simple, robusto y fácil de ejecutar.
3. **Claridad del código:** Arquitectura limpia, desacoplada, tipada y legible.
4. **Prompting y trabajo con IA:** Registros de la interacción incluidos en el repositorio.
5. **Tradeoffs justificados:** Explicar por qué se tomaron ciertas decisiones técnicas en el `README.md`.

---

## 🏛️ 2. Arquitectura de la Solución

```
+-----------------------------------------------------------------------------------+
|                                  NAVEGADOR WEB                                    |
|                                                                                   |
|  [ Panel de Control Local (MVP) ]          [ Stacker News (Pestaña Externa) ]     |
|   http://localhost:8000                     https://stacker.news/login            |
|   - Generar / Cargar nsec                   - Inicia login con Nostr (bunker://)  |
|   - Ver estado del Bunker y Relays (3/3)    - Opcional: window.nostr inyectado    |
|   - Copiar bunker:// URI                      por bridge.js                       |
+-----------------------------------------------------------------------------------+
          |                                               |
          | HTTP REST                                     | NIP-46 Kind 24133 (WebSocket)
          v                                               v
+------------------------+                     +------------------------------------+
|  Backend FastAPI       |                     |  Relays Públicos de Nostr          |
|  (app/main.py)         |                     |  (damus, nos.lol, primal)          |
+------------------------+                     +------------------------------------+
          |                                               |
          | Control local                                 | Eventos cifrados Kind 24133
          v                                               v
+-----------------------------------------------------------------------------------+
|                        BUNKER NIP-46 EN PYTHON (app/)                             |
|                                                                                   |
|  - relay.py:  Cliente WebSocket asíncrono multi-relay para Kind 24133             |
|  - nip46.py:  Manejador de RPC: connect, get_public_key, sign_event, ping         |
|  - crypto.py: Schnorr BIP-340, secp256k1, bech32 (nsec/npub), cifrado NIP-04/44   |
|  - storage.py: Custodia en memoria de la clave privada y bitácora en vivo         |
+-----------------------------------------------------------------------------------+
```

---

## 📂 3. Estructura del Repositorio

```text
nostr-nip46-signer/
├── .gitignore                   # Excluye .venv/, __pycache__/, .env, etc.
├── GEMINI.md                    # Plano arquitectónico maestro y memoria técnica
├── README.md                    # Documentación final de entrega (Instrucciones, Supuestos y Tradeoffs)
├── requirements.txt             # Dependencias Python mínimas y reproducibles
├── app/
│   ├── __init__.py
│   ├── main.py                  # Servidor web FastAPI + endpoints de control
│   ├── crypto.py                # Criptografía Nostr: secp256k1, BIP-340 Schnorr, bech32, cifrado
│   ├── nip46.py                 # Protocolo NIP-46 (JSON-RPC: connect, sign_event, get_public_key)
│   ├── relay.py                 # Cliente WebSocket para relays Nostr (Kind 24133)
│   └── storage.py               # Gestión del nsec / persistencia local mínima
├── static/
│   ├── index.html               # Frontend en HTML/CSS/JS vainilla (MVP minimalista responsivo)
│   └── bridge.js                # Puente NIP-07 -> NIP-46 para la pestaña de Stacker News
├── tests/
│   ├── __init__.py
│   ├── test_crypto.py           # Tests unitarios de derivación de claves y firmas
│   └── test_nip46.py            # Tests unitarios del protocolo NIP-46
└── conversations/
    └── prompt-history.md        # Registro ejecutivo de interacción y decisiones con IA
```

---

## 🐍 3.1. Entorno de Ejecución: Obligatoriedad de `venv` (PEP 668)
> [!IMPORTANT]
> **REGLA MANDATORIA DE INSTALACIÓN:**
> Las distribuciones modernas de Linux (Ubuntu 23+, Debian 12+, Fedora) bloquean la instalación global con `pip` mediante **PEP 668** (`externally-managed-environment`).
> 
> El `README.md` y el flujo de desarrollo **SIEMPRE deben indicar y utilizar un entorno virtual `.venv`**:
> ```bash
> # 1. Crear entorno virtual aislado
> python3 -m venv .venv
> 
> # 2. Activar entorno virtual
> source .venv/bin/activate       # En Linux / macOS
> .venv\Scripts\activate          # En Windows
> 
> # 3. Instalar dependencias limpias
> pip install -r requirements.txt
> 
> # 4. Ejecutar la aplicación
> python -m app.main
> ```
> 
> **Salvaguarda:** `.venv/` ya se encuentra protegido en el `.gitignore` para no subir binarios compilados al repositorio.

---

## ⚙️ 4. Especificación Técnica de Componentes

### A. Dependencias (`requirements.txt`)
Usar dependencias estándar y consolidadas para máxima compatibilidad multiplataforma:
```txt
fastapi>=0.110.0
uvicorn>=0.28.0
websockets>=12.0
cryptography>=42.0.0
bech32>=1.2.0
coincurve>=20.0.0  # o secp256k1 para firmas Schnorr BIP-340
pytest>=8.0.0
```

### B. Módulo Criptográfico (`app/crypto.py`)
- Conversión `nsec` (Bech32) <-> clave privada (32 bytes hex).
- Conversión `npub` (Bech32) <-> clave pública (32 bytes x-only hex).
- Generación de claves aleatorias criptográficamente seguras (`secrets.token_bytes(32)`).
- Firma digital de eventos Nostr usando **Schnorr BIP-340** sobre curva `secp256k1`.
- Cifrado/Descifrado Diffie-Hellman **NIP-04** (AES-256-CBC) y/o **NIP-44** para el intercambio seguro de mensajes en Kind `24133`.

### C. Manejador NIP-46 (`app/nip46.py`)
Implementa las llamadas JSON-RPC definidas en la especificación NIP-46:
1. `connect(client_pubkey, secret=None)`: Valida el secreto compartido y autoriza la sesión con el cliente.
2. `get_public_key()`: Retorna la clave pública (`npub` en hex) del usuario custodiado.
3. `sign_event(event_dict)`:
   - Valida el evento propuesto (desafío de autenticación de Stacker News o nota Nostr).
   - Calcula el `id` (hash SHA-256 del array serializado `[0, pubkey, created_at, kind, tags, content]`).
   - Firma con el `nsec` del usuario mediante BIP-340.
   - Retorna el evento completo con `id` y `sig`.
4. `ping()`: Retorna `"pong"`.
5. `get_relays()`: Retorna los relays preferidos.

### D. Conexión a Relays (`app/relay.py`)
- Se conecta vía WebSocket asíncrono a uno o más relays públicos (`wss://relay.damus.io`, `wss://nos.lol`).
- Publica su suscripción: `["REQ", "<sub_id>", {"kinds": [24133], "#p": ["<bunker_pubkey>"]}]`.
- Al recibir un Kind `24133`:
  1. Extrae el `content` cifrado.
  2. Descifra el payload usando la clave pública del remitente (cliente).
  3. Ejecuta el comando en `app/nip46.py`.
  4. Cifra la respuesta JSON-RPC.
  5. Envía un nuevo evento Kind `24133` firmado por el Bunker hacia el `#p` del cliente.

### E. Frontend Vainilla (`static/index.html`)
- **Interfaz moderna y limpia:** HTML5 + CSS responsivo con variables nativas o Tailwind vía CDN.
- **Sin pasos de compilación:** Abre y funciona directo.
- **Funcionalidades:**
  - Input para ingresar un `nsec` existente o botón para *"Generar nueva identidad"*.
  - Indicador de estado del Bunker (conectado a relays, desconectado, firmas realizadas).
  - Visualizador de la URI `bunker://<bunker_pubkey>?relay=<relay>&secret=<secret>` con botón de copiar.
  - Registro en vivo (log visual) de eventos firmados para demostración en tiempo real.

### F. Puente Stacker News (`static/bridge.js`)
Stacker News en la web busca `window.nostr` (NIP-07). Para cumplir con la demostración sin requerir instalar extensiones de terceros:
- `bridge.js` es un script ligero (~60 líneas) que se puede ejecutar en la consola del navegador o como Bookmarklet en `https://stacker.news/login`.
- Inyecta `window.nostr = { getPublicKey: ..., signEvent: ... }`.
- Cuando Stacker News llama a `window.nostr.signEvent(event)`, el script:
  1. Envía el evento a través del relay hacia nuestro Bunker NIP-46.
  2. Espera la respuesta firmada por el Bunker.
  3. Devuelve el evento firmado a Stacker News.
  4. **Resultado:** Stacker News valida la firma y completa el inicio de sesión exitosamente.

---

## 📝 5. Supuestos y Tradeoffs para el `README.md`

### Supuestos Documentados:
1. **Desacoplamiento NIP-07 / NIP-46 en Stacker News:** Stacker News web consume NIP-07 (`window.nostr`). Dado que la prueba estipula *"No se espera una extensión de navegador ni un firmante universal"*, se provee un puente ligero (`bridge.js` inyectable vía Bookmarklet o consola de navegador) que traduce las llamadas de Stacker News a NIP-46 de forma transparente.
2. **Custodia de Claves:** Por tratarse de un MVP para evaluación técnica, el `nsec` se mantiene en memoria del proceso con opción de guardado local cifrado o archivo `.env`/sesión, priorizando la simplicidad y seguridad durante la sesión activa.
3. **Relays Públicos:** Se utilizan relays estándar de alta disponibilidad (`relay.damus.io`, `nos.lol`) para la comunicación remota, documentando que en entornos de producción se sugiere un relay privado o autenticado.

### Tradeoffs Documentados:
* **Python vs Lenguajes Compilados:** Se priorizó Python por legibilidad del código para el evaluador, rapidez de configuración multiplataforma y cero dependencias de compiladores de sistema.
* **Frontend Vainilla vs Frameworks:** Cero tooling de Node.js/npm. Todo corre bajo el mismo proceso Python, eliminando problemas de versiones de Node en la máquina del revisor.

---

## 🚀 6. Instrucciones de Entrega y Git
* **Cuenta de GitHub:** `ariveramgithub` (cuenta personal).
* **Identidad de Autor (Git Config):**
  * Nombre: `Angel Rivera M.`
  * Correo: `ariveram@gmail.com`
* **Directorio local:** `~/projects/github/ariveramgithub/nostr-nip46-signer`.
* **Configuración SSH:** Configurada localmente en `.git/config` con `~/.ssh/id_ed25519_ariveram`. Para hacer push:
  ```bash
  git push -u origin main
  ```
* **Destinatario de Entrega:** Correo con enlace al repositorio público a `seleccion@hacienda.gov.cl`.
