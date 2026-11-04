# 🔐 Nostr NIP-46 Remote Signer (Bunker)

Aplicación mínima en Python que permite guardar o crear una clave secreta de Nostr (`nsec`) y utilizarla mediante un firmante remoto **NIP-46** (eventos `Kind 24133`) para autenticarse en **Stacker News**.

---

## 🚀 1. Instalación y Ejecución

**Requisitos:** Python 3.10+ (compatible con Python 3.12 LTS, 3.13 y 3.14). No requiere Node.js ni compiladores del sistema.

```bash
# 1. Clonar el repositorio y entrar al directorio
git clone https://github.com/ariveramgithub/nostr-nip46-signer.git
cd nostr-nip46-signer

# 2. Crear y activar entorno virtual (.venv)
python3 -m venv .venv
source .venv/bin/activate        # En Linux / macOS
# .venv\Scripts\activate         # En Windows

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Iniciar el firmante NIP-46
python -m app.main
```

Abra en su navegador el panel local del firmante:
👉 **`http://127.0.0.1:8000`**

Para ejecutar las pruebas unitarias (BIP-340, NIP-04, NIP-44 v2 y NIP-46):
```bash
pytest -v
```

---

## 🖥️ 2. Flujo de Inicio de Sesión en Stacker News (Principio a Fin)

1. **Crear o ingresar clave secreta (`nsec`):**
   - En `http://127.0.0.1:8000` (sección **1. Clave Secreta de Nostr**), utilice la clave generada automáticamente, presione **"Crear Nueva Clave"** o ingrese un `nsec1...` propio y presione **"Guardar Clave"**.
2. **Copiar la URI del firmante (`bunker://`):**
   - En la sección **2. Iniciar Sesión en Stacker News (NIP-46)**, verifique que el indicador superior muestre **`Relays NIP-46: 3/3`** y haga clic en **"Copiar URI bunker://"**.
3. **Autenticarse en Stacker News:**
   - Haga clic en **"Abrir Stacker News ↗"** (`https://stacker.news/signup?callbackUrl=https%3A%2F%2Fstacker.news%2F&type=nostr`).
   - Pegue la URI `bunker://...` en el campo **"Connect with token or NIP-05 address"** y presione **"Sign up with token or NIP-05"** (o *Login with token or NIP-05*).
   - En la sección **3. Actividad NIP-46 en Vivo** de su panel local verá llegar las solicitudes `connect`, `get_public_key` y `sign_event` (firmando el desafío `Kind 27235`), completando el inicio de sesión en Stacker News.

---

## 🧠 3. Supuestos Realizados

1. **Flujo iniciado por el firmante (`bunker://`):** NIP-46 define dos formas de iniciar la conexión (`bunker://` y `nostrconnect://`). Dado que Stacker News expone directamente el campo *"Connect with token"* en su pantalla de login Nostr, se priorizó la generación de URIs `bunker://<pubkey>?relay=...&secret=<secret>` como flujo principal.
2. **Custodia en memoria de sesión:** Al tratarse de un MVP demostrativo y no de una billetera de producción, la clave privada (`nsec`) se mantiene únicamente en la memoria del proceso Python mientras la aplicación está en ejecución (con soporte opcional por variable de entorno `NOSTR_NSEC`).
3. **Aprobación automática tras validar el `secret`:** Una vez que el cliente presenta el `secret` válido incluido en la URI `bunker://` durante el método `connect`, el firmante autoriza la firma del evento de autenticación (`Kind 27235`) sin requerir popups adicionales de confirmación manual.
4. **Relays públicos por defecto:** Se utilizan tres relays públicos de alta disponibilidad (`wss://relay.damus.io`, `wss://nos.lol`, `wss://relay.primal.net`) para el transporte de eventos `Kind 24133`.

---

## ⚖️ 4. Tradeoffs Técnicos

* **Python + FastAPI + HTML/JS Vainilla (Cero Frameworks):** Se eligió servir una interfaz única en HTML/CSS/JS simple desde el mismo proceso Python (`app/main.py`) para cumplir con la restricción de no usar frameworks de frontend y permitir que el evaluador levante todo el sistema con un solo comando.
* **Schnorr BIP-340 en Python + `cryptography` (`abi3`) en lugar de `coincurve`:** Librerías como `coincurve` o `secp256k1` dependen de compilación C (`cffi`) que suele fallar en versiones recientes de Python o sistemas sin headers de desarrollo. Implementar BIP-340 sobre la aritmética de curva `secp256k1` junto con `cryptography` (wheels binarios universales) garantiza una instalación limpia en cualquier entorno en ~1 ms por firma.
* **Soporte dual NIP-44 v2 y NIP-04:** Aunque NIP-46 moderno especifica cifrado NIP-44 v2 (`ChaCha20` + `HKDF-SHA256`), algunos clientes Nostr aún utilizan NIP-04 (`AES-256-CBC`). Se implementaron ambos con autodetección para evitar incompatibilidades de protocolo.

---

## 📂 5. Estructura y Registros de IA

* `app/crypto.py`: Derivación `secp256k1`, Bech32 (`nsec`/`npub`), firmas Schnorr BIP-340 y cifrado NIP-04 / NIP-44 v2.
* `app/nip46.py`: Manejador JSON-RPC NIP-46 (`connect`, `get_public_key`, `sign_event`, `ping`, `switch_relays`).
* `app/relay.py`: Cliente WebSocket asíncrono suscrito a eventos `Kind 24133`.
* `app/storage.py`: Gestión en memoria de la clave `nsec` y registro de actividad.
* `static/index.html`: Interfaz web mínima en HTML/CSS/JS vainilla.
* `conversations/prompt-history.md`: Resumen estructurado del proceso de desarrollo, decisiones de acotación de alcance y supuestos técnicos.
* `conversations/transcripcion-dialogo.md`: Transcripción cronológica completa de los prompts del postulante y las respuestas del agente de IA.
