"""TakTak.brave — servidor del acortador de enlaces con pagina de anuncio.

Solo libreria estandar de Python (sin dependencias). Guarda los enlaces en
SQLite y sirve la web, la API y una pagina de anuncio de 3 s antes de redirigir.

Variables de entorno:
    PUERTO / PORT   puerto (por defecto 8080)
    TAKTAK_DB       ruta del fichero SQLite
    TAKTAK_ADMIN    correo del administrador
    TAKTAK_ADMIN_CLAVE  clave del administrador (obligatoria para entrar)
    MAX_BANNERS     maximo de banners (20)
    MAX_DIAS        dias de conservacion de enlaces (365)
    TOPE_POR_HORA   enlaces por IP y hora (10)
    SESION_HORAS    duracion de la sesion de admin (12)
    LOTERIA_PRECIO  precio del ticket en BAT (demo, 1.0)
    LOTERIA_BASE    pozo base en BAT (demo, 5.0)
"""
import hashlib
import json
import os
import random
import re
import secrets
import sqlite3
import string
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

RAIZ = Path(__file__).resolve().parent.parent
INDEX = RAIZ / "index.html"
PUBLICIDAD = RAIZ / "publicidad"
DB = Path(os.environ.get("TAKTAK_DB") or (Path(__file__).parent / "taktak.db"))

PUERTO = int(os.environ.get("PUERTO") or os.environ.get("PORT") or 8080)
MAX_BANNERS = int(os.environ.get("MAX_BANNERS") or 20)
MAX_DIAS = int(os.environ.get("MAX_DIAS") or 365)
TOPE_POR_HORA = int(os.environ.get("TOPE_POR_HORA") or 10)
SESION_HORAS = int(os.environ.get("SESION_HORAS") or 12)

# Lotería (DEMO). No se cobra ni se paga nada: son cifras de demostración.
LOTERIA_PRECIO = float(os.environ.get("LOTERIA_PRECIO") or 1.0)   # BAT por ticket (demo)
LOTERIA_BASE = float(os.environ.get("LOTERIA_BASE") or 5.0)       # pozo base (demo)
LOTERIA_POZO_PCT = 0.8    # 80% del ticket va al pozo
LOTERIA_ADMIN_PCT = 0.2   # 20% reservado para administración

NOMBRE_ARCHIVO = re.compile(r"^[a-zA-Z0-9._-]+$")
CONTADOR = {}
CERROJO = threading.Lock()


# --------------------------------------------------------------------------- #
# Base de datos
# --------------------------------------------------------------------------- #
def _bd():
    conexion = sqlite3.connect(DB)
    conexion.row_factory = sqlite3.Row
    return conexion


def preparar_bd():
    con = _bd()
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS enlaces (
            corto       TEXT PRIMARY KEY,
            destino     TEXT NOT NULL,
            creado      INTEGER NOT NULL,
            visitas     INTEGER NOT NULL DEFAULT 0,
            impresiones INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS banners (
            id       TEXT PRIMARY KEY,
            titulo   TEXT NOT NULL,
            imagen   TEXT NOT NULL,
            destino  TEXT NOT NULL,
            orden    INTEGER NOT NULL DEFAULT 0,
            creado   INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sesiones (
            clave  TEXT PRIMARY KEY,
            correo TEXT NOT NULL,
            creado INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS loterias (
            fecha           TEXT PRIMARY KEY,
            sorteado        INTEGER NOT NULL DEFAULT 0,
            ganador_numero  TEXT,
            ganador_wallet  TEXT,
            sorteado_en     INTEGER
        );
        CREATE TABLE IF NOT EXISTS tickets (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha  TEXT NOT NULL,
            numero TEXT NOT NULL,
            wallet TEXT NOT NULL,
            creado INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS usuarios (
            correo  TEXT PRIMARY KEY,
            sal     TEXT NOT NULL,
            clave   TEXT NOT NULL,
            creado  INTEGER NOT NULL
        );
        """
    )
    con.commit()
    con.close()


def bd_enlaces():
    con = _bd()
    filas = con.execute("SELECT * FROM enlaces ORDER BY creado DESC").fetchall()
    con.close()
    return filas


def bd_banners():
    con = _bd()
    filas = con.execute("SELECT * FROM banners ORDER BY orden, creado").fetchall()
    con.close()
    return filas


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #
def aleatorio(n=7):
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def url_valida(texto):
    if not texto or len(texto) > 2000:
        return ""
    try:
        u = urlparse(texto if "://" in texto else "https://" + texto)
    except ValueError:
        return ""
    if u.scheme not in ("http", "https") or not u.netloc or "." not in u.netloc:
        return ""
    return u.geturl()


def escapar(t):
    return (str(t).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def permitido(ip):
    """Limite simple de enlaces por IP y hora."""
    ahora = time.time()
    with CERROJO:
        marcas = [t for t in CONTADOR.get(ip, []) if ahora - t < 3600]
        if len(marcas) >= TOPE_POR_HORA:
            CONTADOR[ip] = marcas
            return False
        marcas.append(ahora)
        CONTADOR[ip] = marcas
        return True


# --------------------------------------------------------------------------- #
# Claves (hash con sal, sin dependencias)
# --------------------------------------------------------------------------- #
def _hash_clave(clave, sal):
    return hashlib.pbkdf2_hmac("sha256", clave.encode("utf-8"), bytes.fromhex(sal), 120_000).hex()


def clave_valida(correo, clave):
    """Comprueba correo+clave. El admin se valida con TAKTAK_ADMIN_CLAVE."""
    correo = (correo or "").strip().lower()
    clave = clave or ""
    admin = (os.environ.get("TAKTAK_ADMIN") or "taktak.messenger@gmail.com").lower()
    if correo == admin:
        esperada = os.environ.get("TAKTAK_ADMIN_CLAVE") or ""
        return bool(esperada) and secrets.compare_digest(clave, esperada)
    con = _bd()
    fila = con.execute("SELECT sal, clave FROM usuarios WHERE correo=?", (correo,)).fetchone()
    con.close()
    if not fila:
        return False
    return secrets.compare_digest(_hash_clave(clave, fila["sal"]), fila["clave"])


def crear_usuario(correo, clave):
    correo = (correo or "").strip().lower()
    clave = clave or ""
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", correo):
        return "Escribe un correo válido"
    if len(clave) < 6:
        return "La clave debe tener al menos 6 caracteres"
    sal = secrets.token_hex(16)
    con = _bd()
    existe = con.execute("SELECT 1 FROM usuarios WHERE correo=?", (correo,)).fetchone()
    if existe:
        con.close()
        return "Ese correo ya está registrado"
    con.execute("INSERT INTO usuarios (correo, sal, clave, creado) VALUES (?,?,?,?)",
                (correo, sal, _hash_clave(clave, sal), int(time.time())))
    con.commit()
    con.close()
    return None


# --------------------------------------------------------------------------- #
# Vistas
# --------------------------------------------------------------------------- #
def json_banners():
    return [{"id": f["id"], "titulo": f["titulo"], "imagen": f["imagen"], "destino": f["destino"]}
            for f in bd_banners()]


def pagina_ad(fila):
    banners = json_banners()
    anunciante = random.choice(banners) if banners else None
    tarjeta = ""
    if anunciante:
        tarjeta = f"""
        <a class="anuncio" href="{escapar(anunciante['destino'])}" target="_blank" rel="noopener">
          <span class="etiqueta">Patrocinado</span>
          <img src="{escapar(anunciante['imagen'])}" alt="Publicidad">
          <div class="anuncio-pie">{escapar(anunciante['titulo'])} &rarr;</div>
        </a>"""
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TakTak.brave - Redirigiendo...</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; min-height:100vh; background:#0B0F19; color:#e5e7eb;
         font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         display:flex; align-items:center; justify-content:center; padding:16px; }}
  .caja {{ width:100%; max-width:420px; background:#111827; border:1px solid #1F2937;
           border-radius:20px; padding:22px; text-align:center; }}
  .cab {{ display:flex; justify-content:space-between; font-size:11px; color:#9ca3af;
          text-transform:uppercase; letter-spacing:.06em; padding-bottom:10px;
          border-bottom:1px solid #1F2937; }}
  .marca {{ color:#FF5500; font-weight:700; }}
  .anuncio {{ display:block; margin:16px 0; text-decoration:none; color:inherit;
              background:#0B0F19; border:1px solid #1F2937; border-radius:14px;
              padding:12px; text-align:left; }}
  .etiqueta {{ display:inline-block; font-size:10px; font-weight:700; color:#FF5500;
               background:rgba(255,85,0,.15); padding:2px 8px; border-radius:6px; }}
  .anuncio img {{ width:100%; height:150px; object-fit:cover; border-radius:10px; margin:8px 0; }}
  .anuncio-pie {{ font-size:13px; font-weight:700; color:#fff; }}
  .contador {{ width:48px; height:48px; border-radius:50%; margin:12px auto 8px;
               display:flex; align-items:center; justify-content:center; font-size:20px;
               font-weight:700; color:#FF5500; background:rgba(255,85,0,.15);
               border:2px solid #FF5500; }}
  .boton {{ width:100%; padding:13px; border:0; border-radius:12px; font-size:14px;
            font-weight:700; background:#1F2937; color:#6b7280; cursor:not-allowed; }}
  .boton.listo {{ background:#FF5500; color:#fff; cursor:pointer; }}
  .nota {{ font-size:11px; color:#6b7280; margin-top:10px; }}
</style>
</head>
<body>
  <div class="caja">
    <div class="cab"><span class="marca">TakTak Interstellar Redirect</span><span>Redirigiendo...</span></div>
    {tarjeta}
    <div class="contador" id="cuenta">3</div>
    <button class="boton" id="seguir" disabled>Espere 3 segundos...</button>
    <div class="nota">Volviendo a tu enlace original...</div>
  </div>
<script>
  const destino = {json.dumps(fila["destino"])};
  const corto = {json.dumps(fila["corto"])};
  let seg = 3;
  const cuenta = document.getElementById('cuenta');
  const boton = document.getElementById('seguir');
  fetch('/api/visita', {{method:'POST', headers:{{'Content-Type':'application/json'}},
                        body: JSON.stringify({{corto: corto}})}}).catch(function () {{}});
  function seguir() {{ window.location.href = destino; }}
  boton.addEventListener('click', seguir);
  const t = setInterval(function () {{
    seg--; cuenta.innerText = seg;
    if (seg <= 0) {{
      clearInterval(t);
      boton.disabled = false;
      boton.className = 'boton listo';
      boton.innerText = 'Continuar a la web de destino';
      setTimeout(seguir, 1500);
    }} else {{
      boton.innerText = 'Espere ' + seg + ' segundos...';
    }}
  }}, 1000);
</script>
</body>
</html>"""


def pagina_404():
    return """<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TakTak.brave - Enlace no encontrado</title>
<style>body{margin:0;min-height:100vh;background:#0B0F19;color:#e5e7eb;
font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;text-align:center;padding:24px}
h1{color:#FF5500;font-size:52px;margin:0}p{color:#9ca3af}a{color:#FF5500}</style></head>
<body><div><h1>404</h1><p>Este enlace TakTak no existe o ya caduco.</p>
<p><a href="/">Volver a TakTak.brave</a></p></div></body></html>"""


# --------------------------------------------------------------------------- #
# Lotería (DEMO) — el pozo y los tickets se guardan de verdad en SQLite, pero
# NO se cobra ni se paga ningún token: son cifras de demostración.
# --------------------------------------------------------------------------- #
def hoy():
    return time.strftime("%Y-%m-%d", time.localtime())


def proximo_sorteo():
    """Marca de tiempo de la próxima medianoche UTC (fin del sorteo de hoy)."""
    return (int(time.time() // 86400) + 1) * 86400


def loteria_estado():
    fecha = hoy()
    con = _bd()
    fila = con.execute("SELECT * FROM loterias WHERE fecha=?", (fecha,)).fetchone()
    total = con.execute("SELECT COUNT(*) AS n FROM tickets WHERE fecha=?", (fecha,)).fetchone()["n"]
    con.close()
    estado = {
        "fecha": fecha,
        "precio": LOTERIA_PRECIO,
        "pozo": round(LOTERIA_BASE + total * LOTERIA_PRECIO * LOTERIA_POZO_PCT, 2),
        "admin": round(total * LOTERIA_PRECIO * LOTERIA_ADMIN_PCT, 2),
        "tickets": total,
        "pozo_pct": int(LOTERIA_POZO_PCT * 100),
        "admin_pct": int(LOTERIA_ADMIN_PCT * 100),
        "proximo": proximo_sorteo(),
        "sorteado": bool(fila and fila["sorteado"]),
        "ganador": None,
        "demo": True,
    }
    if fila and fila["sorteado"]:
        estado["ganador"] = {"numero": fila["ganador_numero"], "wallet": fila["ganador_wallet"]}
    return estado


def loteria_comprar(numero, wallet):
    numero = re.sub(r"\D", "", str(numero or ""))[:4]
    if len(numero) != 4:
        return "El número debe tener 4 dígitos (0000-9999)"
    wallet = (wallet or "").strip()[:80]
    if not wallet:
        return "Conecta tu billetera primero"
    fecha = hoy()
    con = _bd()
    fila = con.execute("SELECT sorteado FROM loterias WHERE fecha=?", (fecha,)).fetchone()
    if fila and fila["sorteado"]:
        con.close()
        return "El sorteo de hoy ya se realizó. Vuelve mañana."
    con.execute("INSERT INTO tickets (fecha, numero, wallet, creado) VALUES (?,?,?,?)",
                (fecha, numero, wallet, int(time.time())))
    con.commit()
    con.close()
    return None


def loteria_sortear():
    fecha = hoy()
    con = _bd()
    fila = con.execute("SELECT * FROM loterias WHERE fecha=?", (fecha,)).fetchone()
    if fila and fila["sorteado"]:
        con.close()
        return {"numero": fila["ganador_numero"], "wallet": fila["ganador_wallet"]}, None
    tickets = con.execute("SELECT numero, wallet FROM tickets WHERE fecha=?", (fecha,)).fetchall()
    if not tickets:
        con.close()
        return None, "No hay tickets vendidos hoy."
    ganador = random.choice(tickets)
    con.execute(
        "INSERT INTO loterias (fecha, sorteado, ganador_numero, ganador_wallet, sorteado_en) "
        "VALUES (?,1,?,?,?) ON CONFLICT(fecha) DO UPDATE SET sorteado=1, "
        "ganador_numero=excluded.ganador_numero, ganador_wallet=excluded.ganador_wallet, "
        "sorteado_en=excluded.sorteado_en",
        (fecha, ganador["numero"], ganador["wallet"], int(time.time())))
    con.commit()
    con.close()
    return {"numero": ganador["numero"], "wallet": ganador["wallet"]}, None


def loteria_tickets(wallet=None):
    fecha = hoy()
    con = _bd()
    if wallet:
        filas = con.execute(
            "SELECT numero, wallet, creado FROM tickets WHERE fecha=? AND wallet=? ORDER BY creado DESC",
            (fecha, wallet)).fetchall()
    else:
        filas = con.execute(
            "SELECT numero, wallet, creado FROM tickets WHERE fecha=? ORDER BY creado DESC",
            (fecha,)).fetchall()
    con.close()
    salida = []
    for f in filas:
        w = f["wallet"]
        salida.append({"numero": f["numero"],
                       "hora": time.strftime("%H:%M:%S", time.localtime(f["creado"])),
                       "wallet": (w[:6] + "..." + w[-4:]) if len(w) > 10 else w})
    return salida


# --------------------------------------------------------------------------- #
# Manejador HTTP
# --------------------------------------------------------------------------- #
class Manejador(BaseHTTPRequestHandler):
    server_version = "TakTak/1.0"

    def _responder(self, codigo, cuerpo, tipo="text/html; charset=utf-8", extra=None):
        if isinstance(cuerpo, str):
            cuerpo = cuerpo.encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Content-Type-Options", "nosniff")
        for clave, valor in (extra or {}).items():
            self.send_header(clave, valor)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(cuerpo)

    def _json(self, datos, codigo=200):
        self._responder(codigo, json.dumps(datos, ensure_ascii=False),
                        "application/json; charset=utf-8")

    def _entrada(self):
        largo = int(self.headers.get("Content-Length") or 0)
        if not largo or largo > 500_000:
            return {}
        try:
            return json.loads(self.rfile.read(largo) or b"{}")
        except (ValueError, TypeError):
            return {}

    def log_message(self, formato, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), formato % args))

    def _admin(self):
        clave = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
        if not clave:
            return False
        con = _bd()
        fila = con.execute("SELECT creado FROM sesiones WHERE clave=?", (clave,)).fetchone()
        con.close()
        return bool(fila) and (time.time() - fila["creado"] < SESION_HORAS * 3600)

    def do_GET(self):
        partes = urlparse(self.path)
        ruta = partes.path

        if ruta in ("/", "/index.html"):
            if INDEX.exists():
                return self._responder(200, INDEX.read_bytes())
            return self._responder(500, "Falta index.html")
        if ruta == "/api/banners":
            return self._json({"banners": json_banners(), "stats": self._stats()})
        if ruta == "/api/loteria":
            return self._json(loteria_estado())
        if ruta == "/api/loteria/tickets":
            consulta = parse_qs(urlparse(self.path).query)
            wallet = (consulta.get("wallet") or [""])[0].strip()
            if not wallet and not self._admin():
                return self._json({"error": "no autorizado"}, 401)
            return self._json({"tickets": loteria_tickets(wallet or None)})
        if ruta == "/api/enlaces":
            if not self._admin():
                return self._json({"error": "no autorizado"}, 401)
            return self._json({"enlaces": [dict(f) for f in bd_enlaces()]})
        if ruta.startswith("/publicidad/"):
            return self._servir_archivo(PUBLICIDAD, ruta)
        if ruta == "/favicon.ico":
            return self._responder(204, b"")
        corto = ruta.strip("/")
        if corto and "/" not in corto and corto not in ("api", "publicidad"):
            return self._seguir_enlace(corto)
        return self._responder(404, pagina_404())

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        ruta = urlparse(self.path).path
        datos = self._entrada()
        if ruta == "/api/acortar":
            return self._acortar(datos)
        if ruta == "/api/visita":
            return self._visita(datos)
        if ruta == "/api/admin/login":
            return self._login(datos)
        if ruta == "/api/usuarios/registro":
            error = crear_usuario(datos.get("correo"), datos.get("clave"))
            if error:
                return self._json({"error": error}, 400)
            return self._json({"ok": True, "correo": (datos.get("correo") or "").strip().lower()})
        if ruta == "/api/usuarios/login":
            correo = (datos.get("correo") or "").strip().lower()
            if not clave_valida(correo, datos.get("clave")):
                return self._json({"error": "correo o clave incorrectos"}, 401)
            return self._json({"ok": True, "correo": correo})
        if ruta == "/api/admin/banners":
            return self._guardar_banner(datos)
        if ruta == "/api/admin/borrar":
            return self._borrar_banner(datos)
        if ruta == "/api/loteria/comprar":
            error = loteria_comprar(datos.get("numero"), datos.get("wallet"))
            if error:
                return self._json({"error": error}, 400)
            return self._json(loteria_estado())
        if ruta == "/api/loteria/sortear":
            if not self._admin():
                return self._json({"error": "no autorizado"}, 401)
            ganador, error = loteria_sortear()
            if error:
                return self._json({"error": error}, 400)
            estado = loteria_estado()
            estado["ganador"] = ganador
            return self._json(estado)
        return self._json({"error": "ruta no encontrada"}, 404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Base")
        self.end_headers()

    def _servir_archivo(self, base, ruta):
        nombre = ruta.split("/", 2)[-1]
        if not NOMBRE_ARCHIVO.match(nombre):
            return self._responder(400, "Nombre no valido")
        archivo = (base / nombre).resolve()
        if base.resolve() not in archivo.parents or not archivo.exists():
            return self._responder(404, "No encontrado")
        tipos = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                 ".gif": "image/gif", ".webp": "image/webp", ".svg": "image/svg+xml",
                 ".css": "text/css", ".js": "application/javascript",
                 ".html": "text/html; charset=utf-8"}
        self._responder(200, archivo.read_bytes(),
                        tipos.get(archivo.suffix.lower(), "application/octet-stream"))

    def _stats(self):
        filas = bd_enlaces()
        return {"enlaces": len(filas),
                "visitas": sum(f["visitas"] for f in filas),
                "impresiones": sum(f["impresiones"] for f in filas)}

    def _seguir_enlace(self, corto):
        con = _bd()
        fila = con.execute("SELECT * FROM enlaces WHERE corto=?", (corto,)).fetchone()
        if fila:
            con.execute("UPDATE enlaces SET visitas=visitas+1 WHERE corto=?", (corto,))
            con.commit()
        con.close()
        if not fila:
            return self._responder(404, pagina_404())
        self._responder(200, pagina_ad(fila))

    def _acortar(self, datos):
        destino = url_valida((datos.get("url") or "").strip())
        if not destino:
            return self._json({"error": "URL no valida. Debe empezar por http:// o https://"}, 400)
        if not permitido(self.client_address[0]):
            return self._json({"error": "Demasiados enlaces seguidos. Espera un momento."}, 429)

        con = _bd()
        corto = ""
        for _ in range(6):
            intento = aleatorio()
            if not con.execute("SELECT 1 FROM enlaces WHERE corto=?", (intento,)).fetchone():
                corto = intento
                break
        con.execute("INSERT INTO enlaces (corto, destino, creado) VALUES (?,?,?)",
                    (corto, destino, int(time.time())))
        con.commit()
        con.close()

        base = (self.headers.get("X-Base") or ("http://" + (self.headers.get("Host") or "taktak.brave"))).rstrip("/")
        return self._json({"corto": corto, "enlace": f"{base}/{corto}", "destino": destino})

    def _visita(self, datos):
        corto = (datos.get("corto") or "").strip()
        if corto:
            con = _bd()
            con.execute("UPDATE enlaces SET impresiones=impresiones+1 WHERE corto=?", (corto,))
            con.commit()
            con.close()
        return self._json({"ok": True})

    def _login(self, datos):
        correo = (datos.get("correo") or "").strip().lower()
        clave = datos.get("clave") or ""
        admin = (os.environ.get("TAKTAK_ADMIN") or "taktak.messenger@gmail.com").lower()
        if correo != admin or not clave_valida(correo, clave):
            return self._json({"error": "correo o clave incorrectos"}, 401)
        clave_sesion = secrets.token_urlsafe(24)
        con = _bd()
        con.execute("INSERT INTO sesiones (clave, correo, creado) VALUES (?,?,?)",
                    (clave_sesion, correo, int(time.time())))
        con.commit()
        con.close()
        return self._json({"clave": clave_sesion})

    def _guardar_banner(self, datos):
        if not self._admin():
            return self._json({"error": "no autorizado"}, 401)
        titulo = (datos.get("titulo") or "").strip()[:120]
        imagen = url_valida((datos.get("imagen") or "").strip())
        destino = url_valida((datos.get("destino") or "").strip())
        if not titulo or not imagen or not destino:
            return self._json({"error": "Titulo, imagen y destino validos son obligatorios"}, 400)
        con = _bd()
        total = con.execute("SELECT COUNT(*) AS n FROM banners").fetchone()["n"]
        if total >= MAX_BANNERS:
            con.close()
            return self._json({"error": f"Maximo {MAX_BANNERS} banners"}, 400)
        con.execute("INSERT INTO banners (id, titulo, imagen, destino, orden, creado) VALUES (?,?,?,?,?,?)",
                    (secrets.token_hex(6), titulo, imagen, destino, total, int(time.time())))
        con.commit()
        con.close()
        return self._json({"ok": True, "banners": json_banners()})

    def _borrar_banner(self, datos):
        if not self._admin():
            return self._json({"error": "no autorizado"}, 401)
        ident = (datos.get("id") or "").strip()
        con = _bd()
        total = con.execute("SELECT COUNT(*) AS n FROM banners").fetchone()["n"]
        if total <= 1:
            con.close()
            return self._json({"error": "Debe quedar al menos 1 banner"}, 400)
        con.execute("DELETE FROM banners WHERE id=?", (ident,))
        con.commit()
        con.close()
        return self._json({"ok": True, "banners": json_banners()})


def banner_por_defecto():
    con = _bd()
    if con.execute("SELECT COUNT(*) AS n FROM banners").fetchone()["n"] == 0:
        con.execute("INSERT INTO banners (id, titulo, imagen, destino, orden, creado) VALUES (?,?,?,?,?,?)",
                    ("demo", "TakTak.brave - Tu acortador Web3",
                     "https://images.unsplash.com/photo-1639762681485-074b7f938ba0?w=600&auto=format&fit=crop&q=60",
                     "https://taktak.brave", 0, int(time.time())))
        con.commit()
    con.close()


def limpiar_vencidos():
    con = _bd()
    con.execute("DELETE FROM enlaces WHERE creado < ?", (int(time.time()) - MAX_DIAS * 86400,))
    con.execute("DELETE FROM sesiones WHERE creado < ?", (int(time.time()) - SESION_HORAS * 3600,))
    con.commit()
    con.close()


def main():
    preparar_bd()
    banner_por_defecto()
    limpiar_vencidos()
    servidor = ThreadingHTTPServer(("0.0.0.0", PUERTO), Manejador)
    print(f"TakTak.brave sirviendo en http://0.0.0.0:{PUERTO}", flush=True)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        servidor.shutdown()


if __name__ == "__main__":
    main()
