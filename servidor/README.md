# TakTak.brave — Servidor del acortador

Servidor real que hace funcionar el acortador: guarda los enlaces, sirve la
web, muestra una **página de anuncio de 3 segundos** y luego redirige.

## Qué hace

- `POST /api/acortar` — guarda la URL y devuelve un enlace corto real.
- `GET /<corto>` — abre la página de anuncio (3 s) y redirige al destino.
- `POST /api/visita` — cuenta las impresiones del anuncio.
- `GET /api/banners` — lista los banners y las estadísticas.
- `POST /api/admin/login` — valida el correo del administrador y da una clave.
- `POST /api/admin/banners` — añade un banner (requiere clave).
- `POST /api/admin/borrar` — borra un banner (requiere clave).

## Cómo funciona ahora

```
Navegador  ──POST /api/acortar──►  Servidor  ──►  SQLite (taktak.db)
              ◄── /5sg9s2e ──────┘

Quien abre el enlace:
  /5sg9s2e  ──►  página de anuncio (3 s)  ──►  redirige a la web original
```

## Dependencias

**Ninguna.** Solo la librería estándar de Python 3.8+.

## Ejecutar en local

```bash
python3 servidor/servidor.py
# abre http://localhost:8080
```

Variables de entorno (todas opcionales):

| Variable | Por defecto | Para qué |
|---|---|---|
| `PUERTO` / `PORT` | 8080 | Puerto de escucha |
| `TAKTAK_DB` | `servidor/taktak.db` | Fichero SQLite |
| `TAKTAK_ADMIN` | `taktak.messenger@gmail.com` | Correo del admin |
| `MAX_BANNERS` | 20 | Máximo de banners |
| `MAX_DIAS` | 365 | Días que dura un enlace |
| `TOPE_POR_HORA` | 10 | Enlaces por IP y hora |
| `SESION_HORAS` | 12 | Duración de la sesión de admin |

## Poner en internet (Render, plan gratis)

1. Sube este repositorio a GitHub.
2. En Render: **New → Web Service** → conecta el repo.
3. Render lee `render.yaml` automáticamente; si no:
   - **Start Command:** `python3 servidor/servidor.py`
   - **Build Command:** (vacío)
4. Crea el servicio y Render te da una URL `https://tu-servicio.onrender.com`.

> ⚠️ En el plan **gratis** el servicio se duerme y **la base de datos se borra**
> en cada reinicio. Para conservar los enlaces: plan de pago + disco en
> `/var/data` + variable `TAKTAK_DB=/var/data/taktak.db`.

## Conectar el dominio `taktak.brave`

El dominio Unstoppable hoy apunta a IPFS (la web estática). Para que los
**enlaces cortos funcionen**, el dominio debe apuntar a **este servidor**:

1. En Unstoppable Domains: **Manage → Website / Redirect**.
2. Cambia el destino de IPFS a tu URL de Render
   (`https://tu-servicio.onrender.com`) o a un dominio propio.
3. Guarda. Los enlaces `taktak.brave/<corto>` ya resolverán en el servidor.

Alternativa recomendada: comprar un dominio normal (`.com`, `.app`), apuntar
con CNAME a Render, y usar el `.brave` solo como marca.

## Aviso

- Legal: no recojas dinero ni prometas premios sin licencia.
- Al pagar por publicidad, el usuario final debe ver el anuncio por escrito.
