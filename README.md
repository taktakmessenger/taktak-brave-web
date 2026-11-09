# TakTak.brave

Web3 Link Shortener & Ad Engine — acortador de enlaces con página de anuncio.

## Estructura

- `index.html` — la web (interfaz).
- `servidor/servidor.py` — el servidor real (enlaces, banners, anuncio de 3 s).
- `publicidad/` — imágenes y textos para redes sociales.
- `render.yaml` — configuración de despliegue en Render.

## Ejecutar en local

```bash
python3 servidor/servidor.py
# abre http://localhost:8080
```

## Cómo funciona

1. El usuario pega una URL y el servidor crea un enlace corto real (`/xxxxxxx`).
2. Quien abre ese enlace ve un **anuncio durante 3 segundos** y luego es
   redirigido a la web original.
3. El administrador (`taktak.messenger@gmail.com`) gestiona los banners desde
   el panel, y se guardan en el servidor (los ve todo el mundo).

Detalles en `servidor/README.md`.
