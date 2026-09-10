# Guía de desarrollo — crea tus módulos REDHAVOC

## 1. Anatomía mínima (2 minutos)

Crea `modules/recon/mi_modulo.py`:

```python
# -*- coding: utf-8 -*-
"""Módulo recon/mi_modulo — describe aquí qué hace."""

import requests

from core.base_module import BaseModulo, ModuloError


class MiModulo(BaseModulo):

    NAME = "recon/mi_modulo"          # ruta única categoria/nombre
    CATEGORIA = "recon"
    DESCRIPCION = "Una frase clara: aparecerá en `search`."
    RIESGO = "bajo"                    # bajo | medio | alto
    AUTOR = "tu-nick"
    REFERENCIA = "herramienta que te inspiró (opcional)"
    ATTCK = ("T1087.002",)   # técnicas MITRE ATT&CK (opcional; las muestra info y attack)

    def definir_opciones(self) -> None:
        self.opciones.declarar("TARGET", "", True, "Host objetivo")
        self.opciones.declarar("EXTRA", "valor", False, "Parámetro opcional")

    def ejecutar(self) -> dict:
        host = self._objetivo_host(self.opt("TARGET"))
        try:
            resp = requests.get(f"https://{host}", timeout=self.opt_int("TIMEOUT", 5))
        except requests.RequestException as err:
            raise ModuloError(f"Sin respuesta de {host}: {err}")   # error limpio

        return {
            "resumen": f"{host} respondió {resp.status_code}",     # 1 línea destacada
            "codigo": resp.status_code,
            "detalle": dict(resp.headers),                         # dict/list arbitrarios
        }
```

Listo. El `ModuleManager` lo detectará en el próximo arranque:

```text
redhavoc > use recon/mi_modulo
redhavoc (recon/mi_modulo) > set TARGET example.com
redhavoc (recon/mi_modulo) > run
[+] Módulo completado en 0.3s.
[*] Informe: output/2026-09-10_12-00-01_recon-mi_modulo.json (+ .md)
```

## 2. Reglas del contrato

| Regla | Motivo |
|---|---|
| `ejecutar()` devuelve **dict** | El Reporter renderiza JSON+MD automáticamente |
| Fallos controlados → `raise ModuloError(msg)` | Mensaje limpio, sin traceback |
| Usa `self.opt()/opt_int()/opt_bool()` | Heredan los globales (TIMEOUT, THREADS...) |
| `_objetivo_host()` para limpiar URLs | El operador pega con/sin `http(s)://` |
| Categoría = carpeta | `modules/web/...` → `web/...` |
| `RIESGO=alto` solo si toca | Exige AUTHORIZED y queda bloqueado sin él |

## 3. Convenciones de nombres de opciones

Los comandos `run`/reportes reconocen estos nombres como "objetivo" (por
prioridad): `TARGET`, `URL`, `DOMAIN`, `LHOST`, `HOST`. Úsalos si aplica
para que el audit.log sea legible.

## 4. Módulos interactivos (handlers, servidores)

Si tu módulo mantiene la consola viva (listener, servidor HTTP), marca:

```python
    INTERACTIVO = True
```

El framework omite el spinner y deja la salida en vivo. Documenta cómo se
detiene (Ctrl+C, DURACION=N). Ejemplos de referencia:
`post/multi_handler` y `phishing/campaign_server`.

## 5. Registro de sesiones (para listeners)

Si aceptas conexiones persistentes, regístralas en el contexto compartido:

```python
    def ejecutar(self) -> dict:
        conn, addr = servidor.accept()
        sid = self._registrar(conn, addr)          # tu contador
        self.ctx.sesiones[sid] = {"conn": conn, "addr": addr, "abierta": time.time()}
```

El comando `sessions` / `sessions -i N` / `sessions -k N` del framework
opera sobre `self.ctx.sesiones`. Modelo: `modules/post/multi_handler.py`.

## 6. Tests para tu módulo

Añade `tests/test_mi_modulo.py`:

```python
from unittest import mock
from core.base_module import ModuloError

def test_mi_modulo_con_mock(manager):
    cls = manager.obtener("recon/mi_modulo")
    m = cls()
    m.opciones.set("TARGET", "example.com")
    resp = mock.Mock(headers={"Server": "nginx"}, status_code=200)
    with mock.patch("requests.get", return_value=resp):
        res = m.ejecutar()
    assert res["codigo"] == 200
```

Ejecuta la suite: `python3 -m pytest tests/ -q`.
Módulos offline preferibles: mockea la red; los tests deben correr sin
internet.

## 7. Checklist de calidad antes de PR

- [ ] Docstrings en español y comentarios útiles
- [ ] `NAME` único y categoría correcta
- [ ] Opciones con descripciones claras (aparecen en `show options`)
- [ ] Errores de red → `ModuloError`, nunca traceback
- [ ] `resumen` de una línea en el resultado
- [ ] `RIESGO` calibrado; alto solo si envía payloads o captura credenciales
- [ ] Test unitario (mock) incluido
- [ ] `python3 -m pytest tests/ -q` en verde

## 8. Empaquetar tu módulo como plugin (v2.1)

Un plugin es un pack con la misma estructura que `modules/`, instalable sin
tocar el código del framework:

```text
mi-pack/
└── modules/
    └── mi_categoria/          # a-z0-9_ (regex estricta)
        └── mi_modulo.py       # clase BaseModulo con NAME = "mi_categoria/mi_modulo"
```

Instalación y ciclo de vida:

```text
redhavoc > plugin install ./mi-pack          # ruta local (sin confirmación)
redhavoc > plugin install https://x/y.git    # remoto: exige AUTHORIZED + REVISADO
redhavoc > plugin list                       # categorías instaladas
redhavoc > use mi_categoria/mi_modulo        # ¡disponible al instante!
redhavoc > plugin del mi_categoria           # desinstalar
```

Notas de diseño:

- Los packs **remotos** se clonan con `git clone --depth 1` (hace falta el
  binario `git`) y exigen AUTHORIZED + escribir `REVISADO`: ejecutar código
  de terceros con privilegios del framework es una acción de máxima
  confianza, y queda registrada en `audit`.
- Los ficheros se copian a `plugins/<categoria>/`; el registro en caliente
  importa el `.py` con `importlib.util.spec_from_file_location` y añade las
  clases `BaseModulo` al `ModuleManager._registro`.
- Tras `plugin del`, los módulos desaparecen del arsenal al reiniciar la
  consola (los módulos ya importados viven en memoria hasta entonces).
