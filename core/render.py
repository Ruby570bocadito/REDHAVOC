# -*- coding: utf-8 -*-
"""
core.render
===========
Presentación de los resultados de los módulos EN la terminal.

Cada módulo devuelve un diccionario desde `ejecutar()`; esta capa lo traduce
a una salida Rica homogénea:

  • "resumen"        → panel destacado al principio.
  • listas de dict   → tabla (columnas = unión de claves, máx. 6).
  • listas planas    → columnas compactas.
  • dicts            → tabla clave/valor.
  • escalares        → línea "clave: valor".

Reglas de la casa:
  • Todo dato dinámico pasa por escape() (un valor con corchetes no puede
    romper el markup Rich ni inyectar estilos).
  • Las listas largas se truncan a MAX_FILAS filas con un aviso "… +N más";
    el detalle completo siempre queda en el informe JSON/MD/HTML.
  • Si una fila trae "severidad", la celda se colorea (critico/alto/medio/...).
"""

from rich.columns import Columns
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from core.advice import consejos_de_resultado, plan_de_workspace

# Truncado y límites de composición
MAX_FILAS = 25          # filas por tabla antes de truncar
MAX_COLUMNAS = 60       # elementos en columnas antes de truncar
MAX_CLAVES = 6          # columnas máximo por tabla de dicts

COLORES_SEV = {
    "critico": "bold red",
    "alto": "red",
    "medio": "yellow",
    "bajo": "green",
    "info": "dim",
}

# Claves de resultado conocidas → título de sección bonito
_TITULOS = {
    "abiertos": "Puertos abiertos",
    "hosts_vivos": "Hosts vivos",
    "subdominios": "Subdominios",
    "hallazgos": "Hallazgos",
    "ficheros": "Ficheros expuestos",
    "credenciales_validas": "Credenciales válidas",
    "validas": "Válidas",
    "hashes": "Hashes capturados",
    "resultados": "Resultados",
    "registro": "Registro",
    "pares_probados": "Pares probados",
    "probados": "Probados",
    "probadas": "Probadas",
    "confirmados": "Confirmados",
    "nameservers": "Nameservers",
    "inexistentes": "Inexistentes",
    "resolver": "Sin resolver",
    "errores": "Errores",
    "tecnica": "Técnica",
    "carpeta": "Carpeta de salida",
}

# Claves que NO merecen sección propia (metadatos sueltos, ya visibles en totales)
_CLAVES_MUDAS = {"resumen", "nota", "aviso", "recomendacion", "problema"}


def _fmt(valor) -> str:
    """Formatea un escalar de forma segura para Rich (con escape)."""
    if valor is None:
        return "—"
    if isinstance(valor, bool):
        return "sí" if valor else "no"
    if isinstance(valor, float):
        return f"{valor:.4g}"
    return escape(str(valor))


def _rendible(valor) -> bool:
    """True si el valor merece una sección propia en pantalla."""
    if valor is None:
        return False
    if isinstance(valor, (list, dict)):
        return len(valor) > 0
    return str(valor).strip() != ""


def _titulo_de(clave: str) -> str:
    """Título humano para una clave de resultado."""
    return _TITULOS.get(clave, clave.replace("_", " ").capitalize())


def _totales(datos: dict) -> str:
    """Línea de totales: '· Puertos abiertos: 3 · Hallazgos: 2'."""
    partes = []
    for clave, valor in datos.items():
        if isinstance(valor, list) and valor:
            partes.append(f"{_titulo_de(clave)}: {len(valor)}")
        elif isinstance(valor, dict) and valor:
            partes.append(f"{_titulo_de(clave)}: {len(valor)}")
    return "  ·  ".join(partes)


# ----------------------------------------------------------------------
# Renderizadores por forma de dato
# ----------------------------------------------------------------------
def _tabla_dicts(console, titulo: str, filas: list) -> None:
    """Lista de diccionarios → tabla con la unión de claves."""
    claves: list = []
    for fila in filas:
        if isinstance(fila, dict):
            for k in fila:
                if k not in claves:
                    claves.append(k)
    claves = claves[:MAX_CLAVES]
    tabla = Table(title=f"[bold white]{escape(titulo)}[/bold white] "
                        f"[dim]({len(filas)})[/dim]",
                  border_style="dim", title_justify="left", expand=False)
    for k in claves:
        tabla.add_column(_titulo_de(k).upper(), style="white",
                         overflow="fold", max_width=42)
    for fila in filas[:MAX_FILAS]:
        celdas = []
        for k in claves:
            v = fila.get(k) if isinstance(fila, dict) else None
            if k == "severidad" and str(v).lower() in COLORES_SEV:
                color = COLORES_SEV[str(v).lower()]
                celdas.append(f"[{color}]{escape(str(v))}[/{color}]")
            else:
                celdas.append(_fmt(v))
        tabla.add_row(*celdas)
    console.print(tabla)
    if len(filas) > MAX_FILAS:
        console.print(f"[dim]  … +{len(filas) - MAX_FILAS} más "
                      f"(detalle completo en el informe)[/dim]")


def _columnas(console, titulo: str, items: list) -> None:
    """Lista de textos → columnas compactas."""
    visibles = [f"[white]{_fmt(x)}[/white]" for x in items[:MAX_COLUMNAS]]
    console.print(Columns(visibles, padding=(0, 2), equal=False))
    if len(items) > MAX_COLUMNAS:
        console.print(f"[dim]  … +{len(items) - MAX_COLUMNAS} más "
                      f"(detalle completo en el informe)[/dim]")


def _seccion(console, titulo: str, valor) -> None:
    """Pinta una sección según la forma del valor."""
    if isinstance(valor, list) and all(isinstance(x, dict) for x in valor) and valor:
        _tabla_dicts(console, titulo, valor)
    elif isinstance(valor, list):
        if len(valor) >= 4 and all(len(str(x)) <= 28 for x in valor[:8]):
            console.print(f"[bold white]{escape(titulo)}[/bold white] "
                          f"[dim]({len(valor)})[/dim]")
            _columnas(console, titulo, valor)
        else:
            _lista_larga(console, titulo, valor)
    elif isinstance(valor, dict):
        _tabla_dicts(console, titulo, [{"clave": k, "valor": v} for k, v in valor.items()])
    else:
        console.print(f"[bold white]{escape(titulo)}[/bold white]: "
                      f"[valor]{_fmt(valor)}[/valor]")


def _lista_larga(console, titulo: str, items: list) -> None:
    """Lista de textos largos → una línea numerada por elemento."""
    console.print(f"[bold white]{escape(titulo)}[/bold white] [dim]({len(items)})[/dim]")
    for i, x in enumerate(items[:MAX_FILAS], 1):
        console.print(f"  [dim]{i:3}[/dim]  {_fmt(x)}")
    if len(items) > MAX_FILAS:
        console.print(f"[dim]  … +{len(items) - MAX_FILAS} más "
                      f"(detalle completo en el informe)[/dim]")


def _generico(console, clave: str, valor) -> None:
    """Fallback para claves no conocidas."""
    if isinstance(valor, list) and valor and all(isinstance(x, dict) for x in valor):
        _tabla_dicts(console, _titulo_de(clave), valor)
        return
    if isinstance(valor, list) and len(valor) >= 4 and all(
            isinstance(x, (str, int, float)) and len(str(x)) <= 28 for x in valor[:8]):
        console.print(f"[bold white]{escape(_titulo_de(clave))}[/bold white] "
                      f"[dim]({len(valor)})[/dim]")
        _columnas(console, _titulo_de(clave), valor)
        return
    if _rendible(valor):
        _seccion(console, _titulo_de(clave), valor)


# ----------------------------------------------------------------------
# API principal
# ----------------------------------------------------------------------
def mostrar_resultado(nombre_modulo: str, datos: dict, console) -> None:
    """Pinta el dict de resultados de un módulo de forma bonita y segura.

    No lanza excepciones ante datos raros: cualquier fallo de forma degrada
    a una impresión cruda escapada.
    """
    if not isinstance(datos, dict) or not datos:
        return

    # 1) Resumen destacado en panel
    resumen = datos.get("resumen")
    if resumen:
        console.print(Panel(
            f"[bold white]{escape(str(resumen))}[/bold white]",
            title=f"[bold white]resultado · {escape(nombre_modulo)}[/bold white]",
            border_style="dim", expand=False,
        ))

    # 2) Avisos/notas como líneas contextuales
    for clave in ("nota", "aviso", "recomendacion", "problema"):
        if datos.get(clave):
            icono = "[aviso][!][/aviso]" if clave in ("aviso", "problema") else "[info][*][/info]"
            console.print(f"{icono} {escape(str(datos[clave]))}")

    # 3) Línea de totales
    totales = _totales(datos)
    if totales:
        console.print(f"[dim]{totales}[/dim]")

    # 4) Secciones conocidas primero, luego el resto
    conocidas = [(k, v) for k, v in datos.items()
                 if k in _TITULOS and k not in _CLAVES_MUDAS and _rendible(v)]
    restantes = [(k, v) for k, v in datos.items()
                 if k not in _TITULOS and k not in _CLAVES_MUDAS and _rendible(v)]

    for clave, valor in conocidas:
        try:
            _seccion(console, _titulo_de(clave), valor)
        except Exception:  # noqa: BLE001 — el render NUNCA rompe un run
            console.print(f"[dim]{escape(clave)}: {escape(str(valor))[:200]}[/dim]")
    for clave, valor in restantes:
        try:
            _generico(console, clave, valor)
        except Exception:  # noqa: BLE001
            console.print(f"[dim]{escape(clave)}: {escape(str(valor))[:200]}[/dim]")


def mostrar_consejos(nombre_modulo: str, datos: dict, console) -> None:
    """Panel 'Siguientes pasos' con consejos accionables tras un resultado."""
    try:
        consejos = consejos_de_resultado(nombre_modulo, datos)
    except Exception:  # noqa: BLE001
        return
    if not consejos:
        return
    lineas = []
    for i, consejo in enumerate(consejos, 1):
        fila = f"[dim]{i}.[/dim] {escape(consejo.texto)}"
        if consejo.comando:
            fila += f"   [accent]→ {escape(consejo.comando)}[/accent]"
        lineas.append(fila)
    console.print(Panel("\n".join(lineas), title="siguientes pasos",
                        border_style="dim", expand=False, padding=(0, 1)))


def mostrar_plan(console, workspace) -> None:
    """Plan de batalla del workspace para el comando `consejos`."""
    try:
        consejos = plan_de_workspace(workspace)
    except Exception:  # noqa: BLE001
        console.print("[aviso][!][/aviso] No se pudo generar el plan.")
        return
    if not consejos:
        console.print("[dim]Sin consejos disponibles ahora mismo.[/dim]")
        return
    lineas = []
    for i, consejo in enumerate(consejos, 1):
        fila = f"[dim]{i}.[/dim] {escape(consejo.texto)}"
        if consejo.comando:
            fila += f"   [accent]→ {escape(consejo.comando)}[/accent]"
        lineas.append(fila)
    console.print(Panel("\n".join(lineas), title="plan de batalla del workspace",
                        border_style="dim", expand=False, padding=(0, 1)))
