# -*- coding: utf-8 -*-
"""
Módulo phishing/mailer
======================
Envío de correos para campañas de SIMULACIÓN de phishing autorizadas
(ciberconcienciación corporativa), estilo GoPhish:

    • SMTP configurable (host, puerto, TLS/SSL, credenciales).
    • Plantilla de correo con marcadores {{ORG}} y {{ENLACE}}.
    • DRY_RUN=true por defecto: muestra los correos que ENVIARÍA sin enviarlos.
    • Límite duro de destinatarios (anti-abuso).

Riesgo: ALTO → exige AUTHORIZED si DRY_RUN=false.
"""

import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from core.base_module import BaseModulo, ModuloError

MAX_DESTINATARIOS = 200
PLANTILLA_CORREO = Path(__file__).resolve().parent.parent.parent / "templates" / "phishing" / "correo_plantilla.html"


class Mailer(BaseModulo):
    """Envía correos de simulación de phishing vía SMTP (con dry-run)."""

    NAME = "phishing/mailer"
    CATEGORIA = "phishing"
    DESCRIPCION = ("Envío SMTP para campañas de simulación de phishing autorizadas. "
                   "DRY_RUN=true por defecto (previsualiza sin enviar).")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "GoPhish · juzeon/fast-mail-bomber (concepto inverso: simulación ética)"

    def definir_opciones(self) -> None:
        self.opciones.declarar("SMTP_HOST", "", True, "Servidor SMTP del laboratorio/corporativo")
        self.opciones.declarar("SMTP_PORT", "587", False, "Puerto SMTP (587 STARTTLS / 465 SSL / 25 plano)")
        self.opciones.declarar("SMTP_USER", "", False, "Usuario SMTP")
        self.opciones.declarar("SMTP_PASS", "", False, "Contraseña SMTP")
        self.opciones.declarar("FROM", "seguridad@empresa.local", True, "Remitente visible")
        self.opciones.declarar("TO", "", True, "Destinatarios separados por coma")
        self.opciones.declarar("ASUNTO", "Simulación de seguridad", False, "Asunto del correo")
        self.opciones.declarar("ENLACE", "http://127.0.0.1:8080/", False, "Enlace a la página de simulación")
        self.opciones.declarar("ORG", "Mi Empresa", False, "Nombre de la organización")
        self.opciones.declarar("DRY_RUN", "true", False, "true = previsualizar sin enviar")

    def _cuerpo(self) -> str:
        """Lee la plantilla de correo y sustituye marcadores."""
        if PLANTILLA_CORREO.exists():
            cuerpo = PLANTILLA_CORREO.read_text(encoding="utf-8")
        else:
            cuerpo = ("<p>Hola,</p><p>{{ORG}} está realizando una simulación de seguridad. "
                      "Revisa tu cuenta aquí: <a href='{{ENLACE}}'>Revisar ahora</a></p>")
        return (cuerpo.replace("{{ORG}}", self.opt("ORG", "Mi Empresa"))
                      .replace("{{ENLACE}}", self.opt("ENLACE"))
                      .replace("{{FECHA}}", time.strftime("%d/%m/%Y")))

    def ejecutar(self) -> dict:
        destinatarios = [d.strip() for d in self.opt("TO").split(",") if d.strip()]
        if not destinatarios:
            raise ModuloError("No hay destinatarios (opción TO)")
        if len(destinatarios) > MAX_DESTINATARIOS:
            raise ModuloError(f"Máximo {MAX_DESTINATARIOS} destinatarios por seguridad operacional")

        dry_run = self.opt_bool("DRY_RUN", True)
        asunto = self.opt("ASUNTO", "Simulación de seguridad")
        remitente = self.opt("FROM")
        cuerpo = self._cuerpo()

        # --- Modo previsualización ---------------------------------------
        if dry_run:
            vista = f"De: {remitente}\nPara: {', '.join(destinatarios)}\nAsunto: {asunto}\n\n{cuerpo[:600]}..."
            return {
                "resumen": f"DRY_RUN: se enviarían {len(destinatarios)} correos (no enviado)",
                "modo": "dry_run",
                "vista_previa": vista,
                "destinatarios": destinatarios,
            }

        # --- Envío real ----------------------------------------------------
        host = self.opt("SMTP_HOST")
        puerto = self.opt_int("SMTP_PORT", 587)
        enviados, errores = 0, []

        for destino in destinatarios:
            mensaje = MIMEMultipart("alternative")
            mensaje["From"] = remitente
            mensaje["To"] = destino
            mensaje["Subject"] = asunto
            mensaje.attach(MIMEText(cuerpo, "html", "utf-8"))
            try:
                if puerto == 465:
                    servidor = smtplib.SMTP_SSL(host, puerto, timeout=10)
                else:
                    servidor = smtplib.SMTP(host, puerto, timeout=10)
                    try:
                        servidor.starttls()
                    except smtplib.SMTPNotSupportedError:
                        pass  # servidor sin STARTTLS (laboratorio)
                if self.opt("SMTP_USER"):
                    servidor.login(self.opt("SMTP_USER"), self.opt("SMTP_PASS"))
                servidor.sendmail(remitente, [destino], mensaje.as_string())
                servidor.quit()
                enviados += 1
            except (smtplib.SMTPException, OSError) as err:
                errores.append({"destinatario": destino, "error": str(err)})

        return {
            "resumen": f"Enviados {enviados}/{len(destinatarios)} correos de simulación",
            "modo": "envio_real",
            "enviados": enviados,
            "errores": errores,
        }
