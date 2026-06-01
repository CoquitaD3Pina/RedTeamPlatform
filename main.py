import sys
import argparse
import config
from d4y_utils.logger import log
from recon.nmap_agent import escanear
from ai.attack_planner import analizar
from exploits.exploit_dispatcher import despachar_exploit
from bruteforce.hydra_agent import ejecutar_fuerza_bruta
from post_exploitation.post_exploit import ejecutar_post_explotacion
from reporting.reporte_pdf import RedTeamReport
from osint.osint_agent import ejecutar_osint


def parse_args():
    parser = argparse.ArgumentParser(
        description="D4YSHELL — Autonomous Offensive Security Platform"
    )
    parser.add_argument(
        "--target",
        default=config.DEFAULT_TARGET,
        help=f"Dirección IP del objetivo (default: {config.DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--modules",
        default="all",
        help="Módulos a ejecutar separados por coma (recon,osint,ai,brute,exploit,post,report) o 'all'"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    target_ip = args.target

    if not target_ip:
        log.error("No se especificó un objetivo. Use --target <IP> para definir el target.")
        sys.exit(1)

    modulos_seleccionados = args.modules.lower().split(",")
    if "all" in modulos_seleccionados:
        modulos_seleccionados = ["recon", "osint", "ai", "brute", "exploit", "post", "report"]

    modulos_config = {
        "reconocimiento":   "recon"   in modulos_seleccionados,
        "osint":            "osint"   in modulos_seleccionados,
        "analisis_ia":      "ai"      in modulos_seleccionados,
        "fuerza_bruta":     "brute"   in modulos_seleccionados,
        "explotacion":      "exploit" in modulos_seleccionados,
        "post_explotacion": "post"    in modulos_seleccionados,
        "reporte_pdf":      "report"  in modulos_seleccionados,
    }

    config.validar_configuracion()

    log.info("=" * 60)
    log.info("  D4YSHELL — Autonomous Offensive Security Platform")
    log.info("=" * 60)
    log.info(f"Objetivo: {target_ip}")
    log.info(f"Módulos activos: {[k for k, v in modulos_config.items() if v]}")
    log.info("=" * 60)

    # FASE 1 — RECONOCIMIENTO
    perfil = None
    if modulos_config["reconocimiento"]:
        perfil = escanear(target_ip)
        if not perfil:
            log.error("El reconocimiento no pudo completarse. Verifique que el objetivo esté activo y accesible.")
    else:
        log.warning("Reconocimiento omitido. Los módulos subsecuentes requieren un perfil válido del objetivo.")

    # FASE 0.5 — OSINT
    if modulos_config["osint"] and perfil:
        log.info("FASE 0.5 — Reconocimiento pasivo en curso...")
        try:
            ejecutar_osint(perfil)
            log.info("Reconocimiento pasivo completado.")
        except Exception as e:
            log.error(f"El reconocimiento pasivo no pudo completarse: {e}")

    # FASE 2 — ANÁLISIS IA
    analisis = ""
    if modulos_config["analisis_ia"] and perfil:
        log.info("FASE 2 — Análisis de vulnerabilidades con IA en curso...")
        try:
            analisis = analizar(perfil)
            log.info("Análisis de vulnerabilidades completado.")
        except Exception as e:
            log.error(f"El análisis automatizado no pudo completarse: {e}")
            analisis = "El análisis automatizado no pudo completarse en esta evaluación."

    # FASE 2.5 — FUERZA BRUTA
    credenciales = ""
    if modulos_config["fuerza_bruta"] and perfil:
        log.info("FASE 2.5 — Auditoría de credenciales en curso...")
        try:
            credenciales = ejecutar_fuerza_bruta(perfil)
        except Exception as e:
            log.error(f"La auditoría de credenciales no pudo completarse: {e}")

    # FASE 3 — EXPLOTACIÓN
    evidencia = ""
    if modulos_config["explotacion"] and perfil:
        log.info("FASE 3 — Fase de explotación en curso...")
        try:
            evidencia = despachar_exploit(perfil)
        except Exception as e:
            log.error(
                "La fase de explotación automatizada no pudo completarse por "
                "restricciones de conectividad con el entorno remoto."
            )

    # FASE 4 — POST-EXPLOTACIÓN
    if modulos_config["post_explotacion"] and perfil:
        log.info("FASE 4 — Post-explotación en curso...")
        exito_previo = (
            "session" in str(evidencia).lower() or
            "backdoor" in str(evidencia).lower() or
            "opened" in str(evidencia).lower()
        )
        if exito_previo:
            try:
                evidencia_post = ejecutar_post_explotacion(target_ip)
                evidencia += "\n" + evidencia_post
            except Exception as e:
                log.error(f"La fase de post-explotación no pudo completarse: {e}")
        else:
            log.warning("Post-explotación omitida: no se detectó acceso exitoso en la fase anterior.")

    # FASE 5 — REPORTE PDF
    if modulos_config["reporte_pdf"] and perfil:
        log.info("FASE 5 — Generando reporte de evaluación...")
        try:
            reporte = RedTeamReport(target_ip, perfil.os_family)
            reporte.generar(analisis, evidencia, perfil, credenciales)
            log.info("Reporte generado exitosamente.")
        except Exception as e:
            log.error(f"El reporte no pudo generarse: {e}")

    log.info("=" * 60)
    log.info("  EVALUACIÓN COMPLETADA")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
