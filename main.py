import sys
import argparse
import config
from utils.logger import log
from recon.nmap_agent import escanear
from ai.attack_planner import analizar
from exploits.exploit_dispatcher import despachar_exploit
from bruteforce.hydra_agent import ejecutar_fuerza_bruta
from post_exploitation.post_exploit import ejecutar_post_explotacion
from reporting.reporte_pdf import RedTeamReport

def parse_args():
    parser = argparse.ArgumentParser(
        description="🛡️ AUTONOMOUS AI RED TEAM PLATFORM v2.0 - Suite de Penetracion Automatizada"
    )
    parser.add_argument(
        "--target",
        default=config.DEFAULT_TARGET,
        help=f"IP del objetivo (default: {config.DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--modules",
        default="all",
        help="Módulos a ejecutar separados por coma (ej: recon,ai,brute,exploit,post,report) o 'all' (default)"
    )
    return parser.parse_args()

def main():
    args = parse_args()
    target_ip = args.target
    
    # Parsear módulos a ejecutar
    modulos_seleccionados = args.modules.lower().split(",")
    if "all" in modulos_seleccionados:
        modulos_seleccionados = ["recon", "ai", "brute", "exploit", "post", "report"]
        
    modulos_config = {
        "reconocimiento":   "recon" in modulos_seleccionados,
        "analisis_ia":      "ai" in modulos_seleccionados,
        "fuerza_bruta":     "brute" in modulos_seleccionados,
        "explotacion":      "exploit" in modulos_seleccionados,
        "post_explotacion": "post" in modulos_seleccionados,
        "reporte_pdf":      "report" in modulos_seleccionados,
    }

    log.info("============================================================")
    log.info(" 🛡️ AUTONOMOUS AI RED TEAM PLATFORM v2.0 (Cimientos Estables)")
    log.info("============================================================")
    log.info(f"Target Configurado: {target_ip}")
    log.info(f"Módulos Activos: {[k for k, v in modulos_config.items() if v]}")
    log.info("============================================================")

    # FASE 1 — RECONOCIMIENTO
    perfil = None
    if modulos_config["reconocimiento"]:
        perfil = escanear(target_ip)
    else:
        log.warning("Fase de Reconocimiento omitida. Los módulos subsecuentes podrían no ejecutarse correctamente sin un perfil del target.")

    # FASE 2 — ANÁLISIS CON IA
    analisis = ""
    if modulos_config["analisis_ia"] and perfil:
        log.info("🤖 FASE 2: Iniciando Análisis de vulnerabilidades con IA...")
        try:
            analisis = analizar(perfil)
            log.info("Análisis de IA completado.")
        except Exception as e:
            log.error(f"Error durante el análisis con IA (CrewAI/Ollama): {e}")
            analisis = "Error durante el análisis automático de IA."

    # FASE 2.5 — FUERZA BRUTA
    credenciales = ""
    if modulos_config["fuerza_bruta"] and perfil:
        log.info("🔑 FASE 2.5: Iniciando Fuerza bruta automatizada...")
        try:
            credenciales = ejecutar_fuerza_bruta(perfil)
        except Exception as e:
            log.error(f"Error durante la ejecución de fuerza bruta: {e}")

    # FASE 3 — EXPLOTACIÓN
    evidencia = ""
    if modulos_config["explotacion"] and perfil:
        log.info("💥 FASE 3: Iniciando Despachador de Exploits...")
        try:
            evidencia = despachar_exploit(perfil)
        except Exception as e:
            log.error(f"Error durante la fase de explotación: {e}")

    # FASE 4 — POST-EXPLOTACIÓN
    if modulos_config["post_explotacion"] and perfil:
        log.info("🔓 FASE 4: Iniciando Post-explotación...")
        # Verificamos si hubo éxito en la evidencia o si hay sesión registrada
        exito_previo = "session" in str(evidencia).lower() or "backdoor" in str(evidencia).lower() or "opened" in str(evidencia).lower()
        
        if exito_previo:
            try:
                evidencia_post = ejecutar_post_explotacion(target_ip)
                evidencia += "\n" + evidencia_post
            except Exception as e:
                log.error(f"Error durante la fase de post-explotación: {e}")
        else:
            log.warning("Omitiendo post-explotación: No se detectó acceso exitoso previo en la evidencia del exploit.")

    # FASE 5 — REPORTE PDF
    if modulos_config["reporte_pdf"] and perfil:
        log.info("📋 FASE 5: Generando reporte PDF...")
        try:
            reporte = RedTeamReport(target_ip, perfil.os_family)
            reporte.generar(analisis, evidencia, perfil, credenciales)
            log.info("Generación de reporte completada exitosamente.")
        except Exception as e:
            log.error(f"Error al generar reporte PDF: {e}")

    log.info("============================================================")
    log.info(" ✅ PROCESAMIENTO Y EVALUACIÓN COMPLETADOS")
    log.info("============================================================")

if __name__ == "__main__":
    main()