import sys
from recon.nmap_agent import escanear
from ai.attack_planner import analizar
from exploits.exploit_dispatcher import despachar_exploit
from post_exploitation.post_exploit import ejecutar_post_explotacion
from reporting.reporte_pdf import RedTeamReport

# ============ CONFIGURACION ============
TARGET_IP = "192.168.1.88"

MODULOS = {
    "reconocimiento":   True,
    "analisis_ia":      True,
    "explotacion":      False,
    "post_explotacion": False,
    "reporte_pdf":      True,
}
# =======================================

print("\n" + "="*60)
print(" 🛡  AUTONOMOUS AI RED TEAM PLATFORM")
print("="*60)

# FASE 1 — RECONOCIMIENTO
perfil = None
if MODULOS["reconocimiento"]:
    perfil = escanear(TARGET_IP)

# FASE 2 — ANÁLISIS CON IA
analisis = ""
if MODULOS["analisis_ia"] and perfil:
    print("\n🤖 FASE 2: Análisis con IA...\n")
    analisis = analizar(perfil)

# FASE 3 — EXPLOTACIÓN
evidencia = ""
if MODULOS["explotacion"] and perfil:
    evidencia = despachar_exploit(perfil)

# FASE 4 — POST-EXPLOTACIÓN
evidencia_post = ""
if MODULOS["post_explotacion"] and "ÉXITO" in str(evidencia):
    print("\n🔓 FASE 4: Post-explotación...\n")
    evidencia_post = ejecutar_post_explotacion(TARGET_IP)
    evidencia += evidencia_post

# FASE 5 — REPORTE PDF (ahora recibe el perfil)
if MODULOS["reporte_pdf"] and perfil:
    print("\n📋 FASE 5: Generando reporte PDF...\n")
    reporte = RedTeamReport(TARGET_IP, perfil.os_family)
    reporte.generar(analisis, evidencia, perfil=perfil)

print("\n" + "="*60)
print(" ✅ EVALUACIÓN COMPLETADA")
print("="*60)