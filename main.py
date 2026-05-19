import sys
from recon.nmap_agent import escanear
from ai.attack_planner import analizar
from exploits.linux_exploits import explotar as explotar_linux
from post_exploitation.post_exploit import ejecutar_post_explotacion
from reporting.reporte_pdf import RedTeamReport

# ============ CONFIGURACION ============
TARGET_IP = "192.168.56.20"
MODULOS = {
    "reconocimiento": True,
    "analisis_ia": True,
    "explotacion": True,
    "post_explotacion": True,
    "reporte_pdf": True,
}
# =======================================

print("\n" + "="*60)
print("   🛡 AUTONOMOUS AI RED TEAM PLATFORM")
print("="*60)

# FASE 1 — RECONOCIMIENTO
if MODULOS["reconocimiento"]:
    perfil = escanear(TARGET_IP)

# FASE 2 — ANÁLISIS CON IA
analisis = ""
if MODULOS["analisis_ia"]:
    print("\n🤖 FASE 2: Análisis con IA...\n")
    analisis = analizar(perfil)

# FASE 3 — EXPLOTACIÓN
evidencia = ""
if MODULOS["explotacion"]:
    if perfil.os_family == "linux":
        evidencia = explotar_linux(perfil)
    elif perfil.os_family in ["windows", "windows7"]:
        print("⚠️  Módulo Windows próximamente")
    else:
        print(f"⚠️  OS {perfil.os_family} — sin módulo de explotación disponible")

# FASE 4 — POST-EXPLOTACIÓN
evidencia_post = ""
if MODULOS["post_explotacion"] and "ÉXITO" in str(evidencia):
    print("\n🔓 FASE 4: Post-explotación...\n")
    evidencia_post = ejecutar_post_explotacion(TARGET_IP)
    evidencia += evidencia_post

# FASE 5 — REPORTE PDF
if MODULOS["reporte_pdf"]:
    print("\n📋 FASE 5: Generando reporte PDF...\n")
    reporte = RedTeamReport(TARGET_IP, perfil.os_family)
    reporte.generar(analisis, evidencia)

print("\n" + "="*60)
print("   ✅ EVALUACIÓN COMPLETADA")
print("="*60)