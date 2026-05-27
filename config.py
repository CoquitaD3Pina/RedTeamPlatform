import os
import sys
from dotenv import load_dotenv

# Cargar variables de entorno del archivo .env
load_dotenv()

# Configuración de SSH para Kali
KALI_IP   = os.getenv("KALI_IP",   "192.168.56.101")
KALI_USER = os.getenv("KALI_USER", "kali")
KALI_PASS = os.getenv("KALI_PASS")   # Sin default — debe estar en .env

# Configuración de Nmap
NMAP_PATH = os.getenv("NMAP_PATH", r"C:\Program Files (x86)\Nmap\nmap.exe")

# Target por defecto
DEFAULT_TARGET = os.getenv("DEFAULT_TARGET", "192.168.56.103")

# Configuración de IA
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "ollama/llama3.1:8b")

# Timeouts y Hilos
EXPLOIT_TIMEOUT      = int(os.getenv("EXPLOIT_TIMEOUT",      120))
POST_EXPLOIT_TIMEOUT = int(os.getenv("POST_EXPLOIT_TIMEOUT", 180))
HYDRA_THREADS        = int(os.getenv("HYDRA_THREADS",         16))

def validar_configuracion():
    """Valida que las variables críticas estén definidas antes de ejecutar."""
    errores = []
    if not KALI_PASS:
        errores.append("  ❌ KALI_PASS  — contraseña SSH de Kali (requerida)")
    if not KALI_IP:
        errores.append("  ❌ KALI_IP    — IP de la máquina Kali (requerida)")
    if not KALI_USER:
        errores.append("  ❌ KALI_USER  — usuario SSH de Kali (requerido)")
    if errores:
        print("\n⛔  CONFIGURACIÓN INCOMPLETA — Variables faltantes en .env:")
        for e in errores:
            print(e)
        print("\n  Edita el archivo .env con los valores correctos y vuelve a ejecutar.\n")
        sys.exit(1)
