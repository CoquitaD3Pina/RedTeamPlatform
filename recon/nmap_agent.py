import subprocess

class TargetProfile:
    def __init__(self, ip):
        self.ip = ip
        self.os_family = "desconocido"
        self.os_version = ""
        self.architecture = "x64"
        self.services = []
        self.ports = []
        self.probable_cves = []
        self.attack_surface = []
        self.exploit_candidates = []
        self.nmap_output = ""

def escanear(ip):
    """Escanea la IP y retorna un TargetProfile completo"""
    print(f"\n🔍 Escaneando {ip}...")
    
    resultado = subprocess.run(
        [r"C:\Program Files (x86)\Nmap\nmap.exe",
         "-sV", "-O", "--osscan-guess", "--script", "banner", ip],
        capture_output=True, text=True
    )
    
    output = resultado.stdout
    perfil = TargetProfile(ip)
    perfil.nmap_output = output
    perfil.os_family = _detectar_os(output)
    perfil.architecture = _detectar_arquitectura(output)
    perfil.services = _extraer_servicios(output)
    
    print(f"✅ OS: {perfil.os_family.upper()} | Arquitectura: {perfil.architecture}")
    return perfil

def _detectar_os(output):
    lower = output.lower()
    if "windows 7" in lower or "windows server 2008" in lower:
        return "windows7"
    elif "windows" in lower and "microsoft" in lower:
        return "windows"
    elif "linux" in lower or "ubuntu" in lower or "debian" in lower:
        return "linux"
    elif "ios" in lower or "iphone" in lower or "apple" in lower:
        return "ios"
    elif "android" in lower:
        return "android"
    elif any(x in lower for x in ["vsftpd", "apache", "telnetd", "metasploitable"]):
        return "linux"
    return "desconocido"

def _detectar_arquitectura(output):
    if "x86-64" in output or "x64" in output or "64-bit" in output:
        return "x64"
    elif "x86" in output or "32-bit" in output or "i686" in output:
        return "x86"
    return "x64"

def _extraer_servicios(output):
    servicios = []
    for linea in output.split('\n'):
        if '/tcp' in linea and 'open' in linea:
            servicios.append(linea.strip())
    return servicios