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
    perfil.ports = _extraer_puertos(output)
    print(f"✅ OS: {perfil.os_family.upper()} | Arquitectura: {perfil.architecture}")
    print(f"   Puertos abiertos: {perfil.ports}")
    return perfil


def _detectar_os(output):
    lower = output.lower()

    # Windows
    if "windows xp" in lower or "windows server 2003" in lower:
        return "windowsxp"
    elif "windows 7" in lower or "windows server 2008" in lower:
        return "windows7"
    elif "windows 8" in lower:
        return "windows8"
    elif "windows 10" in lower:
        return "windows10"
    elif "windows 11" in lower:
        return "windows11"
    elif "windows server 2012" in lower:
        return "windows2012"
    elif "windows server 2016" in lower:
        return "windows2016"
    elif "windows server 2019" in lower:
        return "windows2019"
    elif "windows server 2022" in lower:
        return "windows2022"
    elif "windows" in lower or "microsoft" in lower or "cpe:/o:microsoft" in lower:
        return "windows"

    # Apple iOS (iPhone/iPad) — ANTES que Cisco IOS
    elif any(x in lower for x in ["iphone", "ipad", "ipod", "apple ios",
                                   "ios device", "bonjour", "airplay",
                                   "itunes", "cfnetwork"]):
        return "ios_apple"

    # Cisco IOS
    elif any(x in lower for x in ["cisco ios", "cisco adaptive",
                                   "cisco router", "cisco switch",
                                   "cpe:/o:cisco:ios"]):
        return "cisco_ios"

    # macOS
    elif any(x in lower for x in ["mac os x", "macos", "darwin", "os x"]):
        return "macos"

    # Android
    elif "android" in lower:
        return "android"

    # Linux distros
    elif "kali" in lower:
        return "kali"
    elif "parrot" in lower:
        return "parrot"
    elif "ubuntu" in lower:
        return "ubuntu"
    elif "debian" in lower:
        return "debian"
    elif "centos" in lower:
        return "centos"
    elif "fedora" in lower:
        return "fedora"
    elif "red hat" in lower or "redhat" in lower or "rhel" in lower:
        return "redhat"
    elif "arch linux" in lower:
        return "arch"
    elif any(x in lower for x in ["linux", "cpe:/o:linux", "vsftpd", "apache",
                                   "telnetd", "metasploitable", "openssh"]):
        return "linux"

    # BSD / Unix
    elif "freebsd" in lower or "cpe:/o:freebsd" in lower:
        return "freebsd"
    elif "openbsd" in lower:
        return "openbsd"
    elif "netbsd" in lower:
        return "netbsd"
    elif "solaris" in lower or "sunos" in lower:
        return "solaris"
    elif "unix" in lower:
        return "unix"

    # Fallback por puertos típicos de iPhone
    elif _es_probablemente_iphone(output):
        return "ios_apple"

    return "desconocido"


def _es_probablemente_iphone(output):
    """Puerto 62078 = lockdownd de iOS, casi exclusivo de Apple."""
    return "62078" in output


def _detectar_arquitectura(output):
    if "x86-64" in output or "x64" in output or "64-bit" in output or "amd64" in output:
        return "x64"
    elif "x86" in output or "32-bit" in output or "i686" in output or "i386" in output:
        return "x86"
    elif "aarch64" in output or "arm64" in output:
        return "arm64"
    elif "arm" in output:
        return "arm"
    return "x64"


def _extraer_servicios(output):
    servicios = []
    for linea in output.split('\n'):
        if '/tcp' in linea and 'open' in linea:
            servicios.append(linea.strip())
    return servicios


def _extraer_puertos(output):
    puertos = []
    for linea in output.split('\n'):
        if '/tcp' in linea and 'open' in linea:
            try:
                puerto = int(linea.split('/tcp')[0].strip())
                puertos.append(puerto)
            except ValueError:
                pass
    return puertos