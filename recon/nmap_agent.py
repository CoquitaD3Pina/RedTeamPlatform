"""
nmap_agent.py — Escaneo Nmap con output XML guardado como evidencia real.
"""
import subprocess
import re
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from core.models import TargetProfile
from utils.logger import log
import config


def _guardar_evidencia(ip: str, output_xml: str, output_txt: str):
    """Guarda el output real de Nmap como evidencia en carpeta evidencias/."""
    carpeta = Path(__file__).parent.parent / "evidencias" / ip.replace(".", "_")
    carpeta.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Guardar XML crudo
    xml_path = carpeta / f"nmap_{ts}.xml"
    xml_path.write_text(output_xml, encoding="utf-8")

    # Guardar texto legible
    txt_path = carpeta / f"nmap_{ts}.txt"
    txt_path.write_text(output_txt, encoding="utf-8")

    log.info(f"Evidencia Nmap guardada: {carpeta}")
    return str(carpeta)


def _parse_nmap_xml(xml_content: str):
    """Parsea el XML de Nmap para extraer datos reales con versiones exactas."""
    puertos, servicios, banners = [], [], {}
    os_family, architecture = "desconocido", "x64"

    try:
        root = ET.fromstring(xml_content)

        # OS detection real
        for osmatch in root.iter("osmatch"):
            os_name = osmatch.get("name", "")
            if os_name:
                name_lower = os_name.lower()
                if "windows" in name_lower:
                    os_family = "Windows"
                elif any(k in name_lower for k in ["linux", "ubuntu", "debian", "centos", "kali"]):
                    os_family = "Linux"
                elif "macos" in name_lower or "mac os" in name_lower:
                    os_family = "macOS"
                else:
                    os_family = os_name.split()[0]
                break

        # Puertos y servicios con versiones REALES
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            portid = int(port.get("portid", 0))
            puertos.append(portid)

            svc = port.find("service")
            if svc is not None:
                name    = svc.get("name", "unknown")
                product = svc.get("product", "")
                version = svc.get("version", "")
                extra   = svc.get("extrainfo", "")

                # Construir descripción real con versión exacta
                svc_str = name
                if product:
                    svc_str = product
                if version:
                    svc_str += f" {version}"
                if extra:
                    svc_str += f" ({extra})"

                servicios.append(svc_str)

                # Banner real
                banner_str = svc_str
                if banner_str and banner_str != name:
                    banners[str(portid)] = banner_str

        # Architecture
        for osclass in root.iter("osclass"):
            arch = osclass.get("type", "")
            if "64" in arch or "x86-64" in arch:
                architecture = "x64"
            elif "32" in arch:
                architecture = "x86"
            break

    except ET.ParseError as e:
        log.error(f"Error parseando XML de Nmap: {e}")

    return puertos, servicios, banners, os_family, architecture


def escanear(ip: str) -> TargetProfile | None:
    log.info(f"FASE 1 — Iniciando reconocimiento sobre {ip}...")

    # Verificar conectividad básica primero
    try:
        ping = subprocess.run(
            ["ping", "-n", "1", "-w", "2000", ip] if __import__("sys").platform == "win32"
            else ["ping", "-c", "1", "-W", "2", ip],
            capture_output=True, timeout=5
        )
        if ping.returncode != 0:
            log.warning(f"El objetivo {ip} no responde a ping — puede estar filtrado o apagado.")
    except Exception:
        pass

    nmap_path = config.NMAP_PATH
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_output_file = Path(__file__).parent.parent / "evidencias" / f"nmap_raw_{ip.replace('.','_')}_{ts}.xml"
    xml_output_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        nmap_path,
        "-sV",           # Version detection — datos reales de versiones
        "-O",            # OS detection
        "--osscan-guess",
        "-sC",           # Default scripts
        "-T4",           # Timing agresivo
        "-p-",           # Todos los puertos
        "--open",        # Solo puertos abiertos
        "-oX", str(xml_output_file),  # Output XML para evidencia
        ip
    ]

    try:
        log.info(f"Ejecutando escaneo completo contra {ip}...")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        output_txt = result.stdout + result.stderr

        if result.returncode not in [0, 1]:
            log.error(f"El reconocimiento no pudo completarse correctamente. Código: {result.returncode}")

        # Leer XML generado
        xml_content = ""
        if xml_output_file.exists():
            xml_content = xml_output_file.read_text(encoding="utf-8")
            # Guardar también copia legible
            _guardar_evidencia(ip, xml_content, output_txt)
        else:
            log.warning("No se generó archivo XML — usando parser de texto como fallback.")
            return _parse_texto_fallback(ip, output_txt)

        puertos, servicios, banners, os_family, architecture = _parse_nmap_xml(xml_content)

        if not puertos:
            log.warning(f"No se detectaron puertos abiertos en {ip}.")

        log.info(f"Reconocimiento completado: {len(puertos)} puertos, OS: {os_family}")

        perfil = TargetProfile(ip)
        perfil.os_family    = os_family
        perfil.services     = servicios
        perfil.ports        = puertos
        perfil.architecture = architecture
        perfil.osint_data   = {"banners": banners}
        return perfil

    except subprocess.TimeoutExpired:
        log.error(f"El reconocimiento excedió el tiempo máximo permitido para {ip}.")
        return None
    except FileNotFoundError:
        log.error(f"Nmap no encontrado en: {nmap_path}. Verifique la configuración.")
        return None
    except Exception as e:
        log.error(f"El reconocimiento no pudo completarse: {e}")
        return None


def _parse_texto_fallback(ip: str, output: str) -> TargetProfile | None:
    """Fallback: parsea el output de texto de Nmap si el XML falla."""
    puertos, servicios = [], []
    os_family, architecture = "desconocido", "x64"

    for linea in output.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(.*)", linea)
        if m:
            puertos.append(int(m.group(1)))
            svc_name = m.group(3)
            svc_extra = m.group(4).strip()
            servicios.append(f"{svc_name} {svc_extra}".strip() if svc_extra else svc_name)

        if "Running:" in linea or "OS details:" in linea:
            if "Windows" in linea:
                os_family = "Windows"
            elif "Linux" in linea:
                os_family = "Linux"
            elif "macOS" in linea or "Mac OS" in linea:
                os_family = "macOS"

        if "64-bit" in linea or "x86-64" in linea:
            architecture = "x64"
        elif "32-bit" in linea:
            architecture = "x86"

    if not puertos:
        log.warning(f"No se detectaron puertos abiertos en {ip}.")

    perfil = TargetProfile(ip)
    perfil.os_family    = os_family
    perfil.services     = servicios
    perfil.ports        = puertos
    perfil.architecture = architecture
    return perfil