"""
osint_agent.py
Módulo de reconocimiento pasivo OSINT.
Recopila información sobre el target sin interactuar directamente con él
de forma agresiva: DNS, whois, reverse DNS, ping sweep y banner grabbing básico.
"""

import socket
import subprocess
import re
import json
from datetime import datetime
from utils.logger import log
from core.database import RedTeamDB

# ─────────────────────────────────────────────
#  Funciones de reconocimiento pasivo (local)
# ─────────────────────────────────────────────

def _reverse_dns(ip: str) -> str:
    """Intenta resolver el PTR record de la IP."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        log.info(f"  ↳ Reverse DNS: {ip} → {hostname}")
        return hostname
    except socket.herror:
        log.info(f"  ↳ Reverse DNS: sin PTR record para {ip}")
        return ""
    except Exception as e:
        log.warning(f"  ↳ Error en reverse DNS: {e}")
        return ""


def _dns_lookup(hostname: str) -> dict:
    """Resuelve registros DNS básicos del hostname."""
    if not hostname:
        return {}

    resultados = {}
    try:
        # Resolución A
        ip_a = socket.gethostbyname(hostname)
        resultados["A"] = ip_a
        log.info(f"  ↳ DNS A: {hostname} → {ip_a}")
    except Exception:
        pass

    # Registros MX y NS vía nslookup en local
    for tipo in ["MX", "NS", "TXT"]:
        try:
            proc = subprocess.run(
                ["nslookup", "-type=" + tipo, hostname],
                capture_output=True, text=True, timeout=8
            )
            if proc.stdout and "can't find" not in proc.stdout.lower():
                resultados[tipo] = proc.stdout.strip()[:300]
        except Exception:
            pass

    return resultados


def _banner_grabbing(ip: str, puertos: list) -> dict:
    """Conecta a puertos conocidos y lee el banner de bienvenida."""
    banners = {}
    puertos_objetivo = [p for p in puertos if p in [21, 22, 23, 25, 80, 110, 143, 443, 3306, 5432]]

    for puerto in puertos_objetivo[:5]:  # Máximo 5 para no tardar
        try:
            with socket.create_connection((ip, puerto), timeout=4) as s:
                s.settimeout(4)
                try:
                    banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                except Exception:
                    banner = ""

                if not banner:
                    # Para HTTP enviamos HEAD
                    if puerto in [80, 443, 8080, 8443]:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        try:
                            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                        except Exception:
                            pass

                if banner:
                    banners[str(puerto)] = banner[:200]
                    log.info(f"  ↳ Banner {puerto}/tcp: {banner[:60].strip()}...")
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        except Exception as e:
            log.debug(f"  ↳ Banner {puerto}: {e}")

    return banners


def _ping_sweep_subred(ip: str) -> list:
    """Descubre hosts activos en la misma subred /24 con ping."""
    partes = ip.split(".")
    if len(partes) != 4:
        return []

    subred = ".".join(partes[:3])
    hosts_activos = []
    log.info(f"  ↳ Ping sweep en {subred}.1-254 (puede tardar ~20s)...")

    # En Windows usamos ping con timeout corto
    for i in range(1, 255):
        objetivo = f"{subred}.{i}"
        if objetivo == ip:
            continue
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "300", objetivo],
                capture_output=True, text=True, timeout=2
            )
            if "TTL=" in result.stdout or "ttl=" in result.stdout:
                hosts_activos.append(objetivo)
                log.info(f"  ↳ Host activo: {objetivo}")
        except Exception:
            pass

    return hosts_activos


def _whois_local(ip: str) -> str:
    """Intenta obtener info whois usando el comando del sistema."""
    try:
        result = subprocess.run(
            ["whois", ip],
            capture_output=True, text=True, timeout=10
        )
        if result.stdout:
            # Extraer solo líneas relevantes
            lineas_clave = []
            for linea in result.stdout.split("\n"):
                lower = linea.lower()
                if any(k in lower for k in ["netname", "country", "org", "descr",
                                             "organization", "inetnum", "cidr", "route"]):
                    lineas_clave.append(linea.strip())
            return "\n".join(lineas_clave[:10])
    except FileNotFoundError:
        return "whois no disponible en este sistema"
    except Exception as e:
        return f"Error whois: {e}"
    return ""


def _detectar_ttl_os(ip: str) -> str:
    """Estima el OS por el TTL de la respuesta ICMP."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", ip],
            capture_output=True, text=True, timeout=5
        )
        match = re.search(r"TTL=(\d+)", result.stdout, re.IGNORECASE)
        if match:
            ttl = int(match.group(1))
            if ttl <= 64:
                return f"Linux/Unix (TTL={ttl})"
            elif ttl <= 128:
                return f"Windows (TTL={ttl})"
            else:
                return f"Cisco/Network (TTL={ttl})"
    except Exception:
        pass
    return "desconocido"


# ─────────────────────────────────────────────
#  Función principal del módulo
# ─────────────────────────────────────────────

def ejecutar_osint(perfil) -> dict:
    """
    Ejecuta reconocimiento pasivo OSINT sobre el target.
    Enriquece el perfil con los datos recopilados y los persiste en la DB.

    Args:
        perfil: TargetProfile con al menos .ip y .ports definidos

    Returns:
        dict con todos los datos OSINT recopilados
    """
    ip = perfil.ip
    log.info(f"🌐 Iniciando OSINT pasivo contra {ip}...")

    osint_data = {
        "timestamp":      datetime.now().isoformat(),
        "ip":             ip,
        "hostname":       "",
        "dns":            {},
        "os_por_ttl":     "",
        "whois":          "",
        "banners":        {},
        "hosts_subred":   [],
        "resumen":        [],
    }

    # 1. Reverse DNS
    log.info("[OSINT] 1/5 Reverse DNS...")
    hostname = _reverse_dns(ip)
    osint_data["hostname"] = hostname

    # 2. DNS Lookup si hay hostname
    log.info("[OSINT] 2/5 DNS lookup...")
    if hostname:
        osint_data["dns"] = _dns_lookup(hostname)

    # 3. Fingerprint OS por TTL (pasivo, solo ping)
    log.info("[OSINT] 3/5 Fingerprint por TTL...")
    osint_data["os_por_ttl"] = _detectar_ttl_os(ip)

    # 4. Banner grabbing en puertos detectados por nmap
    log.info("[OSINT] 4/5 Banner grabbing...")
    puertos = perfil.ports if hasattr(perfil, "ports") and perfil.ports else []
    osint_data["banners"] = _banner_grabbing(ip, puertos)

    # 5. Whois
    log.info("[OSINT] 5/5 Whois...")
    osint_data["whois"] = _whois_local(ip)

    # Construir resumen de hallazgos
    resumen = []
    if hostname:
        resumen.append(f"Hostname resuelto: {hostname}")
    if osint_data["os_por_ttl"]:
        resumen.append(f"OS estimado por TTL: {osint_data['os_por_ttl']}")
    if osint_data["banners"]:
        resumen.append(f"Banners capturados en puertos: {list(osint_data['banners'].keys())}")
    if osint_data["dns"]:
        resumen.append(f"Registros DNS encontrados: {list(osint_data['dns'].keys())}")
    if osint_data["whois"] and "no disponible" not in osint_data["whois"]:
        resumen.append("Datos Whois obtenidos")

    osint_data["resumen"] = resumen

    # Guardar en el perfil
    perfil.osint_data = osint_data

    # Persistir en base de datos
    try:
        db = RedTeamDB()
        db.registrar_osint(ip, osint_data)
    except Exception as e:
        log.warning(f"No se pudo guardar OSINT en BD: {e}")

    log.info(f"✅ OSINT completado. Hallazgos: {len(resumen)}")
    for item in resumen:
        log.info(f"  → {item}")

    return osint_data
