from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 HRFlowable, Table, TableStyle, PageBreak)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import date
import re
import hashlib
import time

ROJO        = colors.HexColor('#E63946')
AZUL_OSCURO = colors.HexColor('#1D3557')
AZUL_MEDIO  = colors.HexColor('#457B9D')
GRIS        = colors.HexColor('#F1FAEE')
NEGRO       = colors.HexColor('#000000')
VERDE       = colors.HexColor('#2D6A4F')
NARANJA     = colors.HexColor('#F4A261')
AMARILLO    = colors.HexColor('#E9C46A')

def get_estilos():
    styles = getSampleStyleSheet()
    return {
        'portada_titulo': ParagraphStyle('portada_titulo',
            fontSize=28, textColor=ROJO, fontName='Helvetica-Bold',
            alignment=TA_CENTER, spaceAfter=10),
        'portada_subtitulo': ParagraphStyle('portada_subtitulo',
            fontSize=14, textColor=AZUL_MEDIO, fontName='Helvetica',
            alignment=TA_CENTER, spaceAfter=6),
        'portada_info': ParagraphStyle('portada_info',
            fontSize=11, textColor=AZUL_OSCURO, fontName='Helvetica',
            alignment=TA_CENTER, spaceAfter=4),
        'confidencial': ParagraphStyle('confidencial',
            fontSize=13, textColor=ROJO, fontName='Helvetica-Bold',
            alignment=TA_CENTER, spaceAfter=4),
        'seccion': ParagraphStyle('seccion',
            fontSize=14, textColor=ROJO, fontName='Helvetica-Bold',
            spaceBefore=16, spaceAfter=6),
        'subseccion': ParagraphStyle('subseccion',
            fontSize=11, textColor=AZUL_MEDIO, fontName='Helvetica-Bold',
            spaceBefore=10, spaceAfter=4),
        'cuerpo': ParagraphStyle('cuerpo',
            fontSize=9, textColor=AZUL_OSCURO, fontName='Helvetica',
            spaceAfter=3, leading=14),
        'codigo': ParagraphStyle('codigo',
            fontSize=8, textColor=NEGRO, fontName='Courier',
            spaceAfter=2, leading=12, backColor=GRIS),
        'footer': ParagraphStyle('footer',
            fontSize=7, textColor=AZUL_MEDIO, fontName='Helvetica',
            alignment=TA_CENTER),
    }

def _safe_paragraph(texto, estilo):
    texto = str(texto).strip()
    texto = re.sub(r'&(?!amp;|lt;|gt;|apos;|quot;)', '&amp;', texto)
    try:
        return Paragraph(texto, estilo)
    except Exception:
        return Paragraph(texto.encode('ascii', 'ignore').decode(), estilo)

def _calcular_risk_score(perfil, evidencia):
    explotabilidad = 5.0
    impacto        = 5.0
    persistencia   = 4.0
    exposicion     = 5.0

    exito = "EXITO" in str(evidencia) or \
            ("session" in str(evidencia).lower() and "opened" in str(evidencia).lower()) or \
            "backdoor has been spawned" in str(evidencia).lower()

    puertos = perfil.ports if hasattr(perfil, 'ports') else []
    servicios = " ".join(perfil.services) if hasattr(perfil, 'services') else ""

    if exito:
        explotabilidad = 10.0
    elif len(puertos) > 10:
        explotabilidad = 8.0
    elif len(puertos) > 5:
        explotabilidad = 7.0
    elif len(puertos) > 0:
        explotabilidad = 5.0
    else:
        explotabilidad = 2.0

    if exito:
        impacto = 10.0
    elif any(s in servicios.lower() for s in ['ftp', 'telnet', 'ssh', 'mysql', 'smb']):
        impacto = 8.0
    elif len(puertos) > 0:
        impacto = 6.0
    else:
        impacto = 3.0

    if "root" in str(evidencia).lower() or "system" in str(evidencia).lower():
        persistencia = 9.0
    elif exito:
        persistencia = 7.0
    elif len(puertos) > 5:
        persistencia = 5.0
    else:
        persistencia = 2.0

    exposicion = min(10.0, len(puertos) * 0.8 + 2)
    total = round((explotabilidad + impacto + persistencia + exposicion) / 4, 2)

    def nivel(s):
        if s >= 9:   return "CRITICO"
        elif s >= 7: return "ALTO"
        elif s >= 5: return "MEDIO"
        else:        return "BAJO"

    return {
        "explotabilidad": (explotabilidad, nivel(explotabilidad)),
        "impacto":        (impacto,        nivel(impacto)),
        "persistencia":   (persistencia,   nivel(persistencia)),
        "exposicion":     (exposicion,     nivel(exposicion)),
        "total":          (total,          nivel(total)),
    }

def _extraer_vulnerabilidades(perfil):
    CVE_DB = {
        'vsftpd 2.3.4':  ("21/tcp",  "vsftpd",   "2.3.4",   "CVE-2011-2523", "10.0", "CRITICO"),
        'vsftpd':        ("21/tcp",  "vsftpd",   "?",       "CVE-2011-2523", "10.0", "CRITICO"),
        'apache 2.2':    ("80/tcp",  "Apache",   "2.2.x",   "CVE-2017-7679", "9.8",  "CRITICO"),
        'apache':        ("80/tcp",  "Apache",   "?",       "CVE-2017-7679", "9.8",  "CRITICO"),
        'telnet':        ("23/tcp",  "Telnet",   "Linux",   "N/A",           "9.1",  "CRITICO"),
        'mysql 5.0':     ("3306/tcp","MySQL",    "5.0.x",   "CVE-2012-2122", "7.5",  "ALTO"),
        'mysql':         ("3306/tcp","MySQL",    "?",       "CVE-2012-2122", "7.5",  "ALTO"),
        'openssh 4':     ("22/tcp",  "OpenSSH",  "4.x",     "CVE-2016-6515", "7.5",  "ALTO"),
        'openssh':       ("22/tcp",  "OpenSSH",  "?",       "CVE-2016-6515", "5.0",  "MEDIO"),
        'samba':         ("445/tcp", "Samba",    "3.x-4.x", "CVE-2017-7494", "9.8",  "CRITICO"),
        'ftp':           ("21/tcp",  "FTP",      "?",       "N/A",           "5.0",  "MEDIO"),
        'http':          ("80/tcp",  "HTTP",     "?",       "N/A",           "5.0",  "MEDIO"),
        'rdp':           ("3389/tcp","RDP",      "?",       "CVE-2019-0708", "9.8",  "CRITICO"),
        'smb':           ("445/tcp", "SMB",      "?",       "CVE-2017-0144", "9.3",  "CRITICO"),
        'irc':           ("6667/tcp","UnrealIRC","3.2.8.1", "CVE-2010-2075", "10.0", "CRITICO"),
    }

    encontradas = []
    servicios_raw = " ".join(perfil.services).lower() if hasattr(perfil, 'services') else ""

    for keyword, datos in CVE_DB.items():
        if keyword in servicios_raw and datos not in encontradas:
            encontradas.append(datos)

    if not encontradas and hasattr(perfil, 'ports') and perfil.ports:
        for puerto in perfil.ports[:3]:
            encontradas.append((f"{puerto}/tcp", "Servicio desconocido", "?", "N/A", "5.0", "MEDIO"))

    return encontradas if encontradas else [("N/A", "Sin servicios vulnerables detectados", "-", "N/A", "0", "BAJO")]

def _generar_attack_chain(perfil, evidencia):
    puertos_str = ", ".join(str(p) for p in perfil.ports[:5]) if hasattr(perfil, 'ports') and perfil.ports else "ninguno"
    servicios_count = len(perfil.services) if hasattr(perfil, 'services') else 0
    os_name = (perfil.os_family or "desconocido").upper()

    exito = ("session" in str(evidencia).lower() and "opened" in str(evidencia).lower()) or \
            "backdoor has been spawned" in str(evidencia).lower()

    cadena = [
        ("Reconocimiento",  f"Nmap scan -- {servicios_count} servicios detectados en {perfil.ip}", AZUL_MEDIO),
        ("Enumeracion",     f"OS: {os_name} | Puertos abiertos: {puertos_str}",                   AZUL_OSCURO),
    ]

    if exito:
        exploit_usado = "exploit desconocido"
        cve_usado     = "N/A"
        if "vsftpd" in str(evidencia).lower():
            exploit_usado = "unix/ftp/vsftpd_234_backdoor"
            cve_usado     = "CVE-2011-2523"
        elif "ms17_010" in str(evidencia).lower() or "eternalblue" in str(evidencia).lower():
            exploit_usado = "windows/smb/ms17_010_eternalblue"
            cve_usado     = "CVE-2017-0144"
        elif "usermap" in str(evidencia).lower():
            exploit_usado = "multi/samba/usermap_script"
            cve_usado     = "CVE-2007-2447"

        cadena += [
            ("Vulnerabilidad", f"{cve_usado} identificado",                            NARANJA),
            ("Explotacion",    f"Metasploit: {exploit_usado}",                         ROJO),
            ("Shell Remota",   "Sesion Meterpreter/shell abierta en puerto 4444",      ROJO),
            ("Acceso Obtenido","getuid confirmado -- Compromiso del sistema",            colors.HexColor('#8B0000')),
        ]
    else:
        cadena += [
            ("Analisis",      "Vulnerabilidades identificadas, explotacion no ejecutada o fallida", NARANJA),
            ("Reporte",       "Se documentan hallazgos para remediacion",                           AZUL_MEDIO),
        ]

    return cadena

def _generar_mitre(perfil, evidencia):
    tecnicas = [["Tecnica", "ID", "Descripcion", "Fase"]]

    os_key = (perfil.os_family or "").lower()
    servicios = " ".join(perfil.services).lower() if hasattr(perfil, 'services') else ""
    exito = "EXITO" in str(evidencia) or \
            ("session" in str(evidencia).lower() and "opened" in str(evidencia).lower())

    tecnicas.append(["Network Service Scan", "T1046", f"Escaneo Nmap contra {perfil.ip}", "Discovery"])

    if any(s in servicios for s in ['ftp', 'http', 'apache', 'vsftpd']):
        tecnicas.append(["Exploit Public-Facing App", "T1190", "Explotacion de servicio expuesto", "Initial Access"])
    if any(s in servicios for s in ['ssh', 'telnet', 'ftp']):
        tecnicas.append(["Brute Force", "T1110", "Fuerza bruta sobre servicios de acceso remoto", "Credential Access"])
    if 'smb' in servicios or 'samba' in servicios or 'windows' in os_key:
        tecnicas.append(["Exploit Public-Facing App", "T1190", "Explotacion SMB/EternalBlue", "Initial Access"])
    if exito:
        tecnicas.append(["Command & Scripting", "T1059", "Ejecucion de comandos via shell remota", "Execution"])
        tecnicas.append(["Data from Local System", "T1005", "Extraccion de archivos del sistema", "Collection"])
    if "root" in str(evidencia).lower():
        tecnicas.append(["Valid Accounts", "T1078", "Escalacion a cuenta root/SYSTEM", "Privilege Escalation"])

    return tecnicas

def _generar_hardening(perfil):
    servicios = " ".join(perfil.services).lower() if hasattr(perfil, 'services') else ""
    os_key    = (perfil.os_family or "").lower()

    inmediato    = []
    corto_plazo  = []
    mediano_plazo = [
        "Implementar segmentacion de red (VLANs)",
        "Configurar IDS/IPS (Snort/Suricata)",
        "Aplicar principio de minimo privilegio",
        "Implementar monitoreo de logs centralizado (SIEM)",
        "Realizar auditorias de seguridad trimestrales",
    ]

    if 'telnet' in servicios:
        inmediato.append("Deshabilitar Telnet (puerto 23) -- reemplazar con SSH")
    if 'vsftpd' in servicios or 'ftp' in servicios:
        inmediato.append("Actualizar vsftpd a version 3.0.5+ o migrar a SFTP")
    if 'apache' in servicios:
        inmediato.append("Actualizar Apache httpd a version 2.4.57+")
    if 'mysql' in servicios:
        inmediato.append("Actualizar MySQL a version 8.0+ y cambiar credenciales por defecto")
    if 'samba' in servicios or 'smb' in servicios:
        inmediato.append("Actualizar Samba y deshabilitar SMBv1")
    if 'rdp' in servicios or '3389' in servicios:
        inmediato.append("Parchear RDP -- aplicar parche BlueKeep (CVE-2019-0708)")

    if not inmediato:
        inmediato.append("Revisar y cerrar puertos innecesarios expuestos")
        inmediato.append("Actualizar todos los servicios a versiones recientes")

    corto_plazo = [
        "Implementar autenticacion SSH por llaves (deshabilitar contrasenas)",
        "Configurar Fail2ban para prevenir fuerza bruta",
        "Implementar firewall con reglas restrictivas",
    ]

    if 'windows' in os_key:
        corto_plazo.append("Habilitar Windows Defender y mantener actualizaciones automaticas")
        corto_plazo.append("Deshabilitar SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false")
    elif 'linux' in os_key or 'ubuntu' in os_key or 'debian' in os_key:
        corto_plazo.append("Ejecutar: apt update && apt upgrade -y para parchear el sistema")
    elif 'macos' in os_key:
        corto_plazo.append("Activar FileVault y Gatekeeper en Preferencias del Sistema")

    return [
        ("INMEDIATO",     inmediato),
        ("CORTO PLAZO",   corto_plazo),
        ("MEDIANO PLAZO", mediano_plazo),
    ]


class RedTeamReport:
    def __init__(self, ip, os_tipo, analista="Red Team AI Agent"):
        self.ip       = ip
        self.os_tipo  = os_tipo or "desconocido"
        self.analista = analista
        self.fecha    = date.today()
        self.reporte_id = hashlib.md5(f"{ip}{time.time()}".encode()).hexdigest()[:8].upper()
        self.estilos  = get_estilos()
        self.story    = []
        self.perfil   = None

    def separador(self, color=None):
        self.story.append(HRFlowable(width="100%", thickness=1, color=color or AZUL_MEDIO))
        self.story.append(Spacer(1, 0.1*inch))

    def _spacer(self):
        self.story.append(Spacer(1, 0.25*inch))

    def agregar_portada(self):
        e = self.estilos
        self.story.append(Spacer(1, 1.5*inch))
        self.story.append(_safe_paragraph("RED TEAM ASSESSMENT", e['portada_titulo']))
        self.story.append(_safe_paragraph("Reporte de Pruebas de Penetracion", e['portada_subtitulo']))
        self.story.append(Spacer(1, 0.3*inch))
        self.story.append(HRFlowable(width="80%", thickness=3, color=ROJO))
        self.story.append(Spacer(1, 0.3*inch))

        datos = [
            ["Objetivo:",   self.ip],
            ["Sistema:",    self.os_tipo.upper()],
            ["Fecha:",      str(self.fecha)],
            ["Analista:",   self.analista],
            ["ID Reporte:", self.reporte_id],
        ]
        tabla = Table(datos, colWidths=[2*inch, 3*inch])
        tabla.setStyle(TableStyle([
            ('TEXTCOLOR',    (0,0), (-1,-1), AZUL_OSCURO),
            ('FONTNAME',     (0,0), (0,-1),  'Helvetica-Bold'),
            ('FONTNAME',     (1,0), (1,-1),  'Helvetica'),
            ('FONTSIZE',     (0,0), (-1,-1), 11),
            ('ROWBACKGROUNDS',(0,0),(-1,-1), [GRIS, colors.white]),
            ('ALIGN',        (0,0), (-1,-1), 'LEFT'),
            ('PADDING',      (0,0), (-1,-1), 8),
        ]))
        self.story.append(tabla)
        self.story.append(Spacer(1, 0.5*inch))
        self.story.append(_safe_paragraph("CONFIDENCIAL -- USO INTERNO", e['confidencial']))
        self.story.append(_safe_paragraph("Este documento contiene informacion sensible de seguridad.", e['portada_info']))
        self.story.append(PageBreak())

    def agregar_indice(self):
        e = self.estilos
        self.story.append(_safe_paragraph("INDICE", e['seccion']))
        self.separador(ROJO)
        secciones = [
            ("1.",  "Resumen Ejecutivo"),
            ("2.",  "Alcance y Metodologia"),
            ("3.",  "Analisis de Vulnerabilidades"),
            ("4.",  "CVE y Referencias"),
            ("5.",  "Attack Chain"),
            ("6.",  "MITRE ATT&amp;CK"),
            ("7.",  "Evidencia de Explotacion"),
            ("7.5","Credenciales Descubiertas"),
            ("8.",  "Risk Score"),
            ("9.",  "Recomendaciones de Hardening"),
            ("10.", "Conclusion"),
        ]
        for num, titulo in secciones:
            self.story.append(_safe_paragraph(f"<b>{num}</b> {titulo}", e['cuerpo']))
        self.story.append(PageBreak())

    def agregar_executive_summary(self, scores, vulns, exito):
        e = self.estilos
        self.story.append(_safe_paragraph("1. RESUMEN EJECUTIVO", e['seccion']))
        self.separador(ROJO)

        nivel_riesgo = scores["total"][1]
        n_criticos   = sum(1 for v in vulns if v[5] == "CRITICO")
        acceso       = "ROOT / SYSTEM" if exito else "No obtenido"

        resumen = (f"Se realizo una evaluacion de seguridad tipo Red Team contra el sistema "
                   f"<b>{self.ip}</b> ({self.os_tipo.upper()}). Durante la evaluacion se identificaron "
                   f"vulnerabilidades con riesgo general <b>{nivel_riesgo}</b>.")
        self.story.append(_safe_paragraph(resumen, e['cuerpo']))
        self.story.append(Spacer(1, 0.15*inch))

        datos = [
            ["METRICA",                    "VALOR"],
            ["Riesgo General",             nivel_riesgo],
            ["Vulnerabilidades Criticas",  str(n_criticos)],
            ["Acceso Obtenido",            acceso],
            ["Puertos Abiertos",           str(len(self.perfil.ports)) if hasattr(self.perfil,'ports') else "?"],
            ["Explotacion sin Credenciales","SI" if exito else "NO"],
        ]
        tabla = Table(datos, colWidths=[3*inch, 3*inch])
        tabla.setStyle(TableStyle([
            ('BACKGROUND',  (0,0),  (-1,0),  AZUL_OSCURO),
            ('TEXTCOLOR',   (0,0),  (-1,0),  colors.white),
            ('FONTNAME',    (0,0),  (-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',    (0,0),  (-1,-1), 9),
            ('BACKGROUND',  (0,1),  (-1,1),  colors.HexColor('#FFCCCC')),
            ('TEXTCOLOR',   (0,1),  (-1,1),  ROJO),
            ('FONTNAME',    (0,1),  (-1,1),  'Helvetica-Bold'),
            ('ROWBACKGROUNDS',(0,2),(-1,-1), [GRIS, colors.white]),
            ('ALIGN',       (0,0),  (-1,-1), 'CENTER'),
            ('PADDING',     (0,0),  (-1,-1), 8),
            ('GRID',        (0,0),  (-1,-1), 0.5, AZUL_MEDIO),
        ]))
        self.story.append(tabla)
        self._spacer()

    def agregar_alcance_metodologia(self):
        e = self.estilos
        self.story.append(_safe_paragraph("2. ALCANCE Y METODOLOGIA", e['seccion']))
        self.separador(ROJO)

        self.story.append(_safe_paragraph("2.1 Alcance", e['subseccion']))
        alcance = [
            ["Objetivo",          self.ip],
            ["Tipo de Evaluacion","Black Box Penetration Test"],
            ["Entorno",           "Laboratorio Controlado"],
            ["Exclusiones",       "Ninguna"],
            ["Limitaciones",      "Entorno de prueba -- no produccion"],
        ]
        tabla = Table(alcance, colWidths=[2.5*inch, 3.5*inch])
        tabla.setStyle(TableStyle([
            ('FONTNAME',      (0,0),(0,-1), 'Helvetica-Bold'),
            ('FONTSIZE',      (0,0),(-1,-1),9),
            ('ROWBACKGROUNDS',(0,0),(-1,-1),[GRIS, colors.white]),
            ('GRID',          (0,0),(-1,-1),0.5, AZUL_MEDIO),
            ('PADDING',       (0,0),(-1,-1),6),
        ]))
        self.story.append(tabla)
        self.story.append(Spacer(1, 0.15*inch))

        self.story.append(_safe_paragraph("2.2 Metodologia", e['subseccion']))
        fases = [
            ("Fase 1 -- Reconocimiento",   "Escaneo de puertos y servicios con Nmap"),
            ("Fase 2 -- Enumeracion",      "Identificacion de versiones y OS fingerprinting"),
            ("Fase 2.5 -- Fuerza Bruta",   "Ataque de credenciales con Hydra"),
            ("Fase 3 -- Analisis",         "Identificacion de vulnerabilidades conocidas"),
            ("Fase 4 -- Explotacion",      "Ejecucion de exploits via Metasploit Framework"),
            ("Fase 5 -- Post-explotacion", "Recoleccion de evidencia y escalacion"),
            ("Fase 6 -- Reporte",          "Documentacion y recomendaciones"),
        ]
        for fase, desc in fases:
            self.story.append(_safe_paragraph(f"<b>{fase}:</b> {desc}", e['cuerpo']))

        self.story.append(Spacer(1, 0.15*inch))
        self.story.append(_safe_paragraph("2.3 Herramientas Utilizadas", e['subseccion']))
        herramientas = [
            ["Herramienta",           "Version", "Proposito"],
            ["Nmap",                  "7.94",    "Escaneo de puertos y servicios"],
            ["Metasploit Framework",  "6.4",     "Explotacion de vulnerabilidades"],
            ["Hydra",                 "9.6",     "Fuerza bruta de credenciales"],
            ["Python",                "3.12",    "Automatizacion del agente"],
            ["Gemma4 (Ollama)",       "Local",   "Analisis inteligente de resultados"],
            ["Paramiko",              "Latest",  "Conexion SSH automatizada"],
        ]
        tabla = Table(herramientas, colWidths=[2*inch, 1.5*inch, 2.5*inch])
        tabla.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,0), AZUL_OSCURO),
            ('TEXTCOLOR',  (0,0),(-1,0), colors.white),
            ('FONTNAME',   (0,0),(-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0,0),(-1,-1),9),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[GRIS, colors.white]),
            ('GRID',       (0,0),(-1,-1),0.5, AZUL_MEDIO),
            ('ALIGN',      (0,0),(-1,-1),'CENTER'),
            ('PADDING',    (0,0),(-1,-1),6),
        ]))
        self.story.append(tabla)
        self._spacer()

    def agregar_vulnerabilidades(self, contenido_ia, vulns):
        e = self.estilos
        self.story.append(_safe_paragraph("3. ANALISIS DE VULNERABILIDADES", e['seccion']))
        self.separador(ROJO)

        self.story.append(_safe_paragraph("3.1 Tabla de Vulnerabilidades Detectadas", e['subseccion']))

        vuln_data = [["Servicio", "Puerto", "Version", "CVE", "CVSS", "Severidad"]]
        for v in vulns:
            vuln_data.append(list(v))

        col_widths = [1.2*inch, 0.9*inch, 1.1*inch, 1.3*inch, 0.7*inch, 0.8*inch]
        tabla = Table(vuln_data, colWidths=col_widths)

        style = [
            ('BACKGROUND',  (0,0), (-1,0),  AZUL_OSCURO),
            ('TEXTCOLOR',   (0,0), (-1,0),  colors.white),
            ('FONTNAME',    (0,0), (-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',    (0,0), (-1,-1), 8),
            ('GRID',        (0,0), (-1,-1), 0.5, AZUL_MEDIO),
            ('ALIGN',       (0,0), (-1,-1), 'CENTER'),
            ('PADDING',     (0,0), (-1,-1), 5),
        ]
        for i, v in enumerate(vulns, start=1):
            if v[5] == "CRITICO":
                style.append(('BACKGROUND', (0,i), (-1,i), colors.HexColor('#FFCCCC')))
            elif v[5] == "ALTO":
                style.append(('BACKGROUND', (0,i), (-1,i), colors.HexColor('#FFE5CC')))
            elif v[5] == "MEDIO":
                style.append(('BACKGROUND', (0,i), (-1,i), colors.HexColor('#FFFACC')))

        tabla.setStyle(TableStyle(style))
        self.story.append(tabla)
        self.story.append(Spacer(1, 0.15*inch))

        self.story.append(_safe_paragraph("3.2 Analisis Detallado (IA)", e['subseccion']))
        for linea in str(contenido_ia).split('\n'):
            linea = linea.strip()
            if not linea:
                self.story.append(Spacer(1, 0.04*inch))
            elif linea.startswith('##') or linea.startswith('#'):
                texto = re.sub(r'^#+\s*', '', linea)
                self.story.append(_safe_paragraph(texto, e['subseccion']))
            else:
                linea = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', linea)
                linea = re.sub(r'\*(.*?)\*',     r'<i>\1</i>', linea)
                self.story.append(_safe_paragraph(linea, e['cuerpo']))

        self._spacer()

    def agregar_attack_chain(self, cadena):
        e = self.estilos
        self.story.append(_safe_paragraph("5. ATTACK CHAIN", e['seccion']))
        self.separador(ROJO)

        for titulo, desc, color in cadena:
            datos = [[titulo, desc]]
            tabla = Table(datos, colWidths=[2*inch, 4*inch])
            tabla.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(0,0), color),
                ('TEXTCOLOR',  (0,0),(0,0), colors.white),
                ('BACKGROUND', (1,0),(1,0), GRIS),
                ('TEXTCOLOR',  (1,0),(1,0), AZUL_OSCURO),
                ('FONTNAME',   (0,0),(-1,-1),'Helvetica-Bold'),
                ('FONTSIZE',   (0,0),(-1,-1),9),
                ('PADDING',    (0,0),(-1,-1),8),
                ('GRID',       (0,0),(-1,-1),0.5, AZUL_MEDIO),
            ]))
            self.story.append(tabla)
            self.story.append(Spacer(1, 0.04*inch))

        self._spacer()

    def agregar_mitre(self, tecnicas):
        e = self.estilos
        self.story.append(_safe_paragraph("6. MITRE ATT&amp;CK", e['seccion']))
        self.separador(ROJO)

        tabla = Table(tecnicas, colWidths=[2*inch, 0.8*inch, 2.5*inch, 1.2*inch])
        tabla.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0),  AZUL_OSCURO),
            ('TEXTCOLOR',     (0,0), (-1,0),  colors.white),
            ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
            ('FONTSIZE',      (0,0), (-1,-1), 8),
            ('ROWBACKGROUNDS',(0,1), (-1,-1), [GRIS, colors.white]),
            ('GRID',          (0,0), (-1,-1), 0.5, AZUL_MEDIO),
            ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
            ('PADDING',       (0,0), (-1,-1), 5),
        ]))
        self.story.append(tabla)
        self._spacer()

    def agregar_evidencia(self, evidencia):
        e = self.estilos
        self.story.append(_safe_paragraph("7. EVIDENCIA DE EXPLOTACION", e['seccion']))
        self.separador(ROJO)

        exito = ("session" in str(evidencia).lower() and "opened" in str(evidencia).lower()) or \
                "backdoor has been spawned" in str(evidencia).lower()

        vector = "N/A -- Explotacion no ejecutada o fallida"
        exploit = "N/A"
        cve     = "N/A"
        payload = "N/A"
        resultado_str = "Sin sesion activa"
        privilegios = "No obtenidos"

        if exito:
            resultado_str = "Sesion abierta"
            if "vsftpd" in str(evidencia).lower():
                vector   = "FTP -- Puerto 21/tcp"
                exploit  = "unix/ftp/vsftpd_234_backdoor"
                cve      = "CVE-2011-2523"
                payload  = "cmd/unix/interact"
            elif "ms17_010" in str(evidencia).lower() or "eternalblue" in str(evidencia).lower():
                vector   = "SMB -- Puerto 445/tcp"
                exploit  = "windows/smb/ms17_010_eternalblue"
                cve      = "CVE-2017-0144"
                payload  = "windows/x64/meterpreter/reverse_tcp"
            elif "usermap" in str(evidencia).lower():
                vector   = "Samba -- Puerto 445/tcp"
                exploit  = "multi/samba/usermap_script"
                cve      = "CVE-2007-2447"
                payload  = "cmd/unix/interact"
            if "root" in str(evidencia).lower():
                privilegios = "root"
            elif "system" in str(evidencia).lower():
                privilegios = "SYSTEM"
            else:
                privilegios = "usuario sin privilegios"
        elif not evidencia or evidencia.strip() == "":
            vector = "Explotacion deshabilitada en esta ejecucion"

        self.story.append(_safe_paragraph("7.1 Resumen de Explotacion", e['subseccion']))
        resumen = [
            ["Vector",      vector],
            ["Exploit",     exploit],
            ["CVE",         cve],
            ["Payload",     payload],
            ["Resultado",   resultado_str],
            ["Privilegios", privilegios],
        ]
        tabla = Table(resumen, colWidths=[2*inch, 4*inch])
        tabla.setStyle(TableStyle([
            ('FONTNAME',      (0,0),(0,-1), 'Helvetica-Bold'),
            ('FONTSIZE',      (0,0),(-1,-1),9),
            ('ROWBACKGROUNDS',(0,0),(-1,-1),[GRIS, colors.white]),
            ('GRID',          (0,0),(-1,-1),0.5, AZUL_MEDIO),
            ('PADDING',       (0,0),(-1,-1),6),
        ]))
        self.story.append(tabla)
        self.story.append(Spacer(1, 0.15*inch))

        self.story.append(_safe_paragraph("7.2 Log de Evidencia", e['subseccion']))

        if evidencia and evidencia.strip():
            keywords = ['backdoor','session','opened','meterpreter','root','passwd','exploit','success','error','failed']
            lineas_relevantes = [
                l.strip() for l in evidencia.split('\n')
                if l.strip() and any(k in l.lower() for k in keywords)
            ]
            if lineas_relevantes:
                for linea in lineas_relevantes[:20]:
                    self.story.append(_safe_paragraph(linea, e['codigo']))
            else:
                self.story.append(_safe_paragraph("No se encontraron lineas relevantes en el log.", e['cuerpo']))
        else:
            self.story.append(_safe_paragraph(
                "La fase de explotacion no fue ejecutada en esta evaluacion.", e['cuerpo']))

        self._spacer()

    def agregar_credenciales(self, credenciales):
        if not credenciales or "Sin servicios" in str(credenciales):
            return

        e = self.estilos
        self.story.append(_safe_paragraph("7.5 CREDENCIALES DESCUBIERTAS", e['seccion']))
        self.separador(ROJO)

        datos = [["Servicio", "Usuario", "Contrasena"]]

        for linea in str(credenciales).split('\n'):
            if "login:" in linea and "password:" in linea:
                try:
                    servicio = linea.split('[')[2].split(']')[0].upper()
                    usuario  = linea.split('login:')[1].split()[0].strip()
                    password = linea.split('password:')[1].strip()
                    datos.append([servicio, usuario, password])
                except:
                    pass

        if len(datos) > 1:
            tabla = Table(datos, colWidths=[2*inch, 2*inch, 2*inch])
            tabla.setStyle(TableStyle([
                ('BACKGROUND',    (0,0), (-1,0),  AZUL_OSCURO),
                ('TEXTCOLOR',     (0,0), (-1,0),  colors.white),
                ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
                ('FONTSIZE',      (0,0), (-1,-1), 9),
                ('ROWBACKGROUNDS',(0,1), (-1,-1), [colors.HexColor('#FFCCCC'), colors.white]),
                ('TEXTCOLOR',     (0,1), (-1,-1), ROJO),
                ('FONTNAME',      (0,1), (-1,-1), 'Helvetica-Bold'),
                ('GRID',          (0,0), (-1,-1), 0.5, AZUL_MEDIO),
                ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
                ('PADDING',       (0,0), (-1,-1), 8),
            ]))
            self.story.append(tabla)
        else:
            self.story.append(_safe_paragraph(
                "No se encontraron credenciales validas.", e['cuerpo']))

        self._spacer()

    def agregar_risk_score(self, scores):
        e = self.estilos
        self.story.append(_safe_paragraph("8. RISK SCORE", e['seccion']))
        self.separador(ROJO)

        datos = [
            ["Categoria",    "Score",  "Nivel"],
            ["Explotabilidad", f"{scores['explotabilidad'][0]}/10", scores['explotabilidad'][1]],
            ["Impacto",        f"{scores['impacto'][0]}/10",        scores['impacto'][1]],
            ["Persistencia",   f"{scores['persistencia'][0]}/10",   scores['persistencia'][1]],
            ["Exposicion",     f"{scores['exposicion'][0]}/10",     scores['exposicion'][1]],
            ["SCORE TOTAL",    f"{scores['total'][0]}/10",          scores['total'][1]],
        ]
        tabla = Table(datos, colWidths=[3*inch, 1.5*inch, 1.5*inch])
        tabla.setStyle(TableStyle([
            ('BACKGROUND',  (0,0),  (-1,0),  AZUL_OSCURO),
            ('TEXTCOLOR',   (0,0),  (-1,0),  colors.white),
            ('FONTNAME',    (0,0),  (-1,0),  'Helvetica-Bold'),
            ('BACKGROUND',  (0,-1), (-1,-1), ROJO),
            ('TEXTCOLOR',   (0,-1), (-1,-1), colors.white),
            ('FONTNAME',    (0,-1), (-1,-1), 'Helvetica-Bold'),
            ('FONTSIZE',    (0,0),  (-1,-1), 10),
            ('ROWBACKGROUNDS',(0,1),(-1,-2), [GRIS, colors.white]),
            ('GRID',        (0,0),  (-1,-1), 0.5, AZUL_MEDIO),
            ('ALIGN',       (0,0),  (-1,-1), 'CENTER'),
            ('PADDING',     (0,0),  (-1,-1), 8),
        ]))
        self.story.append(tabla)
        self._spacer()

    def agregar_hardening(self, recomendaciones):
        e = self.estilos
        self.story.append(_safe_paragraph("9. RECOMENDACIONES DE HARDENING", e['seccion']))
        self.separador(ROJO)

        for prioridad, items in recomendaciones:
            self.story.append(_safe_paragraph(prioridad, e['subseccion']))
            for item in items:
                self.story.append(_safe_paragraph(f"* {item}", e['cuerpo']))
            self.story.append(Spacer(1, 0.1*inch))

        self._spacer()

    def agregar_conclusion(self, scores, exito):
        e = self.estilos
        self.story.append(_safe_paragraph("10. CONCLUSION", e['seccion']))
        self.separador(ROJO)

        nivel = scores["total"][1]
        acceso_txt = ("se logro comprometer el sistema obteniendo acceso privilegiado."
                      if exito else
                      "no se obtuvo acceso directo al sistema en esta evaluacion, "
                      "aunque se identificaron vectores de riesgo.")

        conclusion = (f"El sistema evaluado ({self.ip} -- {self.os_tipo.upper()}) presenta un estado "
                      f"de seguridad <b>{nivel}</b>. Durante la evaluacion {acceso_txt} "
                      f"Se recomienda atender las recomendaciones de hardening listadas en la seccion 9 "
                      f"antes de exponer este sistema a redes productivas.")
        self.story.append(_safe_paragraph(conclusion, e['cuerpo']))
        self.story.append(Spacer(1, 0.3*inch))
        self.separador(ROJO)
        self.story.append(_safe_paragraph(
            f"Reporte ID: {self.reporte_id} | Generado por Red Team AI Agent | {self.fecha} | CONFIDENCIAL",
            e['footer']
        ))

    def generar(self, contenido_ia, evidencia, perfil=None, credenciales=""):
        self.perfil = perfil

        vulns          = _extraer_vulnerabilidades(perfil) if perfil else [("N/A","-","-","N/A","0","BAJO")]
        scores         = _calcular_risk_score(perfil, evidencia) if perfil else _calcular_risk_score_vacio()
        cadena         = _generar_attack_chain(perfil, evidencia) if perfil else []
        tecnicas_mitre = _generar_mitre(perfil, evidencia) if perfil else [["Tecnica","ID","Descripcion","Fase"]]
        recomendaciones= _generar_hardening(perfil) if perfil else []
        exito          = ("session" in str(evidencia).lower() and "opened" in str(evidencia).lower()) or \
                         "backdoor has been spawned" in str(evidencia).lower()

        nombre = f"reporte_profesional_{self.ip.replace('.','_')}_{self.fecha}.pdf"
        doc = SimpleDocTemplate(nombre, pagesize=letter,
                                rightMargin=0.75*inch, leftMargin=0.75*inch,
                                topMargin=0.75*inch,   bottomMargin=0.75*inch)

        self.agregar_portada()
        self.agregar_indice()
        self.agregar_executive_summary(scores, vulns, exito)
        self.agregar_alcance_metodologia()
        self.agregar_vulnerabilidades(contenido_ia, vulns)
        self.agregar_attack_chain(cadena)
        self.agregar_mitre(tecnicas_mitre)
        self.agregar_evidencia(evidencia)
        self.agregar_credenciales(credenciales)
        self.agregar_risk_score(scores)
        self.agregar_hardening(recomendaciones)
        self.agregar_conclusion(scores, exito)

        doc.build(self.story)
        print(f"\n Reporte profesional generado: {nombre}")
        return nombre


def _calcular_risk_score_vacio():
    return {
        "explotabilidad": (0, "BAJO"),
        "impacto":        (0, "BAJO"),
        "persistencia":   (0, "BAJO"),
        "exposicion":     (0, "BAJO"),
        "total":          (0, "BAJO"),
    }