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

# ============ COLORES ============
ROJO = colors.HexColor('#E63946')
AZUL_OSCURO = colors.HexColor('#1D3557')
AZUL_MEDIO = colors.HexColor('#457B9D')
GRIS = colors.HexColor('#F1FAEE')
NEGRO = colors.HexColor('#000000')
VERDE = colors.HexColor('#2D6A4F')
NARANJA = colors.HexColor('#F4A261')
AMARILLO = colors.HexColor('#E9C46A')

# ============ ESTILOS ============
def get_estilos():
    styles = getSampleStyleSheet()
    
    estilos = {
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
        
        'critico': ParagraphStyle('critico',
            fontSize=10, textColor=colors.white, fontName='Helvetica-Bold',
            alignment=TA_CENTER, backColor=ROJO),
        
        'footer': ParagraphStyle('footer',
            fontSize=7, textColor=AZUL_MEDIO, fontName='Helvetica',
            alignment=TA_CENTER),
    }
    return estilos

# ============ GENERADOR DE REPORTE ============
class RedTeamReport:
    def __init__(self, ip, os_tipo, analista="Red Team AI Agent"):
        self.ip = ip
        self.os_tipo = os_tipo
        self.analista = analista
        self.fecha = date.today()
        self.reporte_id = hashlib.md5(f"{ip}{time.time()}".encode()).hexdigest()[:8].upper()
        self.estilos = get_estilos()
        self.story = []
        
    def separador(self, color=None):
        self.story.append(HRFlowable(
            width="100%", thickness=1,
            color=color or AZUL_MEDIO
        ))
        self.story.append(Spacer(1, 0.1*inch))

    def agregar_portada(self):
        e = self.estilos
        self.story.append(Spacer(1, 1.5*inch))
        self.story.append(Paragraph("🛡 RED TEAM ASSESSMENT", e['portada_titulo']))
        self.story.append(Paragraph("Reporte de Pruebas de Penetración", e['portada_subtitulo']))
        self.story.append(Spacer(1, 0.3*inch))
        self.story.append(HRFlowable(width="80%", thickness=3, color=ROJO))
        self.story.append(Spacer(1, 0.3*inch))
        
        datos = [
            ["🎯 Objetivo:", self.ip],
            ["💻 Sistema:", self.os_tipo.upper()],
            ["📅 Fecha:", str(self.fecha)],
            ["👤 Analista:", self.analista],
            ["🔑 ID Reporte:", self.reporte_id],
        ]
        
        tabla = Table(datos, colWidths=[2*inch, 3*inch])
        tabla.setStyle(TableStyle([
            ('TEXTCOLOR', (0,0), (-1,-1), AZUL_OSCURO),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTNAME', (1,0), (1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 11),
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [GRIS, colors.white]),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        self.story.append(tabla)
        self.story.append(Spacer(1, 0.5*inch))
        self.story.append(Paragraph("⚠ CONFIDENCIAL — USO INTERNO", e['confidencial']))
        self.story.append(Paragraph("Este documento contiene información sensible de seguridad.", e['portada_info']))
        self.story.append(PageBreak())

    def agregar_indice(self):
        e = self.estilos
        self.story.append(Paragraph("ÍNDICE", e['seccion']))
        self.separador(ROJO)
        
        secciones = [
            ("1.", "Resumen Ejecutivo"),
            ("2.", "Alcance y Metodología"),
            ("3.", "Análisis de Vulnerabilidades"),
            ("4.", "CVE y Referencias"),
            ("5.", "Attack Chain"),
            ("6.", "MITRE ATT&CK"),
            ("7.", "Evidencia de Explotación"),
            ("8.", "Risk Score"),
            ("9.", "Recomendaciones de Hardening"),
            ("10.", "Conclusión"),
        ]
        
        for num, titulo in secciones:
            self.story.append(Paragraph(f"<b>{num}</b> {titulo}", e['cuerpo']))
        
        self.story.append(PageBreak())

    def agregar_executive_summary(self, hallazgos_criticos=4, riesgo="CRÍTICO"):
        e = self.estilos
        self.story.append(Paragraph("1. RESUMEN EJECUTIVO", e['seccion']))
        self.separador(ROJO)
        
        resumen = f"""
        Se realizó una evaluación de seguridad tipo Red Team contra el sistema <b>{self.ip}</b> 
        ({self.os_tipo.upper()}). Durante la evaluación se identificaron múltiples vulnerabilidades 
        críticas que permiten el compromiso total del sistema sin necesidad de credenciales previas.
        """
        self.story.append(Paragraph(resumen.strip(), e['cuerpo']))
        self.story.append(Spacer(1, 0.15*inch))
        
        # Tabla de resumen
        datos = [
            ["MÉTRICA", "VALOR"],
            ["Riesgo General", riesgo],
            ["Vulnerabilidades Críticas", str(hallazgos_criticos)],
            ["Acceso Obtenido", "ROOT / SYSTEM"],
            ["Servicios Comprometidos", "FTP, SSH, HTTP, MySQL"],
            ["Explotación sin Credenciales", "SÍ"],
        ]
        
        tabla = Table(datos, colWidths=[3*inch, 3*inch])
        tabla.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), AZUL_OSCURO),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#FFCCCC')),
            ('TEXTCOLOR', (0,1), (-1,1), ROJO),
            ('FONTNAME', (0,1), (-1,1), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0,2), (-1,-1), [GRIS, colors.white]),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('PADDING', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, AZUL_MEDIO),
        ]))
        self.story.append(tabla)
        self.story.append(PageBreak())

    def agregar_alcance_metodologia(self):
        e = self.estilos
        self.story.append(Paragraph("2. ALCANCE Y METODOLOGÍA", e['seccion']))
        self.separador(ROJO)
        
        self.story.append(Paragraph("2.1 Alcance", e['subseccion']))
        alcance = [
            ["Objetivo", self.ip],
            ["Tipo de Evaluación", "Black Box Penetration Test"],
            ["Entorno", "Laboratorio Controlado"],
            ["Exclusiones", "Ninguna"],
            ["Limitaciones", "Entorno de prueba — no producción"],
        ]
        tabla = Table(alcance, colWidths=[2.5*inch, 3.5*inch])
        tabla.setStyle(TableStyle([
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [GRIS, colors.white]),
            ('GRID', (0,0), (-1,-1), 0.5, AZUL_MEDIO),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        self.story.append(tabla)
        self.story.append(Spacer(1, 0.2*inch))
        
        self.story.append(Paragraph("2.2 Metodología", e['subseccion']))
        fases = [
            ("Fase 1 — Reconocimiento", "Escaneo de puertos y servicios con Nmap"),
            ("Fase 2 — Enumeración", "Identificación de versiones y OS fingerprinting"),
            ("Fase 3 — Análisis", "Identificación de vulnerabilidades conocidas"),
            ("Fase 4 — Explotación", "Ejecución de exploits via Metasploit Framework"),
            ("Fase 5 — Post-explotación", "Recolección de evidencia y escalación"),
            ("Fase 6 — Reporte", "Documentación y recomendaciones"),
        ]
        for fase, desc in fases:
            self.story.append(Paragraph(f"<b>{fase}:</b> {desc}", e['cuerpo']))
        
        self.story.append(Spacer(1, 0.15*inch))
        self.story.append(Paragraph("2.3 Herramientas Utilizadas", e['subseccion']))
        herramientas = [
            ["Herramienta", "Versión", "Propósito"],
            ["Nmap", "7.80", "Escaneo de puertos y servicios"],
            ["Metasploit Framework", "6.4", "Explotación de vulnerabilidades"],
            ["Python", "3.12", "Automatización del agente"],
            ["Gemma4 (Ollama)", "Local", "Análisis inteligente de resultados"],
            ["Paramiko", "Latest", "Conexión SSH automatizada"],
        ]
        tabla = Table(herramientas, colWidths=[2*inch, 1.5*inch, 2.5*inch])
        tabla.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), AZUL_OSCURO),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [GRIS, colors.white]),
            ('GRID', (0,0), (-1,-1), 0.5, AZUL_MEDIO),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        self.story.append(tabla)
        self.story.append(PageBreak())

    def agregar_vulnerabilidades(self, contenido_ia):
        e = self.estilos
        self.story.append(Paragraph("3. ANÁLISIS DE VULNERABILIDADES", e['seccion']))
        self.separador(ROJO)
        
        # Tabla CVE principal
        self.story.append(Paragraph("3.1 Tabla de Vulnerabilidades Críticas", e['subseccion']))
        
        vuln_data = [
            ["Servicio", "Puerto", "Versión", "CVE", "CVSS", "Severidad"],
            ["vsftpd", "21/tcp", "2.3.4", "CVE-2011-2523", "10.0", "CRÍTICO"],
            ["Apache", "80/tcp", "2.2.8", "CVE-2017-7679", "9.8", "CRÍTICO"],
            ["Telnet", "23/tcp", "Linux telnetd", "N/A", "9.1", "CRÍTICO"],
            ["MySQL", "3306/tcp", "5.0.51a", "CVE-2012-2122", "7.5", "ALTO"],
            ["OpenSSH", "22/tcp", "4.7p1", "CVE-2016-6515", "7.5", "ALTO"],
            ["Samba", "445/tcp", "3.X-4.X", "CVE-2017-7494", "9.8", "CRÍTICO"],
        ]
        
        tabla = Table(vuln_data, colWidths=[1.2*inch, 0.8*inch, 1.2*inch, 1.3*inch, 0.7*inch, 0.8*inch])
        tabla.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), AZUL_OSCURO),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#FFCCCC')),
            ('BACKGROUND', (0,2), (-1,2), colors.HexColor('#FFCCCC')),
            ('BACKGROUND', (0,3), (-1,3), colors.HexColor('#FFCCCC')),
            ('BACKGROUND', (0,4), (-1,4), colors.HexColor('#FFE5CC')),
            ('BACKGROUND', (0,5), (-1,5), colors.HexColor('#FFE5CC')),
            ('BACKGROUND', (0,6), (-1,6), colors.HexColor('#FFCCCC')),
            ('GRID', (0,0), (-1,-1), 0.5, AZUL_MEDIO),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        self.story.append(tabla)
        self.story.append(Spacer(1, 0.2*inch))
        
        # Análisis de la IA
        self.story.append(Paragraph("3.2 Análisis Detallado", e['subseccion']))
        for linea in str(contenido_ia).split('\n'):
            linea = linea.strip()
            if not linea:
                self.story.append(Spacer(1, 0.05*inch))
            elif linea.startswith('##') or linea.startswith('#'):
                texto = re.sub(r'^#+\s*', '', linea)
                self.story.append(Paragraph(texto, e['subseccion']))
            else:
                linea = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', linea)
                linea = re.sub(r'\*(.*?)\*', r'<i>\1</i>', linea)
                try:
                    self.story.append(Paragraph(linea, e['cuerpo']))
                except:
                    self.story.append(Paragraph(linea.encode('ascii', 'ignore').decode(), e['cuerpo']))
        
        self.story.append(PageBreak())

    def agregar_attack_chain(self):
        e = self.estilos
        self.story.append(Paragraph("5. ATTACK CHAIN", e['seccion']))
        self.separador(ROJO)
        
        cadena = [
            ("🔍 Reconocimiento", "Nmap scan — 22 puertos abiertos detectados", AZUL_MEDIO),
            ("📋 Enumeración", "vsftpd 2.3.4 identificado en puerto 21/tcp", AZUL_OSCURO),
            ("🎯 Vulnerabilidad", "CVE-2011-2523 — Backdoor conocido en vsftpd 2.3.4", NARANJA),
            ("💥 Explotación", "Metasploit exploit/unix/ftp/vsftpd_234_backdoor", ROJO),
            ("🐚 Shell Remota", "Meterpreter session abierta en puerto 4444", ROJO),
            ("👑 Acceso Root", "getuid → root — Compromiso total del sistema", colors.HexColor('#8B0000')),
        ]
        
        for titulo, desc, color in cadena:
            datos = [[titulo, desc]]
            tabla = Table(datos, colWidths=[2*inch, 4*inch])
            tabla.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,0), color),
                ('TEXTCOLOR', (0,0), (0,0), colors.white),
                ('BACKGROUND', (1,0), (1,0), GRIS),
                ('TEXTCOLOR', (1,0), (1,0), AZUL_OSCURO),
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('PADDING', (0,0), (-1,-1), 8),
                ('GRID', (0,0), (-1,-1), 0.5, AZUL_MEDIO),
            ]))
            self.story.append(tabla)
            self.story.append(Spacer(1, 0.05*inch))
        
        self.story.append(PageBreak())

    def agregar_mitre(self):
        e = self.estilos
        self.story.append(Paragraph("6. MITRE ATT&CK", e['seccion']))
        self.separador(ROJO)
        
        tecnicas = [
            ["Técnica", "ID", "Descripción", "Fase"],
            ["Exploit Public-Facing App", "T1190", "Explotación de vsftpd 2.3.4 backdoor", "Initial Access"],
            ["Command & Scripting", "T1059", "Ejecución de comandos via shell remota", "Execution"],
            ["Remote Services", "T1021", "Acceso via SSH y FTP", "Lateral Movement"],
            ["Valid Accounts", "T1078", "Uso de credenciales por defecto", "Defense Evasion"],
            ["Data from Local System", "T1005", "Extracción de /etc/passwd", "Collection"],
            ["Network Service Scan", "T1046", "Escaneo con Nmap", "Discovery"],
        ]
        
        tabla = Table(tecnicas, colWidths=[2*inch, 0.8*inch, 2.5*inch, 1.2*inch])
        tabla.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), AZUL_OSCURO),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [GRIS, colors.white]),
            ('GRID', (0,0), (-1,-1), 0.5, AZUL_MEDIO),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        self.story.append(tabla)
        self.story.append(PageBreak())

    def agregar_evidencia(self, evidencia):
        e = self.estilos
        self.story.append(Paragraph("7. EVIDENCIA DE EXPLOTACIÓN", e['seccion']))
        self.separador(ROJO)
        
        self.story.append(Paragraph("7.1 Resumen de Explotación", e['subseccion']))
        resumen = [
            ["Vector", "FTP — Puerto 21/tcp"],
            ["Exploit", "unix/ftp/vsftpd_234_backdoor"],
            ["CVE", "CVE-2011-2523"],
            ["Payload", "cmd/linux/http/x86/meterpreter_reverse_tcp"],
            ["Resultado", "Sesión Meterpreter abierta"],
            ["Privilegios", "root"],
        ]
        tabla = Table(resumen, colWidths=[2*inch, 4*inch])
        tabla.setStyle(TableStyle([
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [GRIS, colors.white]),
            ('GRID', (0,0), (-1,-1), 0.5, AZUL_MEDIO),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        self.story.append(tabla)
        self.story.append(Spacer(1, 0.2*inch))
        
        self.story.append(Paragraph("7.2 Log de Evidencia", e['subseccion']))
        lineas_relevantes = []
        for linea in evidencia.split('\n'):
            linea = linea.strip()
            if any(x in linea.lower() for x in ['backdoor', 'session', 'opened', 'meterpreter', 'root', 'passwd', 'exploit']):
                if linea:
                    lineas_relevantes.append(linea)
        
        for linea in lineas_relevantes[:15]:
            try:
                self.story.append(Paragraph(linea, e['codigo']))
            except:
                self.story.append(Paragraph(linea.encode('ascii', 'ignore').decode(), e['codigo']))
        
        self.story.append(PageBreak())

    def agregar_risk_score(self):
        e = self.estilos
        self.story.append(Paragraph("8. RISK SCORE", e['seccion']))
        self.separador(ROJO)
        
        scores = [
            ["Categoría", "Score", "Nivel"],
            ["Explotabilidad", "10/10", "CRÍTICO"],
            ["Impacto", "10/10", "CRÍTICO"],
            ["Persistencia", "8/10", "ALTO"],
            ["Exposición", "9/10", "CRÍTICO"],
            ["SCORE TOTAL", "9.75/10", "CRÍTICO"],
        ]
        
        tabla = Table(scores, colWidths=[3*inch, 1.5*inch, 1.5*inch])
        tabla.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), AZUL_OSCURO),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BACKGROUND', (0,-1), (-1,-1), ROJO),
            ('TEXTCOLOR', (0,-1), (-1,-1), colors.white),
            ('FONTNAME', (0,-1), (-1,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('ROWBACKGROUNDS', (0,1), (-1,-2), [GRIS, colors.white]),
            ('GRID', (0,0), (-1,-1), 0.5, AZUL_MEDIO),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        self.story.append(tabla)
        self.story.append(PageBreak())

    def agregar_hardening(self):
        e = self.estilos
        self.story.append(Paragraph("9. RECOMENDACIONES DE HARDENING", e['seccion']))
        self.separador(ROJO)
        
        recomendaciones = [
            ("🔴 INMEDIATO", [
                "Deshabilitar Telnet (puerto 23) — reemplazar con SSH",
                "Actualizar vsftpd a versión 3.0.5+ o migrar a SFTP",
                "Actualizar Apache httpd a versión 2.4.57+",
                "Actualizar MySQL a versión 8.0+",
                "Cerrar puerto 1524 (bindshell) inmediatamente",
            ]),
            ("🟠 CORTO PLAZO", [
                "Implementar autenticación SSH por llaves (deshabilitar contraseñas)",
                "Configurar Fail2ban para prevenir fuerza bruta",
                "Actualizar OpenSSH a versión más reciente",
                "Implementar firewall con reglas restrictivas (UFW/iptables)",
                "Deshabilitar servicios RSH (512, 513, 514)",
            ]),
            ("🟡 MEDIANO PLAZO", [
                "Implementar segmentación de red (VLANs)",
                "Configurar IDS/IPS (Snort/Suricata)",
                "Aplicar principio de mínimo privilegio",
                "Implementar monitoreo de logs centralizado (SIEM)",
                "Realizar auditorías de seguridad trimestrales",
            ]),
        ]
        
        for prioridad, items in recomendaciones:
            self.story.append(Paragraph(prioridad, e['subseccion']))
            for item in items:
                self.story.append(Paragraph(f"• {item}", e['cuerpo']))
            self.story.append(Spacer(1, 0.1*inch))
        
        self.story.append(PageBreak())

    def agregar_conclusion(self):
        e = self.estilos
        self.story.append(Paragraph("10. CONCLUSIÓN", e['seccion']))
        self.separador(ROJO)
        
        conclusion = f"""
        El sistema evaluado ({self.ip}) presenta un estado de seguridad <b>CRÍTICO</b>. 
        Durante la evaluación se logró comprometer completamente el sistema obteniendo 
        acceso root sin necesidad de credenciales previas, explotando una vulnerabilidad 
        conocida (CVE-2011-2523) en el servicio FTP vsftpd 2.3.4.
        
        La presencia de múltiples servicios obsoletos, protocolos inseguros y la falta 
        de controles básicos de seguridad representa un riesgo crítico para la 
        confidencialidad, integridad y disponibilidad de la información.
        
        Se recomienda <b>acción inmediata</b> para remediar las vulnerabilidades identificadas 
        antes de conectar este sistema a redes productivas o exponer servicios al internet.
        """
        self.story.append(Paragraph(conclusion.strip(), e['cuerpo']))
        self.story.append(Spacer(1, 0.3*inch))
        self.separador(ROJO)
        self.story.append(Paragraph(
            f"Reporte ID: {self.reporte_id} | Generado por Red Team AI Agent | {self.fecha} | CONFIDENCIAL",
            e['footer']
        ))

    def generar(self, contenido_ia, evidencia):
        nombre = f"reporte_profesional_{self.ip}_{self.fecha}.pdf"
        doc = SimpleDocTemplate(nombre, pagesize=letter,
                                rightMargin=0.75*inch, leftMargin=0.75*inch,
                                topMargin=0.75*inch, bottomMargin=0.75*inch)
        
        self.agregar_portada()
        self.agregar_indice()
        self.agregar_executive_summary()
        self.agregar_alcance_metodologia()
        self.agregar_vulnerabilidades(contenido_ia)
        self.agregar_attack_chain()
        self.agregar_mitre()
        self.agregar_evidencia(evidencia)
        self.agregar_risk_score()
        self.agregar_hardening()
        self.agregar_conclusion()
        
        doc.build(self.story)
        print(f"\n✅ Reporte profesional generado: {nombre}")
        return nombre