"""
reporte_ejecutivo.py — D4yShell
Reporte para CEO/Dirección: sin tecnicismos, lenguaje de negocio.
Coloca este archivo en: reporting/reporte_ejecutivo.py
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 HRFlowable, Table, TableStyle, PageBreak)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import date
from pathlib import Path
import hashlib
import time
import re

# ── Colores corporativos ─────────────────────────────────────────────────────
ROJO        = colors.HexColor('#E63946')
ROJO_CLARO  = colors.HexColor('#FFCCCC')
AZUL_OSCURO = colors.HexColor('#1D3557')
AZUL_MEDIO  = colors.HexColor('#457B9D')
GRIS        = colors.HexColor('#F8F9FA')
GRIS_MEDIO  = colors.HexColor('#E9ECEF')
VERDE       = colors.HexColor('#2D6A4F')
VERDE_CLARO = colors.HexColor('#D4EDDA')
AMARILLO    = colors.HexColor('#FFF3CD')
NARANJA     = colors.HexColor('#F4A261')
NARANJA_CLARO = colors.HexColor('#FFE5CC')
BLANCO      = colors.white
NEGRO       = colors.HexColor('#212529')

# ── Mapeo de nivel a color ────────────────────────────────────────────────────
COLOR_NIVEL = {
    "CRITICO": ROJO,
    "ALTO":    NARANJA,
    "MEDIO":   colors.HexColor('#E9C46A'),
    "BAJO":    VERDE,
}
COLOR_NIVEL_CLARO = {
    "CRITICO": ROJO_CLARO,
    "ALTO":    NARANJA_CLARO,
    "MEDIO":   AMARILLO,
    "BAJO":    VERDE_CLARO,
}

# ── Traducciones a lenguaje de negocio ────────────────────────────────────────
IMPACTO_NEGOCIO = {
    "CRITICO": "Su empresa puede ser comprometida hoy mismo sin necesidad de contraseñas.",
    "ALTO":    "Existen vulnerabilidades graves que un atacante motivado podría explotar.",
    "MEDIO":   "Hay riesgos moderados que requieren atención antes de que escalen.",
    "BAJO":    "La postura de seguridad es aceptable, con áreas de mejora identificadas.",
}

URGENCIA_NIVEL = {
    "CRITICO": "ESTA SEMANA",
    "ALTO":    "ESTE MES",
    "MEDIO":   "ESTE TRIMESTRE",
    "BAJO":    "ESTE AÑO",
}

COSTO_ESTIMADO = {
    "CRITICO": "Alto — requiere intervención inmediata de especialistas",
    "ALTO":    "Medio-Alto — actualizaciones y configuración de sistemas",
    "MEDIO":   "Medio — ajustes de configuración y políticas",
    "BAJO":    "Bajo — revisiones y buenas prácticas",
}

def _safe_p(texto, estilo):
    texto = str(texto).strip()
    texto = re.sub(r'&(?!amp;|lt;|gt;|apos;|quot;)', '&amp;', texto)
    try:
        return Paragraph(texto, estilo)
    except Exception:
        return Paragraph(texto.encode('ascii', 'ignore').decode(), estilo)

def _estilos():
    return {
        'titulo': ParagraphStyle('eje_titulo',
            fontSize=26, textColor=AZUL_OSCURO, fontName='Helvetica-Bold',
            alignment=TA_CENTER, spaceAfter=8),
        'subtitulo': ParagraphStyle('eje_subtitulo',
            fontSize=13, textColor=AZUL_MEDIO, fontName='Helvetica',
            alignment=TA_CENTER, spaceAfter=4),
        'info': ParagraphStyle('eje_info',
            fontSize=10, textColor=AZUL_OSCURO, fontName='Helvetica',
            alignment=TA_CENTER, spaceAfter=3),
        'confidencial': ParagraphStyle('eje_conf',
            fontSize=11, textColor=ROJO, fontName='Helvetica-Bold',
            alignment=TA_CENTER, spaceAfter=4),
        'seccion': ParagraphStyle('eje_sec',
            fontSize=13, textColor=AZUL_OSCURO, fontName='Helvetica-Bold',
            spaceBefore=14, spaceAfter=6),
        'subseccion': ParagraphStyle('eje_subsec',
            fontSize=10, textColor=AZUL_MEDIO, fontName='Helvetica-Bold',
            spaceBefore=8, spaceAfter=4),
        'cuerpo': ParagraphStyle('eje_cuerpo',
            fontSize=10, textColor=NEGRO, fontName='Helvetica',
            spaceAfter=4, leading=16),
        'cuerpo_small': ParagraphStyle('eje_cuerpo_sm',
            fontSize=9, textColor=NEGRO, fontName='Helvetica',
            spaceAfter=3, leading=14),
        'semaforo_label': ParagraphStyle('eje_sem_lbl',
            fontSize=9, textColor=NEGRO, fontName='Helvetica-Bold',
            alignment=TA_CENTER),
        'semaforo_valor': ParagraphStyle('eje_sem_val',
            fontSize=20, textColor=BLANCO, fontName='Helvetica-Bold',
            alignment=TA_CENTER),
        'alerta': ParagraphStyle('eje_alerta',
            fontSize=10, textColor=ROJO, fontName='Helvetica-Bold',
            spaceAfter=4),
        'footer': ParagraphStyle('eje_footer',
            fontSize=7, textColor=AZUL_MEDIO, fontName='Helvetica',
            alignment=TA_CENTER),
        'numero_grande': ParagraphStyle('eje_num',
            fontSize=32, textColor=ROJO, fontName='Helvetica-Bold',
            alignment=TA_CENTER, spaceAfter=2),
        'etiqueta_numero': ParagraphStyle('eje_etq_num',
            fontSize=9, textColor=AZUL_OSCURO, fontName='Helvetica',
            alignment=TA_CENTER),
    }


class ReporteEjecutivo:
    """
    Reporte PDF para dirección/CEO — sin tecnicismos.
    Uso:
        from reporting.reporte_ejecutivo import ReporteEjecutivo
        rep = ReporteEjecutivo(ip, os_tipo, nombre_empresa="Empresa SA de CV")
        rep.generar(scores, vulns, exito, credenciales, perfil)
    """

    def __init__(self, ip, os_tipo, nombre_empresa="", analista="D4YSHELL", consultor=""):
        self.ip             = ip
        self.os_tipo        = os_tipo or "Sistema evaluado"
        self.nombre_empresa = nombre_empresa or "Empresa cliente"
        self.analista       = analista
        self.consultor      = consultor or analista
        self.fecha          = date.today()
        self.reporte_id     = hashlib.md5(f"exec{ip}{time.time()}".encode()).hexdigest()[:8].upper()
        self.e              = _estilos()
        self.story          = []

    def _sep(self, color=None, grosor=1):
        self.story.append(HRFlowable(width="100%", thickness=grosor, color=color or AZUL_MEDIO))
        self.story.append(Spacer(1, 0.1*inch))

    def _sp(self, h=0.2):
        self.story.append(Spacer(1, h*inch))

    # ── PORTADA ───────────────────────────────────────────────────────────────
    def _portada(self):
        e = self.e
        self.story.append(Spacer(1, 1.2*inch))

        # Franja de color
        tabla_franja = Table([["EVALUACIÓN DE CIBERSEGURIDAD"]], colWidths=[6.5*inch])
        tabla_franja.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), AZUL_OSCURO),
            ('TEXTCOLOR',  (0,0), (-1,-1), BLANCO),
            ('FONTNAME',   (0,0), (-1,-1), 'Helvetica-Bold'),
            ('FONTSIZE',   (0,0), (-1,-1), 18),
            ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
            ('PADDING',    (0,0), (-1,-1), 16),
        ]))
        self.story.append(tabla_franja)
        self.story.append(Spacer(1, 0.15*inch))

        tabla_sub = Table([["Informe Ejecutivo de Resultados"]], colWidths=[6.5*inch])
        tabla_sub.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), AZUL_MEDIO),
            ('TEXTCOLOR',  (0,0), (-1,-1), BLANCO),
            ('FONTNAME',   (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE',   (0,0), (-1,-1), 12),
            ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
            ('PADDING',    (0,0), (-1,-1), 8),
        ]))
        self.story.append(tabla_sub)
        self.story.append(Spacer(1, 0.5*inch))

        datos = [
            ["Preparado para:", self.nombre_empresa],
            ["Sistema evaluado:", self.ip],
            ["Fecha del informe:", str(self.fecha)],
            ["Preparado por:", self.consultor],
            ["ID del informe:", self.reporte_id],
        ]
        tabla = Table(datos, colWidths=[2.2*inch, 4*inch])
        tabla.setStyle(TableStyle([
            ('FONTNAME',      (0,0),(0,-1), 'Helvetica-Bold'),
            ('FONTNAME',      (1,0),(1,-1), 'Helvetica'),
            ('FONTSIZE',      (0,0),(-1,-1),10),
            ('TEXTCOLOR',     (0,0),(-1,-1), AZUL_OSCURO),
            ('ROWBACKGROUNDS',(0,0),(-1,-1),[GRIS, BLANCO]),
            ('PADDING',       (0,0),(-1,-1),8),
            ('GRID',          (0,0),(-1,-1),0.5, GRIS_MEDIO),
        ]))
        self.story.append(tabla)
        self.story.append(Spacer(1, 0.5*inch))

        self.story.append(_safe_p("CONFIDENCIAL — SOLO PARA DIRECCIÓN", e['confidencial']))
        self.story.append(_safe_p(
            "Este informe ha sido preparado exclusivamente para uso de la dirección. "
            "No debe ser distribuido sin autorización.", e['info']))
        self.story.append(PageBreak())

    # ── RESUMEN PARA DIRECCIÓN ────────────────────────────────────────────────
    def _resumen_direccion(self, nivel, exito, n_criticos, n_puertos):
        e = self.e
        self.story.append(_safe_p("¿QUÉ ENCONTRAMOS EN SU EMPRESA?", e['seccion']))
        self._sep(AZUL_OSCURO, 2)

        impacto_txt = IMPACTO_NEGOCIO.get(nivel, "Se identificaron riesgos de seguridad.")
        acceso_txt = (
            "Durante la evaluación, nuestro equipo <b>logró acceder al sistema con privilegios de administrador</b> "
            "sin necesitar contraseñas ni credenciales previas. Esto significa que un atacante real podría "
            "hacer lo mismo."
            if exito else
            "Durante la evaluación se identificaron vulnerabilidades significativas. "
            "Aunque no se obtuvo acceso completo, los riesgos detectados deben atenderse."
        )

        self.story.append(_safe_p(impacto_txt, e['cuerpo']))
        self.story.append(_safe_p(acceso_txt, e['cuerpo']))
        self._sp(0.15)

        # Semáforo visual
        color_nivel = COLOR_NIVEL.get(nivel, AZUL_MEDIO)
        tabla_semaforo = Table(
            [[_safe_p(nivel, ParagraphStyle('sv', fontSize=22, textColor=BLANCO,
                fontName='Helvetica-Bold', alignment=TA_CENTER))]],
            colWidths=[6.5*inch]
        )
        tabla_semaforo.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), color_nivel),
            ('PADDING',    (0,0), (-1,-1), 14),
            ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ]))
        self.story.append(_safe_p("Nivel de Riesgo Global:", e['subseccion']))
        self.story.append(tabla_semaforo)
        self._sp(0.2)

        # KPIs en tarjetas
        kpis = [
            [_safe_p(str(n_puertos), ParagraphStyle('kn', fontSize=28, textColor=ROJO,
                fontName='Helvetica-Bold', alignment=TA_CENTER)),
             _safe_p(str(n_criticos), ParagraphStyle('kn', fontSize=28, textColor=ROJO,
                fontName='Helvetica-Bold', alignment=TA_CENTER)),
             _safe_p("SÍ" if exito else "NO", ParagraphStyle('kn', fontSize=28,
                textColor=ROJO if exito else VERDE,
                fontName='Helvetica-Bold', alignment=TA_CENTER))],
            [_safe_p("Puntos de entrada\ndetectados", e['etiqueta_numero']),
             _safe_p("Vulnerabilidades\ncríticas", e['etiqueta_numero']),
             _safe_p("Acceso de\nadministrador obtenido", e['etiqueta_numero'])],
        ]
        tabla_kpis = Table(kpis, colWidths=[2.1*inch, 2.1*inch, 2.1*inch])
        tabla_kpis.setStyle(TableStyle([
            ('BACKGROUND',   (0,0),(-1,0), GRIS),
            ('BACKGROUND',   (0,1),(-1,1), BLANCO),
            ('GRID',         (0,0),(-1,-1),1, GRIS_MEDIO),
            ('PADDING',      (0,0),(-1,-1),12),
            ('ALIGN',        (0,0),(-1,-1),'CENTER'),
            ('VALIGN',       (0,0),(-1,-1),'MIDDLE'),
        ]))
        self.story.append(tabla_kpis)
        self._sp()

    # ── QUÉ SIGNIFICA PARA EL NEGOCIO ────────────────────────────────────────
    def _impacto_negocio(self, nivel, exito, vulns):
        e = self.e
        self.story.append(_safe_p("¿QUÉ SIGNIFICA ESTO PARA SU NEGOCIO?", e['seccion']))
        self._sep(AZUL_OSCURO, 2)

        riesgos = []
        if exito:
            riesgos.append(("🔴 Robo de información confidencial",
                "Un atacante con acceso de administrador puede copiar toda la información "
                "de clientes, empleados, finanzas y propiedad intelectual de la empresa."))
            riesgos.append(("🔴 Interrupción de operaciones",
                "El atacante puede apagar sistemas, borrar datos o instalar ransomware "
                "(secuestro de información) exigiendo pago para recuperarla."))
            riesgos.append(("🔴 Responsabilidad legal",
                "En México, la Ley Federal de Protección de Datos Personales obliga a "
                "proteger la información. Una brecha puede resultar en multas y demandas."))
        else:
            riesgos.append(("🟡 Vulnerabilidades activas",
                "Existen servicios con fallos de seguridad conocidos que podrían ser "
                "aprovechados por atacantes con las herramientas adecuadas."))
            riesgos.append(("🟡 Exposición de datos",
                "Algunos servicios detectados transmiten información sin cifrado, "
                "lo que permite interceptar comunicaciones."))
            riesgos.append(("🟡 Riesgo de continuidad",
                "Sin atender estas vulnerabilidades, el riesgo de incidente aumenta "
                "con el tiempo a medida que más actores maliciosos las descubren."))

        for titulo, desc in riesgos:
            tabla_riesgo = Table(
                [[_safe_p(titulo, ParagraphStyle('rt', fontSize=10, textColor=NEGRO,
                    fontName='Helvetica-Bold')),
                  _safe_p(desc, e['cuerpo_small'])]],
                colWidths=[2.2*inch, 4.1*inch]
            )
            tabla_riesgo.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,-1), GRIS),
                ('GRID',       (0,0),(-1,-1),0.5, GRIS_MEDIO),
                ('PADDING',    (0,0),(-1,-1),10),
                ('VALIGN',     (0,0),(-1,-1),'TOP'),
            ]))
            self.story.append(tabla_riesgo)
            self.story.append(Spacer(1, 0.08*inch))

        self._sp()

    # ── SEMÁFORO DE ÁREAS ─────────────────────────────────────────────────────
    def _semaforo_areas(self, scores):
        e = self.e
        self.story.append(_safe_p("ESTADO DE SEGURIDAD POR ÁREA", e['seccion']))
        self._sep(AZUL_OSCURO, 2)
        self.story.append(_safe_p(
            "Este semáforo resume el estado de cada área evaluada. "
            "Rojo significa atención urgente, amarillo precaución, verde aceptable.",
            e['cuerpo']))
        self._sp(0.1)

        areas = [
            ("Facilidad de ataque", scores["explotabilidad"],
             "¿Qué tan fácil es para un atacante comprometer el sistema?"),
            ("Daño potencial", scores["impacto"],
             "¿Cuánto daño puede causar un atacante si logra entrar?"),
            ("Permanencia del atacante", scores["persistencia"],
             "¿Puede el atacante mantener acceso sin ser detectado?"),
            ("Superficie expuesta", scores["exposicion"],
             "¿Cuántos servicios y puertos están accesibles desde fuera?"),
        ]

        encabezado = [
            _safe_p("ÁREA", ParagraphStyle('enc', fontSize=9, textColor=BLANCO,
                fontName='Helvetica-Bold', alignment=TA_CENTER)),
            _safe_p("ESTADO", ParagraphStyle('enc', fontSize=9, textColor=BLANCO,
                fontName='Helvetica-Bold', alignment=TA_CENTER)),
            _safe_p("QUÉ SIGNIFICA", ParagraphStyle('enc', fontSize=9, textColor=BLANCO,
                fontName='Helvetica-Bold', alignment=TA_CENTER)),
            _safe_p("ACCIÓN", ParagraphStyle('enc', fontSize=9, textColor=BLANCO,
                fontName='Helvetica-Bold', alignment=TA_CENTER)),
        ]
        filas = [encabezado]

        for area_nombre, (score, nivel), descripcion in areas:
            color_bg = COLOR_NIVEL_CLARO.get(nivel, GRIS)
            color_txt = COLOR_NIVEL.get(nivel, AZUL_MEDIO)
            urgencia = URGENCIA_NIVEL.get(nivel, "REVISAR")
            filas.append([
                _safe_p(area_nombre, e['cuerpo_small']),
                _safe_p(f"<b>{nivel}</b>", ParagraphStyle('nv', fontSize=9,
                    textColor=color_txt, fontName='Helvetica-Bold', alignment=TA_CENTER)),
                _safe_p(descripcion, e['cuerpo_small']),
                _safe_p(urgencia, ParagraphStyle('urg', fontSize=8,
                    textColor=color_txt, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            ])

        tabla = Table(filas, colWidths=[1.5*inch, 1*inch, 2.8*inch, 1.2*inch])
        estilos_tabla = [
            ('BACKGROUND',   (0,0),(-1,0), AZUL_OSCURO),
            ('FONTSIZE',     (0,0),(-1,-1),9),
            ('GRID',         (0,0),(-1,-1),0.5, GRIS_MEDIO),
            ('PADDING',      (0,0),(-1,-1),8),
            ('VALIGN',       (0,0),(-1,-1),'MIDDLE'),
        ]
        for i, (_, (score, nivel), _) in enumerate(areas, start=1):
            estilos_tabla.append(
                ('BACKGROUND', (0,i),(-1,i), COLOR_NIVEL_CLARO.get(nivel, GRIS))
            )
        tabla.setStyle(TableStyle(estilos_tabla))
        self.story.append(tabla)
        self._sp()

    # ── TOP 3 ACCIONES ────────────────────────────────────────────────────────
    def _top3_acciones(self, nivel, exito, vulns, perfil):
        e = self.e
        self.story.append(PageBreak())
        self.story.append(_safe_p("LAS 3 ACCIONES MÁS IMPORTANTES", e['seccion']))
        self._sep(AZUL_OSCURO, 2)
        self.story.append(_safe_p(
            "De todo lo encontrado, estas son las tres acciones que generan mayor impacto "
            "en la seguridad de su empresa. Le recomendamos iniciar por aquí.",
            e['cuerpo']))
        self._sp(0.1)

        servicios = " ".join(perfil.services).lower() if hasattr(perfil,'services') and perfil.services else ""

        acciones = []

        if exito:
            acciones.append({
                "numero": "1",
                "titulo": "Actualizar y parchear los sistemas críticos",
                "plazo": "Esta semana",
                "esfuerzo": "Medio",
                "impacto": "Crítico",
                "descripcion": (
                    "Los sistemas evaluados tienen versiones de software con vulnerabilidades conocidas "
                    "desde hace años. Actualizar estos sistemas elimina inmediatamente los vectores de "
                    "ataque más graves encontrados durante la evaluación."
                ),
            })
            acciones.append({
                "numero": "2",
                "titulo": "Deshabilitar servicios innecesarios y expuestos",
                "plazo": "Esta semana",
                "esfuerzo": "Bajo",
                "impacto": "Alto",
                "descripcion": (
                    "Se detectaron servicios activos que no son necesarios para la operación del negocio "
                    "y que representan puertas de entrada para atacantes. Deshabilitarlos reduce "
                    "inmediatamente la superficie de ataque."
                ),
            })
            acciones.append({
                "numero": "3",
                "titulo": "Implementar monitoreo y alertas de seguridad",
                "plazo": "Este mes",
                "esfuerzo": "Medio",
                "impacto": "Alto",
                "descripcion": (
                    "Actualmente no existe visibilidad sobre quién accede a los sistemas ni cuándo. "
                    "Implementar un sistema básico de alertas permite detectar ataques en tiempo real "
                    "antes de que causen daño."
                ),
            })
        else:
            acciones.append({
                "numero": "1",
                "titulo": "Actualizar software y aplicar parches de seguridad",
                "plazo": "Este mes",
                "esfuerzo": "Medio",
                "impacto": "Alto",
                "descripcion": (
                    "Se identificaron versiones de software con vulnerabilidades conocidas. "
                    "Mantener el software actualizado es la medida de mayor impacto con el menor costo."
                ),
            })
            acciones.append({
                "numero": "2",
                "titulo": "Revisar y fortalecer las contraseñas de acceso",
                "plazo": "Esta semana",
                "esfuerzo": "Bajo",
                "impacto": "Alto",
                "descripcion": (
                    "Algunos servicios detectados utilizan contraseñas débiles o por defecto. "
                    "Cambiar estas contraseñas por contraseñas robustas y únicas es una acción "
                    "inmediata de bajo costo y alto impacto."
                ),
            })
            acciones.append({
                "numero": "3",
                "titulo": "Configurar un firewall para limitar el acceso",
                "plazo": "Este mes",
                "esfuerzo": "Medio",
                "impacto": "Medio",
                "descripcion": (
                    "Se detectaron múltiples servicios accesibles desde la red. "
                    "Un firewall correctamente configurado limita qué servicios pueden ser "
                    "alcanzados desde fuera, reduciendo significativamente los vectores de ataque."
                ),
            })

        for accion in acciones:
            datos = [
                [_safe_p(f"ACCIÓN {accion['numero']}", ParagraphStyle('an', fontSize=11,
                    textColor=BLANCO, fontName='Helvetica-Bold')),
                 _safe_p(accion['titulo'], ParagraphStyle('at', fontSize=11,
                    textColor=BLANCO, fontName='Helvetica-Bold'))],
            ]
            tabla_header = Table(datos, colWidths=[1.2*inch, 5.3*inch])
            tabla_header.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,-1), AZUL_OSCURO),
                ('PADDING',    (0,0),(-1,-1),10),
                ('VALIGN',     (0,0),(-1,-1),'MIDDLE'),
            ]))
            self.story.append(tabla_header)

            detalle = [
                [_safe_p("Plazo:", e['subseccion']),
                 _safe_p(accion['plazo'], e['cuerpo_small']),
                 _safe_p("Esfuerzo:", e['subseccion']),
                 _safe_p(accion['esfuerzo'], e['cuerpo_small']),
                 _safe_p("Impacto:", e['subseccion']),
                 _safe_p(accion['impacto'], e['cuerpo_small'])],
                [_safe_p(accion['descripcion'], e['cuerpo_small']),
                 '', '', '', '', ''],
            ]
            tabla_detalle = Table(detalle, colWidths=[0.8*inch,1*inch,0.8*inch,0.9*inch,0.8*inch,1.2*inch])
            tabla_detalle.setStyle(TableStyle([
                ('BACKGROUND',  (0,0),(-1,0), GRIS),
                ('BACKGROUND',  (0,1),(-1,1), BLANCO),
                ('SPAN',        (0,1),(-1,1)),
                ('GRID',        (0,0),(-1,-1),0.5, GRIS_MEDIO),
                ('PADDING',     (0,0),(-1,-1),8),
                ('VALIGN',      (0,0),(-1,-1),'TOP'),
                ('FONTSIZE',    (0,0),(-1,-1),9),
            ]))
            self.story.append(tabla_detalle)
            self._sp(0.15)

        self._sp()

    # ── PRÓXIMOS PASOS ────────────────────────────────────────────────────────
    def _proximos_pasos(self, nivel):
        e = self.e
        self.story.append(_safe_p("PRÓXIMOS PASOS RECOMENDADOS", e['seccion']))
        self._sep(AZUL_OSCURO, 2)

        pasos = [
            ("Semana 1",     "Atender las vulnerabilidades críticas identificadas en este informe."),
            ("Mes 1",        "Implementar las 3 acciones prioritarias detalladas en la sección anterior."),
            ("Trimestre 1",  "Capacitar al equipo de sistemas en mejores prácticas de seguridad."),
            ("6 meses",      "Realizar una nueva evaluación de seguridad para medir el avance."),
            ("Anual",        "Establecer un programa continuo de evaluaciones de seguridad."),
        ]

        tabla = Table(pasos, colWidths=[1.3*inch, 5*inch])
        tabla.setStyle(TableStyle([
            ('FONTNAME',      (0,0),(0,-1), 'Helvetica-Bold'),
            ('FONTSIZE',      (0,0),(-1,-1),9),
            ('TEXTCOLOR',     (0,0),(0,-1), AZUL_OSCURO),
            ('ROWBACKGROUNDS',(0,0),(-1,-1),[GRIS, BLANCO]),
            ('GRID',          (0,0),(-1,-1),0.5, GRIS_MEDIO),
            ('PADDING',       (0,0),(-1,-1),9),
        ]))
        self.story.append(tabla)
        self._sp(0.2)

        self.story.append(_safe_p(
            "Para mayor información sobre las vulnerabilidades técnicas encontradas, "
            "solicite el <b>Reporte Técnico Detallado</b> a su consultor de seguridad.",
            e['cuerpo']))

        self._sp(0.2)
        self._sep(ROJO)
        self.story.append(_safe_p(
            f"Informe ID: {self.reporte_id}  |  Preparado por: {self.consultor}  |  "
            f"Fecha: {self.fecha}  |  CONFIDENCIAL",
            e['footer']
        ))

    # ── GENERAR PDF ───────────────────────────────────────────────────────────
    def generar(self, scores, vulns, exito, credenciales="", perfil=None):
        """
        scores      — dict de _calcular_risk_score()
        vulns       — lista de vulnerabilidades de _extraer_vulnerabilidades()
        exito       — bool — si se obtuvo sesión
        credenciales— str — output de Hydra
        perfil      — objeto con .ports, .services, .os_family, .ip
        """
        nivel      = scores["total"][1]
        n_criticos = sum(1 for v in vulns if v[5] == "CRITICO")
        n_puertos  = len(perfil.ports) if perfil and hasattr(perfil,'ports') else 0

        carpeta = Path(__file__).parent.parent / "reportes"
        carpeta.mkdir(parents=True, exist_ok=True)

        nombre_archivo = f"ejecutivo_{self.ip.replace('.','_')}_{self.fecha}.pdf"
        ruta = str(carpeta / nombre_archivo)

        doc = SimpleDocTemplate(ruta, pagesize=letter,
                                rightMargin=0.75*inch, leftMargin=0.75*inch,
                                topMargin=0.75*inch,   bottomMargin=0.75*inch)

        self._portada()
        self._resumen_direccion(nivel, exito, n_criticos, n_puertos)
        self._impacto_negocio(nivel, exito, vulns)
        self._semaforo_areas(scores)
        self._top3_acciones(nivel, exito, vulns, perfil or _PerfilVacio())
        self._proximos_pasos(nivel)

        doc.build(self.story)
        print(f"\n📊 Reporte Ejecutivo guardado en: {ruta}")
        return ruta


class _PerfilVacio:
    """Perfil vacío para cuando no hay datos."""
    ports    = []
    services = []
    os_family = "desconocido"
    ip        = "N/A"