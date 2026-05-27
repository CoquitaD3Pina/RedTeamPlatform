"""
attack_planner.py — CrewAI con datos reales obligatorios, sin alucinaciones.
"""
from crewai import Agent, Task, Crew, Process
import config


def _crear_recon_agent():
    return Agent(
        role="Analista de Reconocimiento",
        goal="Interpretar SOLO los datos reales de Nmap proporcionados. Nunca inventar puertos, servicios o versiones.",
        backstory=(
            "Eres un experto en reconocimiento. Tu regla más importante: "
            "SOLO puedes analizar lo que está en el output real de Nmap. "
            "Si un puerto no aparece en la lista, NO existe. Si una versión no está en los banners, NO la menciones."
        ),
        llm=config.OLLAMA_MODEL,
        verbose=False,
        allow_delegation=False,
    )


def _crear_vuln_agent():
    return Agent(
        role="Experto en Vulnerabilidades",
        goal="Mapear SOLO los servicios detectados a CVEs reales. Nunca mencionar servicios o puertos no detectados.",
        backstory=(
            "Eres un investigador de vulnerabilidades. Regla crítica: "
            "SOLO puedes asignar CVEs a servicios que aparecen en la lista real de Nmap. "
            "Si el análisis dice HTTP puerto 80, NO menciones HTTPS puerto 443. "
            "Cada CVE debe corresponder exactamente al puerto y servicio detectado."
        ),
        llm=config.OLLAMA_MODEL,
        verbose=False,
        allow_delegation=False,
    )


def _crear_exploit_planner():
    return Agent(
        role="Planificador de Explotación",
        goal="Crear plan de ataque basado EXCLUSIVAMENTE en los puertos y servicios realmente detectados.",
        backstory=(
            "Eres un red team operator senior. Tu regla absoluta: "
            "el attack chain SOLO puede mencionar puertos que aparecen en el escaneo Nmap real. "
            "Si el ataque es por puerto 21/FTP, NO menciones puerto 443. "
            "Coherencia total: puerto detectado = servicio = CVE = exploit = attack chain."
        ),
        llm=config.OLLAMA_MODEL,
        verbose=False,
        allow_delegation=False,
    )


def analizar(perfil) -> str:
    servicios_str = "\n".join(f"  - {s}" for s in perfil.services[:15]) or "  - Ninguno detectado"
    puertos_str   = ", ".join(str(p) for p in perfil.ports[:20]) or "Ninguno"
    os_str        = (perfil.os_family or "desconocido").upper()
    arch_str      = getattr(perfil, "architecture", "x64")

    osint         = getattr(perfil, "osint_data", {})
    hostname_str  = osint.get("hostname", "desconocido") or "desconocido"
    ttl_os_str    = osint.get("os_por_ttl", "") or ""
    banners_raw   = osint.get("banners", {})
    banners_str   = "\n".join(f"  Puerto {p}: {b[:80]}" for p, b in banners_raw.items()) or "  Sin banners capturados"

    contexto_base = f"""
=== DATOS REALES DEL ESCANEO NMAP (SOLO ESTOS SON VÁLIDOS) ===
TARGET IP:        {perfil.ip}
HOSTNAME:         {hostname_str}
OS DETECTADO:     {os_str} ({arch_str})
OS POR TTL:       {ttl_os_str}
PUERTOS ABIERTOS: {puertos_str}

SERVICIOS DETECTADOS:
{servicios_str}

BANNERS CAPTURADOS:
{banners_str}

ADVERTENCIA CRÍTICA: NO inventes puertos, servicios ni versiones.
Si no aparece en esta lista, NO existe en el target.
"""

    tarea_recon = Task(
        description=f"""{contexto_base}

Clasifica SOLO los servicios listados arriba por nivel de riesgo (CRITICO/ALTO/MEDIO/BAJO).
No menciones ningún puerto o servicio que no esté en PUERTOS ABIERTOS.
Resume la superficie de ataque en 3-5 puntos usando SOLO datos reales.""",
        expected_output="Clasificación de riesgo de servicios reales detectados. Sin inventar datos.",
        agent=_crear_recon_agent(),
    )

    tarea_vulns = Task(
        description=f"""{contexto_base}

Basándote en el análisis anterior, asigna CVEs SOLO a servicios que aparecen en SERVICIOS DETECTADOS.
Para cada CVE indicado:
1. El puerto debe coincidir EXACTAMENTE con uno de: {puertos_str}
2. El servicio debe estar en la lista de SERVICIOS DETECTADOS
3. Indica CVSS score y si hay exploit público en Metasploit

NO menciones HTTPS si solo se detectó HTTP. NO menciones puerto 443 si no está en la lista.""",
        expected_output="Lista de CVEs reales con puerto exacto, servicio real y CVSS. Sin inconsistencias.",
        agent=_crear_vuln_agent(),
        context=[tarea_recon],
    )

    tarea_plan = Task(
        description=f"""{contexto_base}

Crea el plan de ataque final. REGLA ABSOLUTA:
- El attack chain SOLO puede mencionar puertos de esta lista: {puertos_str}
- Si el exploit es por FTP (puerto 21), NO menciones puerto 443 en ningún lugar
- Coherencia total: puerto detectado → servicio → CVE → exploit → mismo puerto en attack chain

## VECTOR DE ATAQUE PRINCIPAL
[Exploit con mayor probabilidad basado en servicios REALES detectados]

## SECUENCIA DE ATAQUE
[Lista ordenada usando SOLO los servicios realmente detectados]

## POST-EXPLOTACIÓN
[Acciones post-acceso]

## RIESGO GLOBAL
[CRITICO/ALTO/MEDIO/BAJO — debe ser CONSISTENTE con el Risk Score calculado]

## REMEDIACIÓN URGENTE
[3 parches para los servicios REALES detectados]""",
        expected_output="Plan de ataque consistente con los datos reales. Sin contradicciones de puertos.",
        agent=_crear_exploit_planner(),
        context=[tarea_recon, tarea_vulns],
    )

    equipo = Crew(
        agents=[_crear_recon_agent(), _crear_vuln_agent(), _crear_exploit_planner()],
        tasks=[tarea_recon, tarea_vulns, tarea_plan],
        process=Process.sequential,
        verbose=False,
    )

    return str(equipo.kickoff())