from crewai import Agent, Task, Crew
from crewai.tools import tool
import subprocess

@tool("escanear_nmap")
def escanear_nmap(ip: str) -> str:
    """Ejecuta un escaneo Nmap contra una IP y devuelve los resultados"""
    resultado = subprocess.run(
        [r"C:\Program Files (x86)\Nmap\nmap.exe", "-sV", "-O", "--osscan-guess", ip],
        capture_output=True, text=True
    )
    return resultado.stdout

def analizar(perfil):
    """La IA analiza el perfil del target y decide el plan de ataque"""
    
    analista = Agent(
        role="Analista de Red Team",
        goal="Analizar vulnerabilidades y planear el ataque más efectivo",
        backstory="Eres un experto en ciberseguridad con años de experiencia en pentesting",
        llm="ollama/llama3.1:8b",
        tools=[escanear_nmap],
        verbose=True
    )
    
    tarea = Task(
        description=f"""Analiza el target {perfil.ip} ({perfil.os_family.upper()}).
        Servicios detectados:
        {chr(10).join(perfil.services[:10])}
        
        Identifica las 3 vulnerabilidades más críticas y recomienda el vector de ataque principal.
        Adapta el análisis al tipo de sistema operativo detectado.""",
        expected_output="Análisis de vulnerabilidades con vector de ataque recomendado",
        agent=analista
    )
    
    equipo = Crew(agents=[analista], tasks=[tarea], verbose=True)
    return equipo.kickoff()