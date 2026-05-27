# 🛡️ Autonomous AI Red Team Platform v2.1

Suite de ciberseguridad ofensiva autónoma basada en agentes de Inteligencia Artificial. La plataforma realiza reconocimiento activo/pasivo, modela superficies de ataque usando múltiples agentes (CrewAI), realiza ataques de fuerza bruta y explotación, ejecuta post-explotación remota sobre objetivos comprometidos y genera reportes formales en formato PDF, además de ofrecer un centro de comando web local.

---

## 🏗️ Arquitectura Modular del Sistema

El pipeline se ejecuta secuencialmente o por módulos específicos:

```
[Target IP] 
    │
    ├── FASE 1: Reconocimiento Activo ────► [Nmap Scan] ─┐
    ├── FASE 0.5: OSINT Pasivo ───────────► [WHOIS/DNS] ─┼─► [TargetProfile]
    │                                                    │
    ┌────────────────────────────────────────────────────┘
    ▼
FASE 2: CrewAI Team ──► [ReconAgent (Clasifica)] ──► [VulnAgent (CVE)] ──► [ExploitPlanner (Plan)]
    │
    ▼
FASE 2.5: Hydra ──────► [Fuerza Bruta en SSH/FTP/etc.] ──► Guardar Credenciales en BD
    │
    ▼
FASE 3: Explotación ──► [Metasploit Core / SSH Exec] ──► Abrir Sesión Remota
    │
    ▼
FASE 4: Post-Exploit ─► [Shadow/Keys/Sysinfo/SUID] ──► Guardar Evidencia
    │
    ▼
FASE 5: Reporte ──────► [Generación de PDF Profesional en /reportes]
    │
    ▼
[DASHBOARD WEB] ──────► Interfaz Flask Local en http://localhost:5000 (SQLite DB)
```

---

## 📁 Estructura del Directorio

*   `main.py`: Orquestador principal del pipeline autónomo.
*   `config.py`: Gestor de variables de entorno y validación inicial de seguridad.
*   `core/`:
    *   `models.py`: Estructura del `TargetProfile` enriquecido con datos de OSINT.
    *   `database.py`: Manejador de la base de datos SQLite local (`redteam.db`), con persistencia histórica y Knowledge Graph para auto-aprendizaje.
    *   `executor.py`: Motor de ejecución asíncrono con SSH y sistema de polling sobre Kali Linux.
    *   `ssh_manager.py` / `session_manager.py`: Gestión de túneles SSH y almacenamiento seguro de sesiones exitosas.
*   `osint/`: Módulo de reconocimiento pasivo local y remoto sin interacción agresiva.
*   `recon/`: Envoltura y parseador inteligente del escaneo de puertos Nmap.
*   `ai/`: Planificador de ataque inteligente multi-agente usando CrewAI.
*   `bruteforce/`: Módulo de ataques a servicios mediante Hydra.
*   `exploits/`: Despachador dinámico y autónomo de exploits de Metasploit.
*   `post_exploitation/`: Recolector automático de evidencias de post-compromiso (incluye fix optimizado para bindshells).
*   `reporting/`: Generador de reportes PDF corporativos con ReportLab.
*   `dashboard/`: Interfaz web interactiva en Flask con dashboard general, log en vivo y visor de base de conocimiento.
*   `reportes/`: Directorio centralizado exclusivo para el resguardo de los reportes PDF.

---

## 🛠️ Instalación y Requisitos

### Prerrequisitos
*   **Python 3.10+** instalado en el host local (Windows/Linux/macOS).
*   **Máquina Kali Linux** accesible por SSH (con privilegios para ejecutar herramientas de red y Metasploit).
*   **Ollama** ejecutándose localmente con el modelo configurado (por ejemplo, `llama3.1:8b` o similar).

### Instalación de dependencias locales
Instala las dependencias requeridas en tu entorno de Python local:
```bash
pip install -r requirements.txt
```

### Configuración del Entorno (.env)
Crea o edita un archivo `.env` en la raíz del proyecto con la siguiente estructura:
```env
KALI_IP=192.168.56.101
KALI_USER=kali
KALI_PASS=tu_contraseña_ssh_aqui
DEFAULT_TARGET=192.168.56.103
OLLAMA_MODEL=ollama/llama3.1:8b
EXPLOIT_TIMEOUT=120
POST_EXPLOIT_TIMEOUT=180
HYDRA_THREADS=16
```

---

## 🚀 Guía de Uso

### 1. Ejecutar el Pipeline Autónomo Completo
Para analizar un objetivo de forma totalmente automatizada (desde reconocimiento hasta reporte):
```bash
python main.py --target 192.168.56.103
```

### 2. Ejecutar Módulos Específicos
Puedes correr partes selectas del pipeline usando el argumento `--modules`:
*   *Solo Reconocimiento y OSINT:*
    ```bash
    python main.py --target 192.168.56.103 --modules recon,osint
    ```
*   *Solo Generar Reporte:*
    ```bash
    python main.py --target 192.168.56.103 --modules report
    ```

### 3. Lanzar el Dashboard Web
Para visualizar estadísticas, inspeccionar targets analizados históricamente, ver credenciales capturadas y descargar reportes PDF directamente desde el navegador:
```bash
python dashboard/app.py
```
Abre en tu navegador: [http://localhost:5000](http://localhost:5000)

---

## 🔒 Mejoras de Seguridad y Estabilidad v2.1
1.  **Credenciales Seguras**: Se removieron todas las credenciales por defecto. El sistema valida las variables del archivo `.env` en el arranque y detiene la ejecución si detecta configuraciones inseguras.
2.  **Optimización Post-Explotación (Bindshells)**: Se implementó un flujo directo mediante netcat (`nc`) para interactuar con sesiones de tipo bindshell (puerto 1524), evitando re-lanzar Metasploit y mejorando el tiempo de respuesta en un 400%.
3.  **Base de Conocimiento de Éxitos**: Se agregó un `Knowledge Graph` persistente en base de datos que registra exploits exitosos por Sistema Operativo, permitiendo al sistema optimizar futuros ataques en base a su propio historial.
4.  **Resguardo de Reportes**: Los reportes PDF corporativos generados se almacenan ordenadamente en el directorio dedicado `/reportes/`.
