import os
import sys
import json
import subprocess
from flask import Flask, render_template, request, send_from_directory, jsonify
from pathlib import Path

# Agregar el directorio raíz al path para poder importar core y config
ruta_raiz = str(Path(__file__).parent.parent)
if ruta_raiz not in sys.path:
    sys.path.append(ruta_raiz)

import config
from core.database import RedTeamDB

app = Flask(__name__)
db = RedTeamDB()

# Carpeta de reportes
CARPETA_REPORTES = Path(ruta_raiz) / "reportes"
LOG_FILE_PATH = Path(ruta_raiz) / "d4yshell.log"

@app.route("/")
def index():
    # Obtener estadísticas básicas
    scans = db.obtener_todos_los_scans()
    
    # Formatear scans
    lista_scans = []
    for s in scans:
        ip, os_family, services_json, ports_json, timestamp = s
        try:
            services = json.loads(services_json) if services_json else []
        except:
            services = [services_json] if services_json else []
            
        try:
            ports = json.loads(ports_json) if ports_json else []
        except:
            ports = [ports_json] if ports_json else []
            
        lista_scans.append({
            "ip": ip,
            "os_family": os_family,
            "services_count": len(services),
            "ports_count": len(ports),
            "timestamp": timestamp
        })
        
    # Obtener el total de credenciales y exploits exitosos
    total_credenciales = 0
    total_exploits_exito = 0
    total_exploits_intentos = 0
    
    knowledge = db.obtener_knowledge_graph()
    for item in knowledge:
        total_exploits_exito += item[3] # success_count
        
    for s in scans:
        ip = s[0]
        creds = db.obtener_credenciales_por_ip(ip)
        total_credenciales += len(creds)
        
        exploits = db.obtener_exploits_por_ip(ip)
        total_exploits_intentos += len(exploits)

    stats = {
        "total_targets": len(scans),
        "total_credentials": total_credenciales,
        "total_exploits_exito": total_exploits_exito,
        "total_exploits_intentos": total_exploits_intentos
    }

    return render_template("index.html", scans=lista_scans, stats=stats)

@app.route("/scan", methods=["POST"])
def launch_scan():
    ip = request.form.get("ip", "").strip()
    modules = request.form.get("modules", "all").strip() or "all"
    if not ip:
        return "Por favor ingresa una IP o hostname válido.", 400
        
    try:
        script_path = str(Path(ruta_raiz) / "main.py")
        subprocess.Popen([sys.executable, script_path, "--target", ip, "--modules", modules])
        
        import time
        time.sleep(1.5)
        
        from flask import redirect, url_for
        return redirect(url_for("view_logs"))
    except Exception as e:
        return f"Error lanzando el escaneo autónomo: {e}", 500


@app.route("/nuevo-scan")
def nuevo_scan():
    return render_template("nuevo_scan.html")


@app.route("/api/launch", methods=["POST"])
def api_launch():
    import re, threading
    data = request.get_json(force=True) or {}
    ip = data.get("target", "").strip()
    modules = data.get("modules", "all").strip() or "all"

    if not ip or not re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$', ip):
        return jsonify({"error": "IP inválida"}), 400
    if any(int(p) > 255 for p in ip.split('/')[0].split('.')):
        return jsonify({"error": "IP fuera de rango"}), 400

    script_path = str(Path(ruta_raiz) / "main.py")

    def run():
        subprocess.run([sys.executable, script_path, "--target", ip, "--modules", modules], cwd=ruta_raiz)

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started", "target": ip, "modules": modules})

@app.route("/target/<ip>")
def target_detail(ip):
    # Buscar el target en base a scans
    scans = db.obtener_todos_los_scans()
    target_scan = None
    for s in scans:
        if s[0] == ip:
            target_scan = s
            break
            
    if not target_scan:
        return "Target no encontrado", 404
        
    _, os_family, services_json, ports_json, timestamp = target_scan
    
    try:
        services = json.loads(services_json) if services_json else []
    except:
        services = [services_json] if services_json else []
        
    try:
        ports = json.loads(ports_json) if ports_json else []
    except:
        ports = [ports_json] if ports_json else []
        
    # Obtener credenciales, exploits y OSINT
    credenciales = db.obtener_credenciales_por_ip(ip)
    exploits = db.obtener_exploits_por_ip(ip)
    osint_raw = db.obtener_osint_por_ip(ip)
    
    osint_data = {}
    if osint_raw:
        # Estructura: hostname, os_por_ttl, whois, banners, dns_data, resumen, timestamp
        try:
            banners = json.loads(osint_raw[3]) if osint_raw[3] else {}
        except:
            banners = {}
        try:
            dns_data = json.loads(osint_raw[4]) if osint_raw[4] else {}
        except:
            dns_data = {}
        try:
            resumen = json.loads(osint_raw[5]) if osint_raw[5] else []
        except:
            resumen = []
            
        osint_data = {
            "hostname": osint_raw[0],
            "os_por_ttl": osint_raw[1],
            "whois": osint_raw[2],
            "banners": banners,
            "dns": dns_data,
            "resumen": resumen,
            "timestamp": osint_raw[6]
        }

    # Formatear exploits e identificar éxito
    intentos_exploits = []
    exito_total = False
    evidencia_total = ""
    for exp in exploits:
        exp_name, cve, exito, evidencia, tstamp = exp
        is_exito = bool(exito)
        if is_exito:
            exito_total = True
            evidencia_total = evidencia
        intentos_exploits.append({
            "name": exp_name,
            "cve": cve,
            "exito": is_exito,
            "evidencia": evidencia,
            "timestamp": tstamp
        })

    # Usar la misma función de risk score que el PDF — fuente única de verdad
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(ruta_raiz)))
    from reporting.reporte_pdf import _calcular_risk_score, _nivel_riesgo

    # Construir perfil temporal para reutilizar la función del PDF
    class _PerfilTemp:
        pass
    _p = _PerfilTemp()
    _p.ports    = ports
    _p.services = services
    _evidencia  = evidencia_total

    scores = _calcular_risk_score(_p, _evidencia)

    def _clase_dashboard(nivel_str):
        return {"CRITICO":"danger","ALTO":"warning","MEDIO":"info","BAJO":"success"}.get(nivel_str,"info")

    risk_score = {
        "total": scores["total"][0],
        "nivel": scores["total"][1],
        "clase": _clase_dashboard(scores["total"][1]),
        "detalles": [
            {"categoria": "Explotabilidad", "score": scores["explotabilidad"][0], "nivel": scores["explotabilidad"][1], "clase": _clase_dashboard(scores["explotabilidad"][1])},
            {"categoria": "Impacto",        "score": scores["impacto"][0],        "nivel": scores["impacto"][1],        "clase": _clase_dashboard(scores["impacto"][1])},
            {"categoria": "Persistencia",   "score": scores["persistencia"][0],   "nivel": scores["persistencia"][1],   "clase": _clase_dashboard(scores["persistencia"][1])},
            {"categoria": "Exposición",     "score": scores["exposicion"][0],     "nivel": scores["exposicion"][1],     "clase": _clase_dashboard(scores["exposicion"][1])},
        ]
    }

    return render_template(
        "target.html",
        ip=ip,
        os_family=os_family,
        services=services,
        ports=ports,
        timestamp=timestamp,
        credenciales=credenciales,
        exploits=intentos_exploits,
        osint=osint_data,
        risk_score=risk_score
    )

@app.route("/reportes")
def list_reports():
    reports = []
    if CARPETA_REPORTES.exists():
        for file in os.listdir(CARPETA_REPORTES):
            if file.endswith(".pdf"):
                full_path = CARPETA_REPORTES / file
                stats = full_path.stat()
                reports.append({
                    "filename": file,
                    "size": f"{round(stats.st_size / 1024, 1)} KB",
                    "mtime": tstamp_a_fecha(stats.st_mtime)
                })
    return render_template("reportes.html", reportes=reports)

@app.route("/reportes/descargar/<filename>")
def download_report(filename):
    if not filename.endswith(".pdf"):
        return "Acceso denegado", 403
    return send_from_directory(CARPETA_REPORTES, filename, as_attachment=True)

@app.route("/logs")
def view_logs():
    return render_template("logs.html")

@app.route("/api/logs")
def api_logs():
    lineas = []
    if LOG_FILE_PATH.exists():
        with open(LOG_FILE_PATH, "r", encoding="utf-8", errors="ignore") as f:
            lineas = f.readlines()
    # Retornar las últimas 150 líneas
    ultimas_lineas = [l.strip() for l in lineas[-150:] if l.strip()]
    return jsonify({"logs": ultimas_lineas})

@app.route("/knowledge-graph")
def view_knowledge_graph():
    kg = db.obtener_knowledge_graph()
    lista_kg = []
    for item in kg:
        lista_kg.append({
            "os_family": item[0],
            "service": item[1],
            "exploit_name": item[2],
            "success_count": item[3]
        })
    return render_template("knowledge_graph.html", graph=lista_kg)

def tstamp_a_fecha(tstamp):
    from datetime import datetime
    return datetime.fromtimestamp(tstamp).strftime('%Y-%m-%d %H:%M:%S')

if __name__ == "__main__":
    CARPETA_REPORTES.mkdir(parents=True, exist_ok=True)
    print("D4YSHELL Dashboard iniciado en http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)