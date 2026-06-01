import os
import sys
import json
import hashlib
import subprocess
import sqlite3
from pathlib import Path
from datetime import datetime

# ── PATH SETUP — ANTES de todo import local ──────────────────────────────────
ruta_raiz = str(Path(__file__).resolve().parent.parent)
if ruta_raiz not in sys.path:
    sys.path.insert(0, ruta_raiz)

# ── Flask y módulos locales ──────────────────────────────────────────────────
from flask import Flask, render_template, request, send_from_directory, jsonify, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_dance.contrib.google import make_google_blueprint, google

import config
from core.database import RedTeamDB

# ── APP SETUP ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(32))
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # solo para localhost

# ── GOOGLE OAUTH ──────────────────────────────────────────────────────────────
google_bp = make_google_blueprint(
    client_id     = os.getenv("GOOGLE_CLIENT_ID"),
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET"),
    scope         = ["openid", "https://www.googleapis.com/auth/userinfo.email",
                     "https://www.googleapis.com/auth/userinfo.profile"],
    redirect_url  = "/login/google/authorized"
)
app.register_blueprint(google_bp, url_prefix="/login")

# ── LOGIN MANAGER ────────────────────────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = None

db = RedTeamDB()

CARPETA_REPORTES = Path(ruta_raiz) / "reportes"
LOG_FILE_PATH    = Path(ruta_raiz) / "d4yshell.log"
DB_PATH          = Path(ruta_raiz) / "d4yshell.db"


# ── BASE DE DATOS DE USUARIOS ─────────────────────────────────────────────────
def _get_db():
    return sqlite3.connect(str(DB_PATH))

def _init_users_table():
    conn = _get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            username         TEXT UNIQUE NOT NULL,
            email            TEXT UNIQUE NOT NULL,
            password_hash    TEXT,
            nombre           TEXT,
            apellido         TEXT,
            empresa          TEXT,
            google_id        TEXT,
            acepta_terminos  INTEGER DEFAULT 0,
            created_at       TEXT
        )
    """)
    conn.commit()
    conn.close()

_init_users_table()


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ── USER MODEL ────────────────────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, id, username, email, nombre, apellido, empresa):
        self.id       = str(id)
        self.username = username
        self.email    = email
        self.nombre   = nombre or ""
        self.apellido = apellido or ""
        self.empresa  = empresa or ""

    @staticmethod
    def get_by_id(user_id):
        try:
            conn = _get_db()
            cur  = conn.execute(
                "SELECT id, username, email, nombre, apellido, empresa FROM users WHERE id = ?",
                (user_id,)
            )
            row = cur.fetchone()
            conn.close()
            return User(*row) if row else None
        except Exception:
            return None

    @staticmethod
    def get_by_email(email):
        try:
            conn = _get_db()
            cur  = conn.execute(
                "SELECT id, username, email, nombre, apellido, empresa FROM users WHERE email = ?",
                (email,)
            )
            row = cur.fetchone()
            conn.close()
            return User(*row) if row else None
        except Exception:
            return None

    @staticmethod
    def validar(username, password):
        try:
            conn = _get_db()
            cur  = conn.execute(
                "SELECT id, username, email, nombre, apellido, empresa FROM users WHERE username = ? AND password_hash = ?",
                (username, _hash(password))
            )
            row = cur.fetchone()
            conn.close()
            return User(*row) if row else None
        except Exception:
            return None

    @staticmethod
    def existe_username(username):
        conn = _get_db()
        cur  = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        existe = cur.fetchone() is not None
        conn.close()
        return existe

    @staticmethod
    def existe_email(email):
        conn = _get_db()
        cur  = conn.execute("SELECT 1 FROM users WHERE email = ?", (email,))
        existe = cur.fetchone() is not None
        conn.close()
        return existe

    @staticmethod
    def crear(username, email, password, nombre, apellido, empresa):
        conn = _get_db()
        conn.execute(
            """INSERT INTO users (username, email, password_hash, nombre, apellido, empresa, acepta_terminos, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
            (username, email, _hash(password) if password else None,
             nombre, apellido, empresa, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()

    @staticmethod
    def crear_google(email, nombre, apellido, google_id):
        """Crea usuario desde Google OAuth — sin contraseña."""
        username = email.split("@")[0].lower().replace(".", "_")
        # Si el username ya existe le agrega un sufijo
        base = username
        i = 1
        while User.existe_username(username):
            username = f"{base}{i}"
            i += 1
        conn = _get_db()
        conn.execute(
            """INSERT INTO users (username, email, nombre, apellido, google_id, acepta_terminos, created_at)
               VALUES (?, ?, ?, ?, ?, 1, ?)""",
            (username, email, nombre, apellido, google_id, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        return username


@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)


# ── AUTH ROUTES ───────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.validar(username, password)
        if user:
            login_user(user)
            return redirect(request.args.get("next", url_for("index")))
        else:
            error = "Usuario o contraseña incorrectos."

    return render_template("login.html", error=error)


@app.route("/login/google/authorized")
def google_authorized():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return redirect(url_for("login"))

    info      = resp.json()
    email     = info.get("email", "")
    nombre    = info.get("given_name", "")
    apellido  = info.get("family_name", "")
    google_id = info.get("id", "")

    # Si ya existe el usuario lo loguea directo
    user = User.get_by_email(email)
    if not user:
        # Primera vez — crea la cuenta automáticamente
        username = User.crear_google(email, nombre, apellido, google_id)
        user = User.get_by_email(email)

    if user:
        login_user(user)
        return redirect(url_for("index"))

    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username          = request.form.get("username",          "").strip().lower()
        email             = request.form.get("email",             "").strip().lower()
        password          = request.form.get("password",          "")
        password2         = request.form.get("password2",         "")
        nombre            = request.form.get("nombre",            "").strip()
        apellido          = request.form.get("apellido",          "").strip()
        empresa           = request.form.get("empresa",           "").strip()
        acepta_terminos   = request.form.get("acepta_terminos")
        acepta_mayoria    = request.form.get("acepta_mayoria")
        acepta_autorizado = request.form.get("acepta_autorizado")

        if not all([username, email, password, nombre, apellido]):
            error = "Todos los campos obligatorios deben estar completos."
        elif len(password) < 8:
            error = "La contraseña debe tener al menos 8 caracteres."
        elif password != password2:
            error = "Las contraseñas no coinciden."
        elif not acepta_terminos or not acepta_mayoria or not acepta_autorizado:
            error = "Debes aceptar todos los términos para continuar."
        elif User.existe_username(username):
            error = "Ese nombre de usuario ya está en uso."
        elif User.existe_email(email):
            error = "Ese correo electrónico ya está registrado."
        else:
            User.crear(username, email, password, nombre, apellido, empresa)
            user = User.validar(username, password)
            login_user(user)
            return redirect(url_for("index"))

    return render_template("register.html", error=error)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ── RUTAS PROTEGIDAS ──────────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    scans = db.obtener_todos_los_scans()
    lista_scans = []
    for s in scans:
        ip, os_family, services_json, ports_json, timestamp = s
        try:    services = json.loads(services_json) if services_json else []
        except: services = [services_json] if services_json else []
        try:    ports = json.loads(ports_json) if ports_json else []
        except: ports = [ports_json] if ports_json else []
        lista_scans.append({
            "ip": ip, "os_family": os_family,
            "services_count": len(services),
            "ports_count": len(ports),
            "timestamp": timestamp
        })

    total_credenciales = total_exploits_exito = total_exploits_intentos = 0
    for item in db.obtener_knowledge_graph():
        total_exploits_exito += item[3]
    for s in scans:
        ip = s[0]
        total_credenciales      += len(db.obtener_credenciales_por_ip(ip))
        total_exploits_intentos += len(db.obtener_exploits_por_ip(ip))

    stats = {
        "total_targets":           len(scans),
        "total_credentials":       total_credenciales,
        "total_exploits_exito":    total_exploits_exito,
        "total_exploits_intentos": total_exploits_intentos,
    }
    return render_template("index.html", scans=lista_scans, stats=stats)


@app.route("/scan", methods=["POST"])
@login_required
def launch_scan():
    ip      = request.form.get("ip", "").strip()
    modules = request.form.get("modules", "all").strip() or "all"
    if not ip:
        return "Por favor ingresa una IP o hostname válido.", 400
    try:
        script_path = str(Path(ruta_raiz) / "main.py")
        subprocess.Popen([sys.executable, script_path, "--target", ip, "--modules", modules])
        import time; time.sleep(1.5)
        return redirect(url_for("view_logs"))
    except Exception as e:
        return f"Error lanzando el escaneo autónomo: {e}", 500


@app.route("/nuevo-scan")
@login_required
def nuevo_scan():
    return render_template("nuevo_scan.html")


@app.route("/api/launch", methods=["POST"])
@login_required
def api_launch():
    import re, threading
    data    = request.get_json(force=True) or {}
    ip      = data.get("target", "").strip()
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
@login_required
def target_detail(ip):
    scans = db.obtener_todos_los_scans()
    target_scan = next((s for s in scans if s[0] == ip), None)
    if not target_scan:
        return "Target no encontrado", 404

    _, os_family, services_json, ports_json, timestamp = target_scan
    try:    services = json.loads(services_json) if services_json else []
    except: services = [services_json] if services_json else []
    try:    ports = json.loads(ports_json) if ports_json else []
    except: ports = [ports_json] if ports_json else []

    credenciales = db.obtener_credenciales_por_ip(ip)
    exploits     = db.obtener_exploits_por_ip(ip)
    osint_raw    = db.obtener_osint_por_ip(ip)

    osint_data = {}
    if osint_raw:
        try:    banners  = json.loads(osint_raw[3]) if osint_raw[3] else {}
        except: banners  = {}
        try:    dns_data = json.loads(osint_raw[4]) if osint_raw[4] else {}
        except: dns_data = {}
        try:    resumen  = json.loads(osint_raw[5]) if osint_raw[5] else []
        except: resumen  = []
        osint_data = {
            "hostname": osint_raw[0], "os_por_ttl": osint_raw[1],
            "whois": osint_raw[2], "banners": banners,
            "dns": dns_data, "resumen": resumen, "timestamp": osint_raw[6],
        }

    intentos_exploits = []
    evidencia_total   = ""
    for exp in exploits:
        exp_name, cve, exito, evidencia, tstamp = exp
        is_exito = bool(exito)
        if is_exito:
            evidencia_total = evidencia
        intentos_exploits.append({
            "name": exp_name, "cve": cve, "exito": is_exito,
            "evidencia": evidencia, "timestamp": tstamp,
        })

    from reporting.reporte_pdf import _calcular_risk_score
    class _PerfilTemp: pass
    _p = _PerfilTemp()
    _p.ports = ports
    _p.services = services
    scores = _calcular_risk_score(_p, evidencia_total)

    def _clase(n):
        return {"CRITICO":"danger","ALTO":"warning","MEDIO":"info","BAJO":"success"}.get(n,"info")

    risk_score = {
        "total": scores["total"][0], "nivel": scores["total"][1], "clase": _clase(scores["total"][1]),
        "detalles": [
            {"categoria":"Explotabilidad","score":scores["explotabilidad"][0],"nivel":scores["explotabilidad"][1],"clase":_clase(scores["explotabilidad"][1])},
            {"categoria":"Impacto",       "score":scores["impacto"][0],       "nivel":scores["impacto"][1],       "clase":_clase(scores["impacto"][1])},
            {"categoria":"Persistencia",  "score":scores["persistencia"][0],  "nivel":scores["persistencia"][1],  "clase":_clase(scores["persistencia"][1])},
            {"categoria":"Exposición",    "score":scores["exposicion"][0],    "nivel":scores["exposicion"][1],    "clase":_clase(scores["exposicion"][1])},
        ],
    }

    return render_template(
        "target.html", ip=ip, os_family=os_family, services=services, ports=ports,
        timestamp=timestamp, credenciales=credenciales,
        exploits=intentos_exploits, osint=osint_data, risk_score=risk_score
    )


@app.route("/reportes")
@login_required
def list_reports():
    reports = []
    if CARPETA_REPORTES.exists():
        for file in sorted(os.listdir(CARPETA_REPORTES), reverse=True):
            if file.endswith(".pdf"):
                full_path = CARPETA_REPORTES / file
                stats = full_path.stat()
                reports.append({
                    "filename": file,
                    "size":     f"{round(stats.st_size / 1024, 1)} KB",
                    "mtime":    _tstamp_a_fecha(stats.st_mtime),
                })
    return render_template("reportes.html", reportes=reports)


@app.route("/reportes/descargar/<filename>")
@login_required
def download_report(filename):
    if not filename.endswith(".pdf"):
        return "Acceso denegado", 403
    return send_from_directory(CARPETA_REPORTES, filename, as_attachment=True)


@app.route("/logs")
@login_required
def view_logs():
    return render_template("logs.html")


@app.route("/api/logs")
@login_required
def api_logs():
    lineas = []
    if LOG_FILE_PATH.exists():
        with open(LOG_FILE_PATH, "r", encoding="utf-8", errors="ignore") as f:
            lineas = f.readlines()
    return jsonify({"logs": [l.strip() for l in lineas[-150:] if l.strip()]})


@app.route("/knowledge-graph")
@login_required
def view_knowledge_graph():
    kg = db.obtener_knowledge_graph()
    lista_kg = [{"os_family":i[0],"service":i[1],"exploit_name":i[2],"success_count":i[3]} for i in kg]
    return render_template("knowledge_graph.html", graph=lista_kg)


# ── HELPERS ───────────────────────────────────────────────────────────────────
def _tstamp_a_fecha(tstamp):
    return datetime.fromtimestamp(tstamp).strftime('%Y-%m-%d %H:%M:%S')


# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    CARPETA_REPORTES.mkdir(parents=True, exist_ok=True)
    print("D4YSHELL Dashboard iniciado en http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)