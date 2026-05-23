import sqlite3
import json
import os
from utils.logger import log

class RedTeamDB:
    def __init__(self, db_path="redteam.db"):
        self.db_path = db_path
        self._inicializar_bd()

    def _conectar(self):
        return sqlite3.connect(self.db_path)

    def _inicializar_bd(self):
        try:
            with self._conectar() as conn:
                cursor = conn.cursor()
                
                # Tabla de Escaneos / Targets
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    os_family TEXT,
                    services TEXT,
                    ports TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """)

                # Tabla de Actividades de Explotación
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS exploits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_ip TEXT,
                    exploit_name TEXT,
                    cve TEXT,
                    exito BOOLEAN,
                    evidencia TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """)

                # Tabla de Credenciales Encontradas
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_ip TEXT,
                    service TEXT,
                    username TEXT,
                    password TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """)

                # Tabla de base de conocimiento (Knowledge Graph para auto-aprendizaje)
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS knowledge_graph (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    os_family TEXT,
                    service TEXT,
                    exploit_name TEXT,
                    success_count INTEGER DEFAULT 0,
                    UNIQUE(os_family, service, exploit_name)
                )
                """)
                conn.commit()
        except Exception as e:
            log.error(f"Error inicializando base de datos: {e}")

    def registrar_scan(self, ip, os_family, services, ports):
        try:
            with self._conectar() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO scans (ip, os_family, services, ports, timestamp)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(ip) DO UPDATE SET
                    os_family = excluded.os_family,
                    services = excluded.services,
                    ports = excluded.ports,
                    timestamp = CURRENT_TIMESTAMP
                """, (ip, os_family, json.dumps(services), json.dumps(ports)))
                conn.commit()
                log.info(f"💾 Resultados de escaneo para {ip} guardados en base de datos.")
        except Exception as e:
            log.error(f"Error registrando scan en BD: {e}")

    def registrar_exploit(self, ip, exploit_name, cve, exito, evidencia):
        try:
            with self._conectar() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO exploits (target_ip, exploit_name, cve, exito, evidencia, timestamp)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (ip, exploit_name, cve, exito, evidencia))
                
                if exito:
                    # Encontrar el OS familiar
                    cursor.execute("SELECT os_family FROM scans WHERE ip = ?", (ip,))
                    fila = cursor.fetchone()
                    os_family = fila[0] if fila else "desconocido"
                    
                    # Deducir servicio
                    service = "generic"
                    if "ftp" in exploit_name.lower(): service = "ftp"
                    elif "ssh" in exploit_name.lower(): service = "ssh"
                    elif "telnet" in exploit_name.lower(): service = "telnet"
                    elif "smb" in exploit_name.lower() or "eternalblue" in exploit_name.lower(): service = "smb"
                    elif "irc" in exploit_name.lower(): service = "irc"
                    elif "rdp" in exploit_name.lower() or "bluekeep" in exploit_name.lower(): service = "rdp"
                    
                    cursor.execute("""
                    INSERT INTO knowledge_graph (os_family, service, exploit_name, success_count)
                    VALUES (?, ?, ?, 1)
                    ON CONFLICT(os_family, service, exploit_name) DO UPDATE SET
                        success_count = success_count + 1
                    """, (os_family, service, exploit_name))
                
                conn.commit()
                log.info(f"💾 Registro de exploit '{exploit_name}' completado en BD (Éxito: {exito}).")
        except Exception as e:
            log.error(f"Error registrando exploit en BD: {e}")

    def registrar_credencial(self, ip, service, username, password):
        try:
            with self._conectar() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO credentials (target_ip, service, username, password, timestamp)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (ip, service, username, password))
                conn.commit()
                log.info(f"💾 Credencial descubierta ({service.upper()}) guardada en BD.")
        except Exception as e:
            log.error(f"Error registrando credenciales en BD: {e}")

    def obtener_ranking_exploits(self, os_family, service=None):
        try:
            with self._conectar() as conn:
                cursor = conn.cursor()
                if service:
                    cursor.execute("""
                    SELECT exploit_name, success_count FROM knowledge_graph
                    WHERE os_family = ? AND service = ?
                    ORDER BY success_count DESC
                    """, (os_family, service))
                else:
                    cursor.execute("""
                    SELECT exploit_name, success_count FROM knowledge_graph
                    WHERE os_family = ?
                    ORDER BY success_count DESC
                    """, (os_family,))
                return cursor.fetchall()
        except Exception as e:
            log.error(f"Error obteniendo ranking de exploits: {e}")
            return []
