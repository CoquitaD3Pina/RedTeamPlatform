from utils.logger import log

class ExploitSession:
    def __init__(self, target_ip, exploit_name, tipo="shell", privilegios="user", puerto=4444):
        self.target_ip = target_ip
        self.exploit_name = exploit_name
        self.tipo = tipo  # 'meterpreter', 'shell', 'ssh', etc.
        self.privilegios = privilegios  # 'root', 'SYSTEM', 'user'
        self.puerto = puerto

class SessionManager:
    _instance = None
    _sesiones = {}

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SessionManager, cls).__new__(cls)
        return cls._instance

    def registrar_sesion(self, target_ip, exploit_name, tipo="shell", privilegios="user", puerto=4444):
        sesion = ExploitSession(target_ip, exploit_name, tipo, privilegios, puerto)
        self._sesiones[target_ip] = sesion
        log.info(f"🔑 Nueva sesión remota en {target_ip} registrada via {exploit_name} ({privilegios}).")

    def obtener_sesion(self, target_ip):
        return self._sesiones.get(target_ip)

    def tiene_sesion_activa(self, target_ip):
        return target_ip in self._sesiones

    def limpiar_sesion(self, target_ip):
        if target_ip in self._sesiones:
            del self._sesiones[target_ip]
            log.info(f"Sesión eliminada para {target_ip}.")
