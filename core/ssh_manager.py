import paramiko
import config
from utils.logger import log

class KaliSSH:
    _instance = None
    _client = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(KaliSSH, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if self._client is None:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ip = config.KALI_IP
            self.user = config.KALI_USER
            self.password = config.KALI_PASS
            self.is_connected = False

    def connect(self):
        if not self.is_connected or not self._is_channel_active():
            try:
                log.info(f"Estableciendo conexión SSH a Kali ({self.ip})...")
                self._client.connect(self.ip, username=self.user, password=self.password, timeout=15)
                self.is_connected = True
                log.info("Conexión SSH a Kali establecida con éxito.")
            except Exception as e:
                log.error(f"No se pudo conectar a Kali via SSH: {e}")
                self.is_connected = False
                raise e
        return self

    def _is_channel_active(self):
        if self._client and self._client.get_transport():
            return self._client.get_transport().is_active()
        return False

    def disconnect(self):
        if self.is_connected and self._client:
            try:
                self._client.close()
                log.info("Conexión SSH cerrada.")
            except Exception as e:
                log.error(f"Error al cerrar conexión SSH: {e}")
            finally:
                self.is_connected = False
                self._client = paramiko.SSHClient()  # Reset
                self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                KaliSSH._client = None

    def ejecutar(self, comando, timeout=None):
        self.connect()
        try:
            log.debug(f"Ejecutando comando SSH: {comando}")
            stdin, stdout, stderr = self._client.exec_command(comando, timeout=timeout)
            return stdin, stdout, stderr
        except Exception as e:
            log.error(f"Error ejecutando comando SSH: {e}")
            self.is_connected = False  # Reset flag in case of connection drop
            raise e

    def ejecutar_y_leer(self, comando, timeout=None):
        _, stdout, stderr = self.ejecutar(comando, timeout=timeout)
        salida = stdout.read().decode('utf-8', errors='ignore')
        errores = stderr.read().decode('utf-8', errors='ignore')
        return salida, errores

    def upload_text(self, text, path_remoto):
        self.connect()
        try:
            sftp = self._client.open_sftp()
            with sftp.file(path_remoto, 'w') as file:
                file.write(text)
            sftp.close()
            log.debug(f"Contenido subido exitosamente a Kali: {path_remoto}")
        except Exception as e:
            log.error(f"Error subiendo texto a Kali: {e}")
            raise e

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Mantener la conexión abierta para reutilización tipo Singleton
        pass
