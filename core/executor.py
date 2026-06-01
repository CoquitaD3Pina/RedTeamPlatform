import time
from core.ssh_manager import KaliSSH
from d4y_utils.logger import log
import config

def ejecutar_con_polling(comando, path_salida, marcadores_exito=None, timeout=None, intervalo_polling=5):
    """
    Ejecuta un comando en segundo plano en Kali, redireccionando su output a un archivo.
    Realiza polling sobre ese archivo buscando marcadores de éxito o fin para retornar antes de tiempo.
    """
    if timeout is None:
        timeout = config.EXPLOIT_TIMEOUT

    ssh = KaliSSH()
    
    # Inicializar/limpiar archivo de salida en Kali
    ssh.ejecutar_y_leer(f"echo '' > {path_salida}")
    
    log.info(f"Ejecutando en Kali: {comando.split('>') [0].strip()}")
    ssh.ejecutar(comando)
    
    # Espera corta inicial
    time.sleep(2)
    
    tiempo_inicio = time.time()
    while time.time() - tiempo_inicio < timeout:
        # Leer contenido actual del archivo
        salida, _ = ssh.ejecutar_y_leer(f"cat {path_salida}")
        salida = salida.strip()
        
        # Evaluar marcadores de éxito
        if marcadores_exito:
            for marcador in marcadores_exito:
                if marcador.lower() in salida.lower():
                    log.info(f"🎯 Marcador de éxito detectado: '{marcador}' en {int(time.time() - tiempo_inicio)} segundos!")
                    return salida
        
        # Evaluar marcadores de finalización sin éxito
        if "exploit completed, but no session was created" in salida.lower() or \
           "exploit failed" in salida.lower() or \
           "failed to connect" in salida.lower() or \
           "authentication failed" in salida.lower():
            log.warning(f"⚠️ El proceso terminó con falla/fin de ejecución en {int(time.time() - tiempo_inicio)} segundos.")
            return salida
            
        time.sleep(intervalo_polling)
        
    log.warning(f"⏰ Se alcanzó el timeout de {timeout} segundos esperando respuesta.")
    salida, _ = ssh.ejecutar_y_leer(f"cat {path_salida}")
    return salida
