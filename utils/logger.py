import logging
import sys
import os

class ColoredFormatter(logging.Formatter):
    # Códigos ANSI para colores
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    LIGHT_GREY = "\033[37m"

    # Formato simple
    FORMAT = "[%(asctime)s] %(levelname)s: %(message)s"

    def format(self, record):
        # Mapeo de niveles a colores
        level_color = {
            logging.DEBUG: self.LIGHT_GREY,
            logging.INFO: self.GREEN,
            logging.WARNING: self.YELLOW,
            logging.ERROR: self.RED,
            logging.CRITICAL: self.BOLD + self.RED
        }.get(record.levelno, self.RESET)

        # Aplicar colores al formatear
        log_fmt = f"{level_color}{self.FORMAT}{self.RESET}"
        formatter = logging.Formatter(log_fmt, datefmt="%H:%M:%S")
        return formatter.format(record)

def setup_logger(name="RedTeam"):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        
        # Handler para consola
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(ColoredFormatter())
        logger.addHandler(ch)
        
        # Handler para archivo
        fh = logging.FileHandler("redteam.log", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('[%(asctime)s] %(levelname)s [%(filename)s:%(lineno)d]: %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
        fh.setFormatter(file_formatter)
        logger.addHandler(fh)
        
    return logger

# Instancia global del logger
log = setup_logger()
