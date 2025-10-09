"""
Centralized logger for PKI entities.

Provides configurable logging with file and console output,
level filtering, and consistent formatting.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


class PKILogger:
    """
    Centralized logger for PKI system with file and console output.
    """

    _loggers = {}

    @staticmethod
    def get_logger(
        name: str,
        log_dir: Optional[str] = None,
        level: int = logging.INFO,
        console_output: bool = True,
    ) -> logging.Logger:
        """
        Ottiene o crea un logger configurato.

        Args:
            name: Nome del logger (es. "RootCA", "EA_001", "AA_TEST")
            log_dir: Directory per i file di log (opzionale)
            level: Livello minimo di log (default: INFO)
            console_output: Se True, stampa anche su console

        Returns:
            Logger configurato pronto all'uso
        """
        # Se esiste già, ritorna il logger cached
        if name in PKILogger._loggers:
            return PKILogger._loggers[name]

        # Crea nuovo logger
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.propagate = False  # Non propagare ai logger parent

        # Rimuovi handler esistenti per evitare duplicati
        logger.handlers.clear()

        # Formato del log: [2025-10-09 14:30:45] [RootCA] [INFO] Messaggio
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )

        # Handler per console (se richiesto)
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        # Handler per file (se directory specificata)
        if log_dir:
            log_path = Path(log_dir)
            log_path.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_path / f"{name}.log", encoding="utf-8")
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        # Salva in cache
        PKILogger._loggers[name] = logger
        return logger

    @staticmethod
    def set_level(name: str, level: int):
        """Changes log level for an existing logger."""
        if name in PKILogger._loggers:
            logger = PKILogger._loggers[name]
            logger.setLevel(level)
            for handler in logger.handlers:
                handler.setLevel(level)

    @staticmethod
    def clear_cache():
        """Clears logger cache."""
        PKILogger._loggers.clear()
