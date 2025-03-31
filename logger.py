#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Logger Module
=======================================

Diese Datei implementiert die Logging-Funktionalität für das XSS Hunter Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import logging
import logging.handlers
from typing import Optional

# Globale Variablen
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DEFAULT_LOG_FILE = "xsshunterpro.log"


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None, debug: bool = False) -> logging.Logger:
    """
    Konfiguriert das Logging für das Framework.

    Args:
        log_level: Das Log-Level als String (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Der Pfad zur Log-Datei. Wenn None, wird nur auf die Konsole geloggt.
        debug: Wenn True, wird das Log-Level auf DEBUG gesetzt, unabhängig von log_level.

    Returns:
        Der konfigurierte Logger.
    """
    # Bestimme das Log-Level
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = DEFAULT_LOG_LEVEL
        
    # Wenn debug True ist, setze das Log-Level auf DEBUG
    if debug:
        numeric_level = logging.DEBUG
        
    # Konfiguriere den Root-Logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Entferne alle bestehenden Handler
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    # Erstelle einen Formatter
    formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
    
    # Erstelle einen Console-Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Erstelle einen File-Handler, wenn log_file angegeben ist
    if log_file:
        try:
            # Stelle sicher, dass das Verzeichnis existiert
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
                
            # Erstelle den File-Handler
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            root_logger.error(f"Fehler beim Erstellen des File-Handlers: {e}")
            
    # Erstelle einen Logger für das Framework
    logger = logging.getLogger("XSSHunterPro")
    logger.info(f"Logging initialisiert mit Level: {logging.getLevelName(numeric_level)}")
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Gibt einen Logger mit dem angegebenen Namen zurück.

    Args:
        name: Der Name des Loggers.

    Returns:
        Der Logger.
    """
    return logging.getLogger(f"XSSHunterPro.{name}")


class LoggerAdapter(logging.LoggerAdapter):
    """Ein LoggerAdapter, der zusätzliche Kontextinformationen hinzufügt."""

    def __init__(self, logger: logging.Logger, extra: dict = None):
        """
        Initialisiert den LoggerAdapter.

        Args:
            logger: Der Logger, der angepasst werden soll.
            extra: Zusätzliche Kontextinformationen.
        """
        super().__init__(logger, extra or {})

    def process(self, msg, kwargs):
        """
        Verarbeitet die Log-Nachricht und fügt Kontextinformationen hinzu.

        Args:
            msg: Die Log-Nachricht.
            kwargs: Zusätzliche Argumente für die Log-Methode.

        Returns:
            Das Tupel (msg, kwargs) mit den verarbeiteten Werten.
        """
        # Füge Kontextinformationen zur Nachricht hinzu
        if self.extra:
            context_str = " ".join([f"{k}={v}" for k, v in self.extra.items()])
            msg = f"{msg} [{context_str}]"
            
        return msg, kwargs


def create_module_logger(module_name: str, extra: dict = None) -> LoggerAdapter:
    """
    Erstellt einen LoggerAdapter für ein Modul.

    Args:
        module_name: Der Name des Moduls.
        extra: Zusätzliche Kontextinformationen.

    Returns:
        Der LoggerAdapter.
    """
    logger = get_logger(module_name)
    return LoggerAdapter(logger, extra)


def set_log_level(level: str) -> None:
    """
    Setzt das Log-Level für alle Logger.

    Args:
        level: Das Log-Level als String (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = DEFAULT_LOG_LEVEL
        
    # Setze das Log-Level für den Root-Logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Setze das Log-Level für alle Handler
    for handler in root_logger.handlers:
        handler.setLevel(numeric_level)
        
    logging.getLogger("XSSHunterPro").info(f"Log-Level geändert auf: {logging.getLevelName(numeric_level)}")


def enable_debug_logging() -> None:
    """Aktiviert das Debug-Logging für alle Logger."""
    set_log_level("DEBUG")


def disable_debug_logging() -> None:
    """Deaktiviert das Debug-Logging für alle Logger."""
    set_log_level("INFO")


# Initialisiere das Logging mit Standardwerten, wenn dieses Modul direkt ausgeführt wird
if __name__ == "__main__":
    logger = setup_logging(log_level="DEBUG", log_file=DEFAULT_LOG_FILE)
    logger.debug("Debug-Nachricht")
    logger.info("Info-Nachricht")
    logger.warning("Warning-Nachricht")
    logger.error("Error-Nachricht")
    logger.critical("Critical-Nachricht")
    
    # Teste den LoggerAdapter
    module_logger = create_module_logger("TestModule", {"session_id": "123456"})
    module_logger.info("Test-Nachricht mit Kontext")
