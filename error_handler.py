#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Error Handler
=============================================

Dieses Modul stellt Funktionen zur Fehlerbehandlung bereit.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import logging
import traceback
import json
import time
from typing import Dict, Any, Optional, Callable, List, Tuple, Union

# Konfiguriere Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("XSSHunterPro.ErrorHandler")

# Fehlertypen
ERROR_TYPES = {
    "DEPENDENCY_ERROR": "Fehler bei Abhängigkeiten",
    "NETWORK_ERROR": "Netzwerkfehler",
    "FILE_ERROR": "Dateifehler",
    "PERMISSION_ERROR": "Berechtigungsfehler",
    "CONFIG_ERROR": "Konfigurationsfehler",
    "RUNTIME_ERROR": "Laufzeitfehler",
    "VALIDATION_ERROR": "Validierungsfehler",
    "UNKNOWN_ERROR": "Unbekannter Fehler"
}

class ErrorHandler:
    """
    Zentrale Klasse zur Fehlerbehandlung im XSS Hunter Pro Framework.
    
    Diese Klasse bietet Methoden zur Fehlerbehandlung, Protokollierung und Erstellung
    von Fehlerantworten. Sie dient als Wrapper für die verschiedenen Fehlertypen
    und Fehlerbehandlungsfunktionen.
    """
    
    def __init__(self):
        """
        Initialisiert einen ErrorHandler.
        """
        self.logger = logger
    
    def handle_exception(self, func: Callable) -> Callable:
        """
        Dekorator zur Behandlung von Ausnahmen.
        
        Args:
            func: Die zu dekorierende Funktion.
        
        Returns:
            Die dekorierte Funktion.
        """
        return handle_exception(func)
    
    def log_error(self, error: Union[Exception, str], error_type: str = "UNKNOWN_ERROR", 
                 details: Optional[Dict[str, Any]] = None) -> None:
        """
        Protokolliert einen Fehler.
        
        Args:
            error: Die Ausnahme oder Fehlermeldung.
            error_type: Der Fehlertyp.
            details: Zusätzliche Details zum Fehler.
        """
        log_error(error, error_type, details)
    
    def create_error_response(self, error: Union[Exception, str], error_type: str = "UNKNOWN_ERROR", 
                             details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Erstellt eine Fehlerantwort.
        
        Args:
            error: Die Ausnahme oder Fehlermeldung.
            error_type: Der Fehlertyp.
            details: Zusätzliche Details zum Fehler.
        
        Returns:
            Ein Dictionary mit der Fehlerantwort.
        """
        return create_error_response(error, error_type, details)
    
    def create_success_response(self, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Erstellt eine Erfolgsantwort.
        
        Args:
            data: Die Daten für die Antwort.
        
        Returns:
            Ein Dictionary mit der Erfolgsantwort.
        """
        return create_success_response(data)
    
    def check_dependencies(self, required_modules: List[str]) -> Dict[str, bool]:
        """
        Überprüft, ob die erforderlichen Module verfügbar sind.
        
        Args:
            required_modules: Die Liste der erforderlichen Module.
        
        Returns:
            Ein Dictionary mit den Modulnamen als Schlüssel und einem booleschen Wert,
            der angibt, ob das Modul verfügbar ist.
        """
        return check_dependencies(required_modules)
    
    def is_debug_mode(self) -> bool:
        """
        Überprüft, ob der Debug-Modus aktiviert ist.
        
        Returns:
            True, wenn der Debug-Modus aktiviert ist, sonst False.
        """
        return is_debug_mode()

class XSSHunterError(Exception):
    """Basisklasse für alle XSS Hunter Pro Framework-Fehler."""
    
    def __init__(self, message: str, error_type: str = "UNKNOWN_ERROR", details: Optional[Dict[str, Any]] = None):
        """
        Initialisiert einen XSSHunterError.
        
        Args:
            message: Die Fehlermeldung.
            error_type: Der Fehlertyp.
            details: Zusätzliche Details zum Fehler.
        """
        self.message = message
        self.error_type = error_type
        self.details = details or {}
        self.timestamp = time.time()
        
        # Rufe den Konstruktor der Basisklasse auf
        super().__init__(self.message)
    
    def __str__(self) -> str:
        """
        Gibt eine Zeichenkettenrepräsentation des Fehlers zurück.
        
        Returns:
            Die Zeichenkettenrepräsentation des Fehlers.
        """
        error_type_str = ERROR_TYPES.get(self.error_type, "Unbekannter Fehler")
        return f"{error_type_str}: {self.message}"
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Konvertiert den Fehler in ein Dictionary.
        
        Returns:
            Ein Dictionary mit den Fehlerinformationen.
        """
        return {
            "error_type": self.error_type,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp
        }
    
    def log(self, level: int = logging.ERROR) -> None:
        """
        Protokolliert den Fehler.
        
        Args:
            level: Das Log-Level.
        """
        logger.log(level, str(self))
        
        if self.details:
            logger.log(level, f"Details: {json.dumps(self.details, indent=2)}")


class DependencyError(XSSHunterError):
    """Fehler bei Abhängigkeiten."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialisiert einen DependencyError.
        
        Args:
            message: Die Fehlermeldung.
            details: Zusätzliche Details zum Fehler.
        """
        super().__init__(message, "DEPENDENCY_ERROR", details)


class NetworkError(XSSHunterError):
    """Netzwerkfehler."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialisiert einen NetworkError.
        
        Args:
            message: Die Fehlermeldung.
            details: Zusätzliche Details zum Fehler.
        """
        super().__init__(message, "NETWORK_ERROR", details)


class FileError(XSSHunterError):
    """Dateifehler."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialisiert einen FileError.
        
        Args:
            message: Die Fehlermeldung.
            details: Zusätzliche Details zum Fehler.
        """
        super().__init__(message, "FILE_ERROR", details)


class PermissionError(XSSHunterError):
    """Berechtigungsfehler."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialisiert einen PermissionError.
        
        Args:
            message: Die Fehlermeldung.
            details: Zusätzliche Details zum Fehler.
        """
        super().__init__(message, "PERMISSION_ERROR", details)


class ConfigError(XSSHunterError):
    """Konfigurationsfehler."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialisiert einen ConfigError.
        
        Args:
            message: Die Fehlermeldung.
            details: Zusätzliche Details zum Fehler.
        """
        super().__init__(message, "CONFIG_ERROR", details)


class RuntimeError(XSSHunterError):
    """Laufzeitfehler."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialisiert einen RuntimeError.
        
        Args:
            message: Die Fehlermeldung.
            details: Zusätzliche Details zum Fehler.
        """
        super().__init__(message, "RUNTIME_ERROR", details)


class ValidationError(XSSHunterError):
    """Validierungsfehler."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialisiert einen ValidationError.
        
        Args:
            message: Die Fehlermeldung.
            details: Zusätzliche Details zum Fehler.
        """
        super().__init__(message, "VALIDATION_ERROR", details)


def handle_exception(func: Callable) -> Callable:
    """
    Dekorator zur Behandlung von Ausnahmen.
    
    Args:
        func: Die zu dekorierende Funktion.
    
    Returns:
        Die dekorierte Funktion.
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except XSSHunterError as e:
            e.log()
            return {"success": False, "error": str(e), "error_type": e.error_type, "details": e.details}
        except Exception as e:
            error = XSSHunterError(str(e), "UNKNOWN_ERROR", {"traceback": traceback.format_exc()})
            error.log()
            return {"success": False, "error": str(error), "error_type": error.error_type, "details": error.details}
    
    return wrapper


def safe_import(module_name: str) -> Any:
    """
    Importiert ein Modul sicher und gibt None zurück, wenn der Import fehlschlägt.
    
    Args:
        module_name: Der Name des zu importierenden Moduls.
    
    Returns:
        Das importierte Modul oder None, wenn der Import fehlschlägt.
    """
    try:
        # Versuche, den Dependency Wrapper zu verwenden
        try:
            from lib.dependency_wrapper import import_module
            return import_module(module_name)
        except ImportError:
            # Wenn der Dependency Wrapper nicht verfügbar ist, importiere direkt
            return __import__(module_name)
    except Exception as e:
        logger.error(f"Fehler beim Importieren von {module_name}: {e}")
        return None


def check_dependencies(required_modules: List[str]) -> Dict[str, bool]:
    """
    Überprüft, ob die erforderlichen Module verfügbar sind.
    
    Args:
        required_modules: Die Liste der erforderlichen Module.
    
    Returns:
        Ein Dictionary mit den Modulnamen als Schlüssel und einem booleschen Wert,
        der angibt, ob das Modul verfügbar ist.
    """
    result = {}
    
    for module_name in required_modules:
        module = safe_import(module_name)
        result[module_name] = module is not None
    
    return result


def log_error(error: Union[Exception, str], error_type: str = "UNKNOWN_ERROR", details: Optional[Dict[str, Any]] = None) -> None:
    """
    Protokolliert einen Fehler.
    
    Args:
        error: Die Ausnahme oder Fehlermeldung.
        error_type: Der Fehlertyp.
        details: Zusätzliche Details zum Fehler.
    """
    if isinstance(error, Exception):
        message = str(error)
        details = details or {}
        details["traceback"] = traceback.format_exc()
    else:
        message = error
    
    error_obj = XSSHunterError(message, error_type, details)
    error_obj.log()


def create_error_response(error: Union[Exception, str], error_type: str = "UNKNOWN_ERROR", details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Erstellt eine Fehlerantwort.
    
    Args:
        error: Die Ausnahme oder Fehlermeldung.
        error_type: Der Fehlertyp.
        details: Zusätzliche Details zum Fehler.
    
    Returns:
        Ein Dictionary mit der Fehlerantwort.
    """
    if isinstance(error, Exception):
        message = str(error)
        details = details or {}
        details["traceback"] = traceback.format_exc()
    else:
        message = error
    
    error_obj = XSSHunterError(message, error_type, details)
    error_obj.log()
    
    return {
        "success": False,
        "error": message,
        "error_type": error_type,
        "details": details
    }


def create_success_response(data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Erstellt eine Erfolgsantwort.
    
    Args:
        data: Die Daten für die Antwort.
    
    Returns:
        Ein Dictionary mit der Erfolgsantwort.
    """
    response = {"success": True}
    
    if data:
        response.update(data)
    
    return response


def is_debug_mode() -> bool:
    """
    Überprüft, ob der Debug-Modus aktiviert ist.
    
    Returns:
        True, wenn der Debug-Modus aktiviert ist, sonst False.
    """
    # Überprüfe die Umgebungsvariable
    debug_env = os.environ.get("XSSHUNTER_DEBUG", "").lower()
    
    if debug_env in ("1", "true", "yes", "on"):
        return True
    
    # Überprüfe die Konfigurationsdatei
    try:
        if os.path.exists("config.json"):
            with open("config.json", "r") as f:
                config = json.load(f)
            
            return config.get("debug_mode", False)
    except Exception:
        pass
    
    return False


def setup_error_handling() -> None:
    """
    Richtet die globale Fehlerbehandlung ein.
    """
    def global_exception_handler(exctype, value, tb):
        """
        Globaler Ausnahmebehandler.
        
        Args:
            exctype: Der Ausnahmetyp.
            value: Der Ausnahmewert.
            tb: Der Traceback.
        """
        if issubclass(exctype, KeyboardInterrupt):
            # Keyboard-Interrupt (Strg+C) normal behandeln
            sys.__excepthook__(exctype, value, tb)
            return
        
        logger.error("Unbehandelte Ausnahme:")
        logger.error("".join(traceback.format_exception(exctype, value, tb)))
    
    # Setze den globalen Ausnahmebehandler
    sys.excepthook = global_exception_handler


# Initialisiere die Fehlerbehandlung
setup_error_handling()
