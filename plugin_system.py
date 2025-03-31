#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Plugin System
=============================================

Dieses Modul implementiert das Plugin-System für das XSS Hunter Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import logging
import json
import importlib.util
import inspect
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.PluginSystem")


class PluginManager:
    """
    Plugin-Manager für das XSS Hunter Framework.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialisiert den Plugin-Manager.

        Args:
            config: Die Konfiguration.
        """
        # Setze die Standardkonfiguration
        self.config = {
            "plugins_dir": "plugins",
            "enabled_plugins": [],
            "disabled_plugins": []
        }
        
        # Überschreibe die Standardkonfiguration mit der übergebenen Konfiguration
        if config:
            self.config.update(config)
        
        # Initialisiere die Plugins
        self.plugins = {}
        
        # Lade die Plugins
        self._load_plugins()

    def _load_plugins(self) -> None:
        """
        Lädt die Plugins aus dem Plugin-Verzeichnis.
        """
        # Prüfe, ob das Plugin-Verzeichnis existiert
        if not os.path.exists(self.config["plugins_dir"]):
            logger.warning(f"Plugin-Verzeichnis {self.config['plugins_dir']} nicht gefunden")
            return
        
        # Durchsuche das Plugin-Verzeichnis
        for filename in os.listdir(self.config["plugins_dir"]):
            # Prüfe, ob die Datei eine Python-Datei ist
            if not filename.endswith(".py") or filename.startswith("__"):
                continue
            
            # Erstelle den Pfad zur Plugin-Datei
            plugin_path = os.path.join(self.config["plugins_dir"], filename)
            
            # Extrahiere den Plugin-Namen
            plugin_name = os.path.splitext(filename)[0]
            
            # Prüfe, ob das Plugin deaktiviert ist
            if plugin_name in self.config["disabled_plugins"]:
                logger.info(f"Plugin {plugin_name} ist deaktiviert")
                continue
            
            # Prüfe, ob nur bestimmte Plugins aktiviert sind
            if self.config["enabled_plugins"] and plugin_name not in self.config["enabled_plugins"]:
                logger.info(f"Plugin {plugin_name} ist nicht in der Liste der aktivierten Plugins")
                continue
            
            try:
                # Lade das Plugin
                spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Prüfe, ob das Plugin eine Plugin-Klasse enthält
                plugin_class = None
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and hasattr(obj, "plugin_name") and hasattr(obj, "plugin_version"):
                        plugin_class = obj
                        break
                
                if not plugin_class:
                    logger.warning(f"Plugin {plugin_name} enthält keine gültige Plugin-Klasse")
                    continue
                
                # Erstelle eine Instanz der Plugin-Klasse
                plugin = plugin_class()
                
                # Füge das Plugin hinzu
                self.plugins[plugin_name] = plugin
                
                logger.info(f"Plugin {plugin_name} v{plugin.plugin_version} geladen")
                
            except Exception as e:
                logger.error(f"Fehler beim Laden des Plugins {plugin_name}: {e}")

    def get_plugin(self, plugin_name: str) -> Any:
        """
        Gibt ein Plugin zurück.

        Args:
            plugin_name: Der Name des Plugins.

        Returns:
            Das Plugin oder None, wenn das Plugin nicht gefunden wurde.
        """
        return self.plugins.get(plugin_name)

    def get_plugins(self) -> Dict[str, Any]:
        """
        Gibt alle Plugins zurück.

        Returns:
            Die Plugins.
        """
        return self.plugins

    def call_plugin_method(self, plugin_name: str, method_name: str, *args, **kwargs) -> Any:
        """
        Ruft eine Methode eines Plugins auf.

        Args:
            plugin_name: Der Name des Plugins.
            method_name: Der Name der Methode.
            *args: Die Argumente.
            **kwargs: Die Keyword-Argumente.

        Returns:
            Das Ergebnis der Methode oder None, wenn das Plugin oder die Methode nicht gefunden wurde.
        """
        # Hole das Plugin
        plugin = self.get_plugin(plugin_name)
        
        if not plugin:
            logger.warning(f"Plugin {plugin_name} nicht gefunden")
            return None
        
        # Prüfe, ob die Methode existiert
        if not hasattr(plugin, method_name):
            logger.warning(f"Methode {method_name} nicht gefunden in Plugin {plugin_name}")
            return None
        
        try:
            # Rufe die Methode auf
            method = getattr(plugin, method_name)
            return method(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"Fehler beim Aufrufen der Methode {method_name} in Plugin {plugin_name}: {e}")
            return None

    def call_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """
        Ruft einen Hook in allen Plugins auf.

        Args:
            hook_name: Der Name des Hooks.
            *args: Die Argumente.
            **kwargs: Die Keyword-Argumente.

        Returns:
            Die Ergebnisse der Hook-Aufrufe.
        """
        results = []
        
        for plugin_name, plugin in self.plugins.items():
            # Prüfe, ob der Hook existiert
            if hasattr(plugin, hook_name):
                try:
                    # Rufe den Hook auf
                    hook = getattr(plugin, hook_name)
                    result = hook(*args, **kwargs)
                    results.append(result)
                    
                except Exception as e:
                    logger.error(f"Fehler beim Aufrufen des Hooks {hook_name} in Plugin {plugin_name}: {e}")
        
        return results


class Plugin:
    """
    Basis-Klasse für Plugins.
    """

    plugin_name = "base_plugin"
    plugin_version = "0.1.0"
    plugin_description = "Basis-Plugin für das XSS Hunter Framework"
    plugin_author = "Anonymous"

    def __init__(self):
        """
        Initialisiert das Plugin.
        """
        self.logger = logging.getLogger(f"XSSHunterPro.Plugin.{self.plugin_name}")
        self.logger.info(f"Plugin {self.plugin_name} v{self.plugin_version} initialisiert")

    def on_load(self) -> None:
        """
        Wird aufgerufen, wenn das Plugin geladen wird.
        """
        pass

    def on_unload(self) -> None:
        """
        Wird aufgerufen, wenn das Plugin entladen wird.
        """
        pass

    def on_scan_start(self, url: str, config: Dict[str, Any]) -> None:
        """
        Wird aufgerufen, wenn ein Scan gestartet wird.

        Args:
            url: Die URL.
            config: Die Konfiguration.
        """
        pass

    def on_scan_end(self, url: str, results: Dict[str, Any]) -> None:
        """
        Wird aufgerufen, wenn ein Scan beendet wird.

        Args:
            url: Die URL.
            results: Die Ergebnisse.
        """
        pass

    def on_exploit_start(self, url: str, param: str, exploit_type: str) -> None:
        """
        Wird aufgerufen, wenn ein Exploit gestartet wird.

        Args:
            url: Die URL.
            param: Der Parameter.
            exploit_type: Der Exploit-Typ.
        """
        pass

    def on_exploit_end(self, url: str, param: str, exploit_type: str, result: Dict[str, Any]) -> None:
        """
        Wird aufgerufen, wenn ein Exploit beendet wird.

        Args:
            url: Die URL.
            param: Der Parameter.
            exploit_type: Der Exploit-Typ.
            result: Das Ergebnis.
        """
        pass

    def on_payload_generate(self, context: str, exploit_type: str) -> Optional[str]:
        """
        Wird aufgerufen, wenn ein Payload generiert wird.

        Args:
            context: Der Kontext.
            exploit_type: Der Exploit-Typ.

        Returns:
            Der generierte Payload oder None.
        """
        return None

    def on_report_generate(self, report_file: str, report_format: str) -> None:
        """
        Wird aufgerufen, wenn ein Bericht generiert wird.

        Args:
            report_file: Die Berichtsdatei.
            report_format: Das Berichtsformat.
        """
        pass


# Beispiel für die Verwendung
if __name__ == "__main__":
    # Konfiguriere Logging
    logging.basicConfig(level=logging.INFO)
    
    # Erstelle den Plugin-Manager
    manager = PluginManager({
        "plugins_dir": "plugins",
        "enabled_plugins": ["example_plugin"],
        "disabled_plugins": []
    })
    
    # Gib die geladenen Plugins aus
    print(f"Geladene Plugins: {list(manager.get_plugins().keys())}")
    
    # Rufe einen Hook auf
    results = manager.call_hook("on_scan_start", "https://example.com", {})
    print(f"Hook-Ergebnisse: {results}")
    
    # Rufe eine Plugin-Methode auf
    result = manager.call_plugin_method("example_plugin", "custom_method", "arg1", arg2="arg2")
    print(f"Methoden-Ergebnis: {result}")
