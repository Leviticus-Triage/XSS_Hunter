#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Adapter Factory
=========================================

Diese Datei implementiert die Factory für die Adapter-Schicht des XSS Hunter Frameworks.
Sie ermöglicht die einfache Erstellung von Adaptern für verschiedene Tools.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import logging
from typing import Dict, List, Optional, Any, Type

from adapter_layer import ToolAdapter, CommandLineAdapter, PythonAdapter, DockerAdapter

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.AdapterFactory")


class AdapterFactory:
    """Factory-Klasse für die Erstellung von Tool-Adaptern."""

    @staticmethod
    def create_adapter(adapter_type: str, **kwargs) -> Optional[ToolAdapter]:
        """
        Erstellt einen Adapter für ein Tool.
        
        Args:
            adapter_type: Der Typ des Adapters ("command_line", "python", "docker").
            **kwargs: Zusätzliche Parameter für den Adapter.
            
        Returns:
            Ein Adapter für das Tool oder None bei Fehler.
            
        Raises:
            ValueError: Wenn der angegebene Adapter-Typ nicht unterstützt wird.
        """
        try:
            if adapter_type.lower() == "command_line":
                return AdapterFactory._create_command_line_adapter(**kwargs)
            elif adapter_type.lower() == "python":
                return AdapterFactory._create_python_adapter(**kwargs)
            elif adapter_type.lower() == "docker":
                return AdapterFactory._create_docker_adapter(**kwargs)
            else:
                raise ValueError(f"Nicht unterstützter Adapter-Typ: {adapter_type}")
                
        except Exception as e:
            logger.error(f"Fehler bei der Erstellung des Adapters: {e}")
            return None

    @staticmethod
    def _create_command_line_adapter(**kwargs) -> CommandLineAdapter:
        """
        Erstellt einen Kommandozeilenadapter.
        
        Args:
            **kwargs: Parameter für den Adapter.
            
        Returns:
            Ein Kommandozeilenadapter.
            
        Raises:
            ValueError: Wenn erforderliche Parameter fehlen.
        """
        if "tool_name" not in kwargs:
            raise ValueError("Parameter 'tool_name' ist erforderlich")
            
        tool_name = kwargs["tool_name"]
        tool_description = kwargs.get("tool_description", "")
        tool_version = kwargs.get("tool_version", "")
        
        return CommandLineAdapter(tool_name, tool_description, tool_version)

    @staticmethod
    def _create_python_adapter(**kwargs) -> PythonAdapter:
        """
        Erstellt einen Python-Adapter.
        
        Args:
            **kwargs: Parameter für den Adapter.
            
        Returns:
            Ein Python-Adapter.
            
        Raises:
            ValueError: Wenn erforderliche Parameter fehlen.
        """
        if "module_name" not in kwargs:
            raise ValueError("Parameter 'module_name' ist erforderlich")
            
        module_name = kwargs["module_name"]
        tool_description = kwargs.get("tool_description", "")
        tool_version = kwargs.get("tool_version", "")
        
        return PythonAdapter(module_name, tool_description, tool_version)

    @staticmethod
    def _create_docker_adapter(**kwargs) -> DockerAdapter:
        """
        Erstellt einen Docker-Adapter.
        
        Args:
            **kwargs: Parameter für den Adapter.
            
        Returns:
            Ein Docker-Adapter.
            
        Raises:
            ValueError: Wenn erforderliche Parameter fehlen.
        """
        if "image_name" not in kwargs:
            raise ValueError("Parameter 'image_name' ist erforderlich")
            
        image_name = kwargs["image_name"]
        tool_description = kwargs.get("tool_description", "")
        tool_version = kwargs.get("tool_version", "")
        
        return DockerAdapter(image_name, tool_description, tool_version)

    @staticmethod
    def create_tool_adapter(tool_name: str, adapter_config: Dict[str, Any] = None) -> Optional[ToolAdapter]:
        """
        Erstellt einen Adapter für ein bestimmtes Tool basierend auf der Konfiguration.
        
        Args:
            tool_name: Der Name des Tools.
            adapter_config: Die Konfiguration für den Adapter.
            
        Returns:
            Ein Adapter für das Tool oder None bei Fehler.
        """
        if adapter_config is None:
            adapter_config = {}
            
        # Bestimme den Adapter-Typ basierend auf dem Tool-Namen oder der Konfiguration
        adapter_type = adapter_config.get("type", "command_line")
        
        # Erstelle die Parameter für den Adapter
        kwargs = {
            "tool_name": tool_name,
            "tool_description": adapter_config.get("description", ""),
            "tool_version": adapter_config.get("version", "")
        }
        
        # Füge zusätzliche Parameter hinzu, je nach Adapter-Typ
        if adapter_type == "python":
            kwargs["module_name"] = adapter_config.get("module_name", tool_name)
        elif adapter_type == "docker":
            kwargs["image_name"] = adapter_config.get("image_name", tool_name)
            
        # Erstelle den Adapter
        return AdapterFactory.create_adapter(adapter_type, **kwargs)

    @staticmethod
    def create_adapters_from_config(config: Dict[str, Any]) -> Dict[str, ToolAdapter]:
        """
        Erstellt Adapter für mehrere Tools basierend auf einer Konfiguration.
        
        Args:
            config: Die Konfiguration für die Adapter.
            
        Returns:
            Ein Dictionary mit den Tool-Namen als Schlüssel und den Adaptern als Werte.
        """
        adapters = {}
        
        for tool_name, adapter_config in config.items():
            adapter = AdapterFactory.create_tool_adapter(tool_name, adapter_config)
            if adapter:
                adapters[tool_name] = adapter
                
        return adapters


class ToolRegistry:
    """Registry für Tool-Adapter."""

    def __init__(self):
        """Initialisiert die Tool-Registry."""
        self._adapters = {}
        
    def register_adapter(self, name: str, adapter: ToolAdapter) -> None:
        """
        Registriert einen Adapter in der Registry.
        
        Args:
            name: Der Name des Adapters.
            adapter: Der zu registrierende Adapter.
        """
        self._adapters[name] = adapter
        logger.info(f"Adapter '{name}' registriert")
        
    def get_adapter(self, name: str) -> Optional[ToolAdapter]:
        """
        Gibt einen Adapter aus der Registry zurück.
        
        Args:
            name: Der Name des Adapters.
            
        Returns:
            Der Adapter oder None, wenn er nicht gefunden wurde.
        """
        return self._adapters.get(name)
        
    def list_adapters(self) -> List[str]:
        """
        Gibt eine Liste aller registrierten Adapter zurück.
        
        Returns:
            Eine Liste mit den Namen aller registrierten Adapter.
        """
        return list(self._adapters.keys())
        
    def remove_adapter(self, name: str) -> bool:
        """
        Entfernt einen Adapter aus der Registry.
        
        Args:
            name: Der Name des Adapters.
            
        Returns:
            True, wenn der Adapter entfernt wurde, sonst False.
        """
        if name in self._adapters:
            del self._adapters[name]
            logger.info(f"Adapter '{name}' entfernt")
            return True
        return False
        
    def clear(self) -> None:
        """Entfernt alle Adapter aus der Registry."""
        self._adapters.clear()
        logger.info("Alle Adapter entfernt")
        
    def load_from_config(self, config: Dict[str, Any]) -> None:
        """
        Lädt Adapter aus einer Konfiguration.
        
        Args:
            config: Die Konfiguration für die Adapter.
        """
        adapters = AdapterFactory.create_adapters_from_config(config)
        for name, adapter in adapters.items():
            self.register_adapter(name, adapter)
            
    def get_adapter_info(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Gibt Informationen über einen Adapter zurück.
        
        Args:
            name: Der Name des Adapters.
            
        Returns:
            Ein Dictionary mit Informationen über den Adapter oder None, wenn er nicht gefunden wurde.
        """
        adapter = self.get_adapter(name)
        if adapter:
            return adapter.get_info()
        return None
        
    def get_all_adapter_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Gibt Informationen über alle Adapter zurück.
        
        Returns:
            Ein Dictionary mit den Adapter-Namen als Schlüssel und Informationen über die Adapter als Werte.
        """
        return {name: adapter.get_info() for name, adapter in self._adapters.items()}


# Globale Registry-Instanz
registry = ToolRegistry()


def register_adapter(name: str, adapter: ToolAdapter) -> None:
    """
    Registriert einen Adapter in der globalen Registry.
    
    Args:
        name: Der Name des Adapters.
        adapter: Der zu registrierende Adapter.
    """
    registry.register_adapter(name, adapter)
    
def get_adapter(name: str) -> Optional[ToolAdapter]:
    """
    Gibt einen Adapter aus der globalen Registry zurück.
    
    Args:
        name: Der Name des Adapters.
        
    Returns:
        Der Adapter oder None, wenn er nicht gefunden wurde.
    """
    return registry.get_adapter(name)
    
def list_adapters() -> List[str]:
    """
    Gibt eine Liste aller registrierten Adapter zurück.
    
    Returns:
        Eine Liste mit den Namen aller registrierten Adapter.
    """
    return registry.list_adapters()
    
def remove_adapter(name: str) -> bool:
    """
    Entfernt einen Adapter aus der globalen Registry.
    
    Args:
        name: Der Name des Adapters.
        
    Returns:
        True, wenn der Adapter entfernt wurde, sonst False.
    """
    return registry.remove_adapter(name)
    
def clear_registry() -> None:
    """Entfernt alle Adapter aus der globalen Registry."""
    registry.clear()
    
def load_adapters_from_config(config: Dict[str, Any]) -> None:
    """
    Lädt Adapter aus einer Konfiguration in die globale Registry.
    
    Args:
        config: Die Konfiguration für die Adapter.
    """
    registry.load_from_config(config)
    
def get_adapter_info(name: str) -> Optional[Dict[str, Any]]:
    """
    Gibt Informationen über einen Adapter aus der globalen Registry zurück.
    
    Args:
        name: Der Name des Adapters.
        
    Returns:
        Ein Dictionary mit Informationen über den Adapter oder None, wenn er nicht gefunden wurde.
    """
    return registry.get_adapter_info(name)
    
def get_all_adapter_info() -> Dict[str, Dict[str, Any]]:
    """
    Gibt Informationen über alle Adapter in der globalen Registry zurück.
    
    Returns:
        Ein Dictionary mit den Adapter-Namen als Schlüssel und Informationen über die Adapter als Werte.
    """
    return registry.get_all_adapter_info()
