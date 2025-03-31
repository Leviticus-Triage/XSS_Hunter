#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Adapter Layer
=======================================

Diese Datei implementiert die Adapter-Schicht für das XSS Hunter Framework.
Sie bietet eine einheitliche Schnittstelle für die Integration externer Tools.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import logging
import subprocess
import shutil
import tempfile
from typing import Dict, List, Optional, Any, Tuple, Union

# Konfiguration für Logging
logger = logging.getLogger("XSSHunterPro.AdapterLayer")


class ToolAdapter:
    """Basisklasse für Tool-Adapter."""

    def __init__(self):
        """Initialisiert den Tool-Adapter."""
        self._tool_name = ""
        self._tool_description = ""
        self._tool_version = ""
        self._required_dependencies = []
        self._fallback_mode = False
        self._executable_path = None
        
        # Suche nach dem ausführbaren Programm
        self._executable_path = self._find_executable()
        
        # Wenn das Tool nicht gefunden wurde, versuche es zu installieren
        if not self._executable_path:
            logger.info(f"Tool {self._tool_name} nicht gefunden, versuche zu installieren...")
            if self._install_tool():
                self._executable_path = self._find_executable()
                if self._executable_path:
                    logger.info(f"Tool {self._tool_name} erfolgreich installiert: {self._executable_path}")
                else:
                    logger.warning(f"Tool {self._tool_name} konnte nicht gefunden werden nach der Installation")
                    self._fallback_mode = True
            else:
                logger.warning(f"Tool {self._tool_name} konnte nicht installiert werden, verwende Fallback-Modus")
                self._fallback_mode = True
        else:
            logger.info(f"Tool {self._tool_name} gefunden: {self._executable_path}")

    @property
    def executable_path(self) -> Optional[str]:
        """
        Gibt den Pfad zum ausführbaren Programm zurück.
        
        Returns:
            Der Pfad zum ausführbaren Programm oder None, wenn es nicht gefunden wurde.
        """
        return self._executable_path

    @property
    def fallback_mode(self) -> bool:
        """
        Gibt zurück, ob der Adapter im Fallback-Modus läuft.
        
        Returns:
            True, wenn der Adapter im Fallback-Modus läuft, sonst False.
        """
        return self._fallback_mode

    def _get_tool_name(self) -> str:
        """
        Gibt den Namen des Tools zurück.
        
        Returns:
            Der Name des Tools.
        """
        return self._tool_name

    def _find_executable(self) -> Optional[str]:
        """
        Sucht nach dem ausführbaren Programm des Tools im System.
        
        Returns:
            Der Pfad zum ausführbaren Programm oder None, wenn es nicht gefunden wurde.
        """
        if not self._tool_name:
            return None
            
        # Prüfe, ob das Tool im PATH ist
        executable = shutil.which(self._tool_name)
        if executable:
            return executable
            
        # Prüfe gängige Verzeichnisse
        common_dirs = [
            os.path.expanduser("~/.local/bin"),
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/opt/local/bin",
            "/opt/bin",
            os.path.expanduser("~/go/bin"),
            os.path.expanduser("~/.cargo/bin")
        ]
        
        for directory in common_dirs:
            path = os.path.join(directory, self._tool_name)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
                
        return None

    def _install_tool(self) -> bool:
        """
        Installiert das Tool.
        
        Returns:
            True, wenn die Installation erfolgreich war, sonst False.
        """
        # Diese Methode sollte von abgeleiteten Klassen überschrieben werden
        logger.warning(f"Installation von {self._tool_name} nicht implementiert")
        return False

    def execute_command(self, command: List[str], timeout: int = 300) -> Tuple[int, str, str]:
        """
        Führt einen Befehl aus und gibt das Ergebnis zurück.
        
        Args:
            command: Der auszuführende Befehl als Liste.
            timeout: Timeout in Sekunden.
            
        Returns:
            Ein Tupel aus Rückgabecode, Standardausgabe und Standardfehlerausgabe.
        """
        try:
            logger.debug(f"Führe Befehl aus: {' '.join(command)}")
            
            # Führe den Befehl aus
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Warte auf das Ende des Prozesses mit Timeout
            stdout, stderr = process.communicate(timeout=timeout)
            returncode = process.returncode
            
            # Protokolliere das Ergebnis
            if returncode == 0:
                logger.debug(f"Befehl erfolgreich ausgeführt: {' '.join(command)}")
            else:
                logger.warning(f"Befehl fehlgeschlagen: {' '.join(command)}, Rückgabecode: {returncode}")
                logger.debug(f"Fehlerausgabe: {stderr}")
            
            return returncode, stdout, stderr
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout bei der Ausführung von: {' '.join(command)}")
            process.kill()
            stdout, stderr = process.communicate()
            return -1, stdout, stderr
            
        except Exception as e:
            logger.error(f"Fehler bei der Ausführung von {' '.join(command)}: {e}")
            return -1, "", str(e)

    def check_dependencies(self) -> Dict[str, bool]:
        """
        Prüft, ob alle erforderlichen Abhängigkeiten installiert sind.
        
        Returns:
            Ein Dictionary mit den Namen der Abhängigkeiten als Schlüssel und
            einem booleschen Wert, der angibt, ob die Abhängigkeit installiert ist.
        """
        dependencies = {}
        
        for dependency in self._required_dependencies:
            # Prüfe, ob die Abhängigkeit im PATH ist
            if shutil.which(dependency):
                dependencies[dependency] = True
            else:
                dependencies[dependency] = False
                
        return dependencies

    def get_version(self) -> Optional[str]:
        """
        Gibt die Version des Tools zurück.
        
        Returns:
            Die Version des Tools oder None, wenn sie nicht ermittelt werden konnte.
        """
        if not self._executable_path:
            return None
            
        try:
            # Versuche, die Version mit --version zu ermitteln
            returncode, stdout, stderr = self.execute_command([self._executable_path, "--version"])
            if returncode == 0:
                return stdout.strip()
                
            # Versuche, die Version mit -v zu ermitteln
            returncode, stdout, stderr = self.execute_command([self._executable_path, "-v"])
            if returncode == 0:
                return stdout.strip()
                
            # Versuche, die Version mit -version zu ermitteln
            returncode, stdout, stderr = self.execute_command([self._executable_path, "-version"])
            if returncode == 0:
                return stdout.strip()
                
            return None
            
        except Exception as e:
            logger.error(f"Fehler bei der Ermittlung der Version von {self._tool_name}: {e}")
            return None

    def get_info(self) -> Dict[str, Any]:
        """
        Gibt Informationen über das Tool zurück.
        
        Returns:
            Ein Dictionary mit Informationen über das Tool.
        """
        return {
            "name": self._tool_name,
            "description": self._tool_description,
            "version": self._tool_version,
            "executable_path": self._executable_path,
            "fallback_mode": self._fallback_mode,
            "required_dependencies": self._required_dependencies,
            "installed_version": self.get_version()
        }


class CommandLineAdapter(ToolAdapter):
    """Adapter für Kommandozeilentools."""

    def __init__(self, tool_name: str, tool_description: str = "", tool_version: str = ""):
        """
        Initialisiert den Kommandozeilenadapter.
        
        Args:
            tool_name: Der Name des Tools.
            tool_description: Die Beschreibung des Tools.
            tool_version: Die Version des Tools.
        """
        self._tool_name = tool_name
        self._tool_description = tool_description
        self._tool_version = tool_version
        super().__init__()

    def run_command(self, args: List[str], timeout: int = 300) -> Dict[str, Any]:
        """
        Führt einen Befehl mit dem Tool aus.
        
        Args:
            args: Die Argumente für den Befehl.
            timeout: Timeout in Sekunden.
            
        Returns:
            Ein Dictionary mit dem Ergebnis des Befehls.
        """
        if not self._executable_path:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Tool {self._tool_name} nicht gefunden",
                "returncode": -1,
                "command": f"{self._tool_name} {' '.join(args)}"
            }
            
        # Erstelle den Befehl
        command = [self._executable_path] + args
        
        # Führe den Befehl aus
        returncode, stdout, stderr = self.execute_command(command, timeout=timeout)
        
        # Erstelle das Ergebnis
        result = {
            "success": returncode == 0,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "command": " ".join(command)
        }
        
        return result


class PythonAdapter(ToolAdapter):
    """Adapter für Python-Tools."""

    def __init__(self, module_name: str, tool_description: str = "", tool_version: str = ""):
        """
        Initialisiert den Python-Adapter.
        
        Args:
            module_name: Der Name des Python-Moduls.
            tool_description: Die Beschreibung des Tools.
            tool_version: Die Version des Tools.
        """
        self._tool_name = "python3"
        self._module_name = module_name
        self._tool_description = tool_description
        self._tool_version = tool_version
        self._required_dependencies = ["python3", "pip3"]
        super().__init__()
        
        # Prüfe, ob das Modul installiert ist
        self._module_installed = self._check_module_installed()
        
        # Wenn das Modul nicht installiert ist, versuche es zu installieren
        if not self._module_installed:
            logger.info(f"Python-Modul {module_name} nicht gefunden, versuche zu installieren...")
            if self._install_module():
                self._module_installed = self._check_module_installed()
                if self._module_installed:
                    logger.info(f"Python-Modul {module_name} erfolgreich installiert")
                else:
                    logger.warning(f"Python-Modul {module_name} konnte nicht gefunden werden nach der Installation")
                    self._fallback_mode = True
            else:
                logger.warning(f"Python-Modul {module_name} konnte nicht installiert werden, verwende Fallback-Modus")
                self._fallback_mode = True
        else:
            logger.info(f"Python-Modul {module_name} gefunden")

    def _check_module_installed(self) -> bool:
        """
        Prüft, ob das Python-Modul installiert ist.
        
        Returns:
            True, wenn das Modul installiert ist, sonst False.
        """
        try:
            # Versuche, das Modul zu importieren
            returncode, stdout, stderr = self.execute_command(
                ["python3", "-c", f"import {self._module_name}; print('Module found')"]
            )
            return returncode == 0 and "Module found" in stdout
            
        except Exception as e:
            logger.error(f"Fehler beim Prüfen des Python-Moduls {self._module_name}: {e}")
            return False

    def _install_module(self) -> bool:
        """
        Installiert das Python-Modul.
        
        Returns:
            True, wenn die Installation erfolgreich war, sonst False.
        """
        try:
            # Installiere das Modul mit pip
            returncode, stdout, stderr = self.execute_command(
                ["pip3", "install", self._module_name]
            )
            return returncode == 0
            
        except Exception as e:
            logger.error(f"Fehler bei der Installation des Python-Moduls {self._module_name}: {e}")
            return False

    def run_script(self, script: str, args: List[str] = None, timeout: int = 300) -> Dict[str, Any]:
        """
        Führt ein Python-Skript aus.
        
        Args:
            script: Der Python-Code, der ausgeführt werden soll.
            args: Die Argumente für das Skript.
            timeout: Timeout in Sekunden.
            
        Returns:
            Ein Dictionary mit dem Ergebnis des Skripts.
        """
        if not self._executable_path:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Python nicht gefunden",
                "returncode": -1,
                "command": "python3 -c ..."
            }
            
        if not self._module_installed and not self._fallback_mode:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Python-Modul {self._module_name} nicht installiert",
                "returncode": -1,
                "command": "python3 -c ..."
            }
            
        # Erstelle eine temporäre Datei für das Skript
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as temp_file:
            temp_file.write(script.encode())
            temp_file_path = temp_file.name
            
        try:
            # Erstelle den Befehl
            command = [self._executable_path, temp_file_path]
            if args:
                command.extend(args)
                
            # Führe den Befehl aus
            returncode, stdout, stderr = self.execute_command(command, timeout=timeout)
            
            # Erstelle das Ergebnis
            result = {
                "success": returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "returncode": returncode,
                "command": f"python3 {temp_file_path} {' '.join(args) if args else ''}"
            }
            
            return result
            
        finally:
            # Lösche die temporäre Datei
            try:
                os.unlink(temp_file_path)
            except:
                pass

    def run_module(self, module_function: str, args: List[str] = None, timeout: int = 300) -> Dict[str, Any]:
        """
        Führt eine Funktion eines Python-Moduls aus.
        
        Args:
            module_function: Die Funktion des Moduls, die ausgeführt werden soll.
            args: Die Argumente für die Funktion.
            timeout: Timeout in Sekunden.
            
        Returns:
            Ein Dictionary mit dem Ergebnis der Funktion.
        """
        if not self._executable_path:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Python nicht gefunden",
                "returncode": -1,
                "command": "python3 -c ..."
            }
            
        if not self._module_installed and not self._fallback_mode:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Python-Modul {self._module_name} nicht installiert",
                "returncode": -1,
                "command": "python3 -c ..."
            }
            
        # Erstelle das Skript
        script = f"import {self._module_name}; {self._module_name}.{module_function}({', '.join(args) if args else ''})"
        
        # Erstelle den Befehl
        command = [self._executable_path, "-c", script]
        
        # Führe den Befehl aus
        returncode, stdout, stderr = self.execute_command(command, timeout=timeout)
        
        # Erstelle das Ergebnis
        result = {
            "success": returncode == 0,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "command": f"python3 -c '{script}'"
        }
        
        return result


class DockerAdapter(ToolAdapter):
    """Adapter für Docker-Container."""

    def __init__(self, image_name: str, tool_description: str = "", tool_version: str = ""):
        """
        Initialisiert den Docker-Adapter.
        
        Args:
            image_name: Der Name des Docker-Images.
            tool_description: Die Beschreibung des Tools.
            tool_version: Die Version des Tools.
        """
        self._tool_name = "docker"
        self._image_name = image_name
        self._tool_description = tool_description
        self._tool_version = tool_version
        self._required_dependencies = ["docker"]
        super().__init__()
        
        # Prüfe, ob das Image vorhanden ist
        self._image_available = self._check_image_available()
        
        # Wenn das Image nicht vorhanden ist, versuche es zu pullen
        if not self._image_available:
            logger.info(f"Docker-Image {image_name} nicht gefunden, versuche zu pullen...")
            if self._pull_image():
                self._image_available = self._check_image_available()
                if self._image_available:
                    logger.info(f"Docker-Image {image_name} erfolgreich gepullt")
                else:
                    logger.warning(f"Docker-Image {image_name} konnte nicht gefunden werden nach dem Pull")
                    self._fallback_mode = True
            else:
                logger.warning(f"Docker-Image {image_name} konnte nicht gepullt werden, verwende Fallback-Modus")
                self._fallback_mode = True
        else:
            logger.info(f"Docker-Image {image_name} gefunden")

    def _check_image_available(self) -> bool:
        """
        Prüft, ob das Docker-Image vorhanden ist.
        
        Returns:
            True, wenn das Image vorhanden ist, sonst False.
        """
        try:
            # Prüfe, ob das Image vorhanden ist
            returncode, stdout, stderr = self.execute_command(
                ["docker", "image", "inspect", self._image_name]
            )
            return returncode == 0
            
        except Exception as e:
            logger.error(f"Fehler beim Prüfen des Docker-Images {self._image_name}: {e}")
            return False

    def _pull_image(self) -> bool:
        """
        Pullt das Docker-Image.
        
        Returns:
            True, wenn das Pull erfolgreich war, sonst False.
        """
        try:
            # Pulle das Image
            returncode, stdout, stderr = self.execute_command(
                ["docker", "pull", self._image_name]
            )
            return returncode == 0
            
        except Exception as e:
            logger.error(f"Fehler beim Pullen des Docker-Images {self._image_name}: {e}")
            return False

    def run_container(self, command: List[str] = None, volumes: Dict[str, str] = None, 
                     environment: Dict[str, str] = None, network: str = "host", 
                     timeout: int = 300) -> Dict[str, Any]:
        """
        Führt einen Docker-Container aus.
        
        Args:
            command: Der Befehl, der im Container ausgeführt werden soll.
            volumes: Die Volumes, die in den Container gemountet werden sollen.
            environment: Die Umgebungsvariablen für den Container.
            network: Das Netzwerk für den Container.
            timeout: Timeout in Sekunden.
            
        Returns:
            Ein Dictionary mit dem Ergebnis des Containers.
        """
        if not self._executable_path:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Docker nicht gefunden",
                "returncode": -1,
                "command": "docker run ..."
            }
            
        if not self._image_available and not self._fallback_mode:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Docker-Image {self._image_name} nicht verfügbar",
                "returncode": -1,
                "command": "docker run ..."
            }
            
        # Erstelle den Befehl
        docker_command = ["docker", "run", "--rm"]
        
        # Füge Volumes hinzu
        if volumes:
            for host_path, container_path in volumes.items():
                docker_command.extend(["-v", f"{host_path}:{container_path}"])
                
        # Füge Umgebungsvariablen hinzu
        if environment:
            for key, value in environment.items():
                docker_command.extend(["-e", f"{key}={value}"])
                
        # Füge Netzwerk hinzu
        docker_command.extend(["--network", network])
        
        # Füge Image hinzu
        docker_command.append(self._image_name)
        
        # Füge Befehl hinzu
        if command:
            docker_command.extend(command)
            
        # Führe den Befehl aus
        returncode, stdout, stderr = self.execute_command(docker_command, timeout=timeout)
        
        # Erstelle das Ergebnis
        result = {
            "success": returncode == 0,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "command": " ".join(docker_command)
        }
        
        return result
