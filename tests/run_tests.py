#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Test Runner
=============================================

Dieses Modul führt alle Tests für das XSS Hunter Framework aus.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

import os
import sys
import unittest
import argparse
import logging

# Konfiguration für Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("XSSHunterPro.TestRunner")

# Füge das Hauptverzeichnis zum Pfad hinzu
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

def run_unit_tests():
    """
    Führt alle Unit-Tests aus.
    """
    logger.info("Führe Unit-Tests aus...")
    
    try:
        from tests import unit_tests
        return unit_tests.run_tests()
    except ImportError as e:
        logger.error(f"Fehler beim Importieren der Unit-Tests: {e}")
        return 1

def run_integration_tests():
    """
    Führt alle Integrationstests aus.
    """
    logger.info("Führe Integrationstests aus...")
    
    try:
        from tests import integration_test
        return integration_test.run_tests()
    except ImportError as e:
        logger.error(f"Fehler beim Importieren der Integrationstests: {e}")
        return 1

def run_all_tests():
    """
    Führt alle Tests aus.
    """
    logger.info("Führe alle Tests aus...")
    
    # Führe Unit-Tests aus
    unit_result = run_unit_tests()
    
    # Führe Integrationstests aus
    integration_result = run_integration_tests()
    
    # Gib den Exit-Code zurück
    return 0 if unit_result == 0 and integration_result == 0 else 1

def main():
    """
    Hauptfunktion.
    """
    # Parse die Kommandozeilenargumente
    parser = argparse.ArgumentParser(description="XSS Hunter Pro Framework - Test Runner")
    parser.add_argument("--unit", action="store_true", help="Führe nur Unit-Tests aus")
    parser.add_argument("--integration", action="store_true", help="Führe nur Integrationstests aus")
    parser.add_argument("--all", action="store_true", help="Führe alle Tests aus")
    parser.add_argument("--verbose", "-v", action="store_true", help="Ausführliche Ausgabe")
    
    args = parser.parse_args()
    
    # Setze das Log-Level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Führe die Tests aus
    if args.unit:
        return run_unit_tests()
    elif args.integration:
        return run_integration_tests()
    else:
        return run_all_tests()

if __name__ == "__main__":
    sys.exit(main())
