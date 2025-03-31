#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Hunter Pro Framework - Integrations Package
===============================================

Dieses Paket enthält Integrationen für verschiedene externe Tools,
die für Bug Bounty und XSS-Hunting nützlich sind.

Autor: Anonymous
Lizenz: MIT
Version: 0.2.0
"""

from .base import ToolIntegration
from .webcrawler import GospiderIntegration, HakrawlerIntegration, WebCrawlerFactory
from .fuzzing import FFuFIntegration, WfuzzIntegration, FuzzingToolFactory
from .subdomain_discovery import SubfinderIntegration, AmassIntegration, SubdomainDiscoveryFactory
from .vulnerability_scanner import NucleiIntegration, XSStrikeIntegration, DalfoxIntegration, VulnerabilityScannerFactory
