# Changelog - XSS Hunter Pro Framework

## Version 0.2.0 (Aktuell)

### Hinzugefügt
- Vollständige Integrations-Module für Web-Crawler, Fuzzing, Subdomain-Discovery und Vulnerability-Scanner
- Screenshot-Funktionalität mit Unterstützung für Selenium und Playwright
- ML-basierte Payload-Optimierung für verschiedene Kontexte
- Umfassende Schwachstellenkategorisierung mit CVSS-Scoring
- Adapter-Schicht für die Integration externer Tools
- Erweiterte Befehlszeilenparameter für alle Modi
- Detaillierte Dokumentation und Benutzerhandbuch

### Verbessert
- Verbesserte Fehlerbehandlung und Logging
- Optimierte Payload-Generierung für verschiedene Kontexte
- Erweiterte Berichterstellung mit mehreren Formaten
- Verbesserte WAF-Bypass-Techniken

### Behoben
- Fehler bei der Erkennung von DOM-basierten XSS-Schwachstellen
- Probleme mit der Authentifizierung bei geschützten Websites
- Fehler bei der Verarbeitung von Unicode-Zeichen in Payloads
- Speicherprobleme bei großen Scans

## Version 0.1.5

### Hinzugefügt
- Grundlegende Unterstützung für WAF-Bypass-Techniken
- Einfache Screenshot-Funktionalität
- Callback-Server für XSS-Validierung

### Verbessert
- Verbesserte Zielentdeckung
- Optimierte Payload-Verwaltung
- Erweiterte Berichterstellung

### Behoben
- Fehler bei der Verarbeitung von HTTPS-Verbindungen
- Probleme mit der Parallelisierung von Scans
- Fehler bei der Erkennung von Reflected XSS

## Version 0.1.0

### Hinzugefügt
- Grundlegende XSS-Scanning-Funktionalität
- Einfache Payload-Verwaltung
- Grundlegende Berichterstellung
- Kommandozeilenschnittstelle für Scan-Modus

### Bekannte Probleme
- Begrenzte Unterstützung für DOM-basierte XSS
- Keine Unterstützung für WAF-Bypass
- Keine Screenshot-Funktionalität
- Begrenzte Berichterstellung
