# Shadow Connections Viewer

Security-focused Windows application for seeing which processes are connecting to the network in the background.

It is built around a simple question:

**What is silently connecting out from this machine right now?**

## Overview

`shadow-connections-viewer` collects active TCP connections, matches them with the owning process, and presents them in a simple local interface.

Main capabilities:

- Local Windows GUI
- Process name and PID
- Local / remote address visibility
- Optional hostname lookup
- Lightweight risk labels
- New connection detection based on the previous scan
- JSON export

The goal is practical visibility, not malware verdicts. It is meant to be useful, easy to demo, and clean enough for a serious GitHub profile.

## Quick Start

Clone the repository:

```bash
git clone https://github.com/YunusOyunda-48/Shadow-Connections-Viewer.git
cd Shadow-Connections-Viewer
```

Run the local GUI:

```powershell
npm run gui
```

Run the CLI:

```bash
node .\src\index.js
```

## GUI

The GUI is intentionally simple:

- Search by application name
- Filter by port
- Choose how many rows to show
- Compare with the previous scan
- Export results as JSON

The table focuses on readable fields such as:

- Application
- Where it connects
- Connection status
- Why it stands out

## CLI Examples

```bash
node .\src\index.js --json
node .\src\index.js --process chrome
node .\src\index.js --port 443
node .\src\index.js --resolve
node .\src\index.js --all
```

## Usage Model

- People who want a local interface can run `npm run gui`
- People who want source access can clone the repo
- People who prefer terminal usage can run the CLI directly

Repository:

`https://github.com/YunusOyunda-48/Shadow-Connections-Viewer.git`

## Roadmap

- Better risk heuristics
- GeoIP / ASN enrichment
- Historical comparison improvements
- Notifications for suspicious new connections

## Ethics

Use this tool only on systems you own or are explicitly authorized to inspect.

## Türkçe Kısa Özet

Bu proje, bilgisayarda hangi uygulamanın internete bağlandığını görmeye yarayan yerel bir Windows aracıdır.

- `npm run gui` ile arayüz açılır
- `node .\src\index.js` ile terminalden çalışır
- Repo klonlamak için:
  `https://github.com/YunusOyunda-48/Shadow-Connections-Viewer.git`
- Uygulama adı, bağlandığı IP/port ve dikkat çeken nedenleri gösterir
- Sonuçları JSON olarak dışa aktarabilir
