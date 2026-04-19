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

Download the project from GitHub Releases if you want the ready-to-use version.

Release downloads are expected to include:

- `Shadow-Connections-Viewer.exe`

Clone the repository if you want the source code:

```bash
git clone https://github.com/YunusOyunda-48/Shadow-Connections-Viewer.git
cd Shadow-Connections-Viewer
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

## Release Direction

- GitHub Releases for downloadable Windows builds
- Releases can ship a ready-to-run `Shadow-Connections-Viewer.exe`
- Local clone support for developers
- CLI kept for lightweight usage

Repository:

`https://github.com/YunusOyunda-48/Shadow-Connections-Viewer.git`

## Roadmap

- Packaged Windows `.exe` release
- Better risk heuristics
- GeoIP / ASN enrichment
- Historical comparison improvements
- Notifications for suspicious new connections

## Ethics

Use this tool only on systems you own or are explicitly authorized to inspect.

## Türkçe Kısa Özet

Bu proje, bilgisayarda hangi uygulamanın internete bağlandığını görmeye yarayan yerel bir Windows aracıdır.

- İsteyen GitHub Releases üzerinden indirip kullanabilir
- İsteyen şu repo linkiyle clone edebilir:
  `https://github.com/YunusOyunda-48/Shadow-Connections-Viewer.git`
- `npm run gui` ile arayüz açılır
- `node .\src\index.js` ile terminalden çalışır
- Uygulama adı, bağlandığı IP/port ve dikkat çeken nedenleri gösterir
- Sonuçları JSON olarak dışa aktarabilir
