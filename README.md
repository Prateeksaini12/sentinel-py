# 🛡️ Sentinel Py

A local, real-time system & security monitoring dashboard. Sentinel Py runs a small Flask server **on your own computer** and gives you a live browser dashboard of your CPU, RAM, disk, network connections, running processes, startup items, firewall status, and a one-click security audit — all with real data pulled directly from your machine, not a simulation.



---

## Features

- 📊 Live CPU / RAM / disk / uptime dashboard with charts
- 🧠 Running process list with one-click "kill process"
- 🌐 Active network connections + listening ports (flags risky ports like RDP, SMB, Telnet)
- 🔥 Firewall status detection (Windows/macOS/Linux)
- 🧩 Startup / persistence scan (Windows registry Run keys)
- 🗂️ Live file-system monitor for `Downloads` and `Documents`
- 🔎 One-click full security audit (processes, persistence, network, hosts file)
- 📄 Exportable PDF security report
- 🚨 Rolling threat/alert feed

## Tech stack

- **Backend:** Python, Flask, `psutil`, `watchdog`, `reportlab`
- **Frontend:** Single-file HTML/CSS/JS dashboard (`dash.html`), Chart.js, Feather Icons

---

## Why this can't be a single hosted link

Sentinel Py reads live data from the machine the Python process is running on (`psutil`, Windows registry, `netsh`/`ufw`, local network sockets) and can terminate local processes. Browsers do not allow websites to read a visitor's CPU/RAM, process list, or firewall state, and for good reason — that would be a massive privacy and security hole. So if this were hosted on a server, everyone visiting the link would see *the server's* stats, and could kill processes *on the server*, not their own.

The correct way to let "anyone use it with a link" is to **distribute the program** so each person downloads and runs it locally, then it opens in their own browser and shows their own machine. That's what the instructions below set up, using GitHub Releases as the free distribution point.

---

## Run from source

**Requirements:** Python 3.10+

```bash
git clone https://github.com/<your-username>/sentinel-py.git
cd sentinel-py
pip install -r requirements.txt
python lol.py
```

This opens `http://127.0.0.1:5001` in your browser automatically.

> Some features (firewall status, registry scan, killing certain processes) need elevated privileges. On Windows, right-click your terminal → **Run as administrator**. On macOS/Linux, run with `sudo python3 lol.py` if you need full results.

---

## Download a ready-to-run version (no Python needed)

Prebuilt executables are attached to each [GitHub Release](../../releases). Download the file for your OS, run it, and your browser will open the dashboard automatically. No installation, no terminal.

- **Windows:** `SentinelPy.exe`
- **macOS/Linux:** build from source (see below) — a signed macOS binary isn't provided since Sentinel Py isn't notarized by Apple; Gatekeeper will block an unsigned one.

> **Antivirus note:** PyInstaller-built `.exe` files are frequently flagged by antivirus/SmartScreen as suspicious purely because of *how* they're packaged (a common false positive for small, unsigned tools) — not because of malicious content. This is expected; the source code above is the ground truth if you want to verify it yourself before running.

---

## Build the executable yourself

```bash
pip install pyinstaller
pyinstaller --onefile --add-data "dash.html;." --name SentinelPy lol.py
```

On macOS/Linux, use a colon instead of a semicolon in `--add-data`:

```bash
pyinstaller --onefile --add-data "dash.html:." --name SentinelPy lol.py
```

The output binary appears in `dist/`.

### Publish it as a free download link (GitHub Releases)

1. Push your code to a GitHub repo (see [What to upload](#what-to-upload-to-github) below).
2. On the repo page, click **Releases → Draft a new release**.
3. Tag it (e.g. `v1.0.0`), add a title/notes, then drag the built `SentinelPy.exe` from `dist/` into the **Attach binaries** box.
4. Publish. The release page URL (`https://github.com/<you>/sentinel-py/releases/latest`) is now your permanent "download link" — free, and GitHub hosts the file for you.

*(Optional, more advanced: set up a GitHub Actions workflow to auto-build the `.exe` on every tagged release, so you never have to build it locally. Ask me if you want that workflow file.)*

---

## What to upload to GitHub

```
sentinel-py/
├── lol.py              # Flask backend (consider renaming to app.py or server.py)
├── dash.html           # Frontend dashboard
├── requirements.txt
├── README.md
├── LICENSE             # e.g. MIT
└── .gitignore
```

**Do not upload:** `dist/`, `build/`, `*.spec`, `__pycache__/`, virtual environment folders, or any generated PDF reports — the included `.gitignore` already excludes these.

---

## Security & privacy notes

- Sentinel Py only binds to `127.0.0.1` (localhost) — it's not reachable from other devices on your network by default.
- It never sends your data anywhere; everything stays on your machine.
- The "kill process" and registry-scanning features are powerful — only run builds you trust (yours, or ones you've reviewed).

## License

MIT — see `LICENSE`.
