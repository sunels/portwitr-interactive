<h1 style="background-color:#222; color:#FFD700; padding:10px; border-radius:5px;">
portwitr-interactive
</h1>

🔌 portwitr  <br>
│  <br>
├─► 🌐 Ports  <br>
├─► 🧠 Processes  <br>
└─► 📂 Open Files


**Interactive terminal-based port, process and file inspector for Linux.**

`portwitr-interactive` is a **curses-based TUI** that lets you explore — in real time and interactively:

> **Which port is open → which process owns it → which files that process is using**

All from a single terminal screen.


<p align="center">
  <img src="logo.png" alt="portwitr-interactive logo" width="280"/>
</p>


---

## 🧠 What Makes It Special?

Unlike classic tools that show *only one layer* (`ss`, `netstat`, `lsof`),  
**portwitr-interactive connects everything together**:

🔌 **Port** → 🧠 **Process / Service** → 📂 **All open files**

---

## 📸 Screenshots

### 🔍 Main View — Ports, Processes & Open Files
<img src="pp-1.png" alt="portwitr-interactive main view" width="100%"/>

---

### 🧾 Detail View — Deep Port & Process Inspection
<img src="pp-2.png" alt="portwitr-interactive detail view" width="100%"/>

---

## ✨ Features

- 🔍 **Live port listing** using `ss`
- 🧠 Maps **PORT → PID → PROGRAM**
- 📂 Displays **all open files** of the selected process (`/proc/<pid>/fd`)
- 🧾 Deep inspection via **`witr --port`**
- 🖥️ Fully interactive **terminal UI (curses)**
- ⚡ Real-time refresh
- 🛑 Stop a **process or systemd service** directly from the UI (with confirmation)

---

## 🎮 Key Bindings

### 🖥️ Main View

| Key | Action |
|----|-------|
| ↑ / ↓ | Move selection |
| + / - | Resize table height |
| → / ← | Scroll open files |
| r | Refresh port list |
| Tab | Switch to detail view |
| s | Stop selected process / service |
| q | Quit |

---

### 📜 Detail View

| Key | Action |
|----|-------|
| ↑ / ↓ | Scroll |
| Tab | Back to main view |
| q | Quit |

---

## 🧠 How It Works

1. **Port discovery**
    - `ss -lntuHp`
2. **Process resolution**
    - Extracts PID & program name from socket metadata
3. **Open file inspection**
    - Reads `/proc/<pid>/fd`
4. **Deep context**
    - Calls `witr --port <port>`
5. **Control**
    - Optional process / service stop via `systemctl` or `kill`

---

## 🧪 Requirements

- 🐧 **Linux only**
- 🐍 Python **3.6+**
- Required system tools:
    - `ss` (iproute2)
    - `systemctl`
    - `/proc` filesystem
    - `witr` (**mandatory**)
- 🔐 `sudo` access required for:
    - `witr`
    - stopping processes/services
    - full `/proc` visibility

---

## 🚀 Installation

> **bash
git clone https://github.com/sunels/portwitr-interactive.git
cd portwitr-interactive**


---

## Ensure `witr` exists:

```bash
which witr
```
---

 # 🔌 Run:

```bash
python3 portwitr_interactive.py
```

---

## ⚠️ Safety Notes

- 🛑 Destructive actions always require confirmation
- 🧠 PID `1` (systemd) is protected
- 👀 Non-root usage limits visibility (expected behavior)

---

## 🧩 Design Philosophy

- ❌ No reinvention of system tools
- ✅ Built on **native Linux introspection**
- 🔍 Read-only by default
- 🎯 Optimized for:
    - “Port already in use” debugging
    - Security inspection
    - DevOps / SRE diagnostics
    - Understanding legacy systems

---

## 📁 Project Structure

```
portwitr-interactive/
├── portwitr_interactive.py
├── README.md
├── pp-1.png
└── pp-2.png
```

---

## 🛣️ Roadmap (Ideas)

- 🔎 Port search & filters
- 📤 JSON export
- 🧪 Parser unit tests
- 🍎 Partial macOS support
- 🔌 Plugin system

---

## 📄 License

MIT License

---

## 👤 Author

**Serkan Sunel**

---

> 🔌 **portwitr-interactive**  
> *See the whole picture — not just the port.*


