# Palo Alto Networks (PAN-OS) Firewall Topology & Change Viewer

[![PAN-OS](https://img.shields.io/badge/PAN--OS-11.1-orange?style=flat-square&logo=paloaltonetworks)](https://www.paloaltonetworks.com/)
[![Device](https://img.shields.io/badge/Hardware-PA--3410-blue?style=flat-square)](https://www.paloaltonetworks.com/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20Vite%20%2B%20Tailwind-61DAFB?style=flat-square&logo=react)](https://reactjs.org/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python)](https://python.org/)

An interactive **Next-Generation Firewall (NGFW) Topology Viewer, Commit Diff Tracker, Layer-7 App-ID Policy Simulator, and AI Assistant** built specifically for **Palo Alto Networks Strata / PAN-OS 11.1**.

---

## 📸 Key Features

1. **Native PAN-OS CLI Config Parser**:
   * Parses authentic running configs in `set` command format (`set cli config-output-format set ; show config running`).
   * Models **Layer 3 Physical Interfaces** (`ethernet1/1` to `ethernet1/8`), **Security Zones** (`Untrust`, `DMZ`, `Trust-Internal`, `PCI-Cardholder`, `Management`), **Virtual Routers** (`default` FIB/RIB), **Address Objects**, and **Operational ARP Tables**.

2. **Commit Time-Travel & Visual Revision Diff (CR-4910)**:
   * Compares configuration revisions (e.g., Baseline V1 vs. Candidate Commit V2).
   * Visualizes added components in **glowing green** (`+ Added`) and decommissioned infrastructure in **red dashed outline** (`✖ Decommissioned`).
   * Summarizes security rule additions (e.g. allowing App-ID `ssl` into the new PCI zone) and rule revocations.

3. **Layer-7 App-ID Reachability Simulator**:
   * Simulates full packet traversal across Security Zones and Virtual Router routing tables.
   * Evaluates top-down security policy rulebases with native support for Palo Alto Networks **App-ID** (`ssl`, `web-browsing`, `postgresql`, `ssh`, `pan-db-cloud`, etc.).
   * Enforces PAN-OS built-in defaults: **Intra-zone Traffic $\rightarrow$ Allowed**, **Inter-zone Traffic $\rightarrow$ Denied/Dropped**.

4. **32-Field CSV Syslog Telemetry Stream**:
   * Real-time ingestion and filtering of authentic PAN-OS CSV traffic and threat logs.
   * Filter sessions by action (`ALLOW`, `DROP`), application (`ssl`, `postgresql`, `ssh`), or destination port.

5. **Site-to-Site IPsec VPN Tunnels & IKE Gateways**:
   * Models authentic PAN-OS tunnel interfaces (`tunnel.1`, `tunnel.2`), IKE Gateways (`GW-AWS-VPC-East`, `GW-Branch-Chicago`), and Suite-B encryption profiles (`AES-256-GCM`).
   * Evaluates FIB static-route lookups through tunnel interfaces into `VPN-SiteToSite` security zone.

6. **Instant Node Search & Interactive Blast Radius Isolation**:
   * Real-time search filter directly on the canvas to find nodes by IP, Zone, Subnet, or Hostname.
   * **Blast Radius Mode**: Select any firewall node or workload to instantly isolate 1-hop and 2-hop connected network dependencies, automatically dimming unrelated elements and pulsing connected links.
   * **Zero-Trust Exposure Profiler**: Computes attack surface risk (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), permitted inbound ingress zones, outbound egress targets, and authorized App-IDs.

7. **Structured 5-Tier Security Hierarchy**:
   * **Left-to-Right Security Progression**: Organizes network architecture into 5 distinct, intuitive security tiers:
     * **Tier 1: External / WAN Ingress** (Internet ISP Gateway, AWS Cloud IPsec VPN, Chicago Branch IPsec VPN)
     * **Tier 2: NGFW Enforcement Core & VR** (PA-3410 Firewall Appliance & Virtual Router `default` FIB engine)
     * **Tier 3: Demilitarized Zone (DMZ)** (Public web workloads and ingress application proxies)
     * **Tier 4: Enterprise Trust & PCI Zones** (Corporate app servers, production DBs, and isolated PCI DSS payment gateway)
     * **Tier 5: Isolated Management Plane** (Out-of-band management interface and bastion jump host)
   * **Hierarchical Breadcrumb Trail**: Active contextual breadcrumbs on canvas (`Firewall > Virtual Router > Zone > Subnet > Host`) for instant spatial orientation.
   * **Hierarchy Depth Filter**: Segmented control switching between `All Tiers`, `Zones Only` (macro architecture), and `Subnets` (routing plane).

8. **Interactive PAN-OS Hierarchy Tree Navigator**:
   * Collapsible left-hand drawer detailing the full appliance containment tree:
     $$\text{Appliance (PA-3410)} \longrightarrow \text{Virtual Router (FIB)} \longrightarrow \text{Security Zones} \longrightarrow \text{Subnets / Interfaces} \longrightarrow \text{Workloads / Hosts}$$
   * Quick filter and instant 1-click focus that centers nodes and computes blast radius.

9. **Autonomous Multi-Tool ReAct Agent (Root Cause Analysis & Remediation)**:
   * Empowers SecOps teams to ask complex, high-level questions such as:
     * *"What is happening and why did things break after CR-4910?"*
     * *"Why is Chicago branch failing to reach the payment gateway?"*
     * *"Show blast radius for DMZ Web 192.168.10.80"*
   * Executes multi-step ReAct tool chaining (`tool_analyze_commit_diff`, `tool_search_threat_logs`, `tool_simulate_packet_path`, `tool_calculate_blast_radius`).
   * Generates exact, copy-pasteable PAN-OS CLI configuration remediation scripts with automated commit comments.

8. **AI Gateway & Model Armor Security Guardrails**:
   * Built-in LLM perimeter defense inspired by **Palo Alto Networks AI Runtime Security** and **Google Cloud Model Armor**.
   * **Prompt Injection Defense**: Intercepts direct adversarial overrides (`Ignore previous instructions...`) and roleplay jailbreaks (`DAN`).
   * **Data Loss Prevention (DLP)**: Redacts sensitive PAN-OS configuration secrets, IKE pre-shared keys, password hashes (`phash`), and API tokens.
   * **SecOps Audit Logging**: Telemetry endpoint (`GET /api/armor/audit`) tracking total queries, blocked attacks, and threat vectors.

---

## 🚀 Quick Start (Fastest - Runs in 60 seconds)

The repository includes pre-compiled production frontend assets in `frontend/dist`. You only need Python to run the entire application!

### 1. Clone the repository
```bash
git clone https://github.com/abhivenkiabhi/panos-firewall-topology.git
cd panos-firewall-topology
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```
*(Or manually: `pip install fastapi uvicorn pydantic`)*

### 3. Start the server
```bash
cd backend
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```

### 4. Open in your browser
Navigate to:
👉 **[http://localhost:8000](http://localhost:8000)**

*(Interactive API Documentation / Swagger UI is available at **[http://localhost:8000/docs](http://localhost:8000/docs)**)*

---

## 🛠️ Developer Mode (Frontend Hot-Reloading)

If you wish to edit and develop the React frontend components with hot-module reloading:

### Terminal 1: Backend API
```bash
cd backend
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Terminal 2: Vite Dev Server
```bash
cd frontend
npm install
npm run dev
```
Open **`http://localhost:5173`** (Vite proxies all `/api` requests to port 8000).

To build new production assets:
```bash
cd frontend
npm run build
```

---

## 🧪 Running Automated Unit Tests

Run the test suite verifying PAN-OS `set` parsing, 32-field CSV log ingestion, App-ID reachability simulation, commit diffs, and the Q&A agent:

```bash
cd backend
python3 test_panos_engine.py
```

**Expected output:**
```text
......
----------------------------------------------------------------------
Ran 6 tests in 0.006s

OK
```

---

## 📁 Repository Structure

```text
panos-firewall-topology/
├── README.md                      # Project documentation and guide
├── requirements.txt               # Backend Python dependencies
├── .gitignore                     # Git ignore rules
│
├── data/                          # Authentic Palo Alto Networks Datasets
│   ├── pan_os_v1.set              # Baseline PA-3410 PAN-OS 11.1 running config (set format)
│   ├── pan_os_v2.set              # CR-4910 updated config (adds PCI zone, deletes Legacy-Test)
│   └── pan_os_traffic.log         # Authentic 32-field PAN-OS CSV syslog traffic events
│
├── backend/                       # Python & FastAPI Backend
│   ├── main.py                    # FastAPI server & static web distribution mount
│   ├── panos_parser.py            # PAN-OS 'set' command parser (interfaces, zones, rules)
│   ├── panos_log_ingestor.py      # 32-field CSV syslog processor & host discovery
│   ├── panos_topology_engine.py   # Network graph builder & Layer-7 App-ID simulator
│   ├── panos_diff_engine.py       # Commit & revision difference calculator
│   ├── panos_qa_agent.py          # Strata customer & SecOps Q&A agent
│   └── test_panos_engine.py       # Unit test suite
│
└── frontend/                      # React + Vite + Tailwind CSS Web UI
    ├── src/
    │   ├── App.jsx                # Main application view & state manager
    │   └── components/
    │       ├── Header.jsx         # PANW Flame branding & commit switcher
    │       ├── TopologyCanvas.jsx # SVG interactive canvas with 5-tier vertical columns
    │       ├── HierarchyTreePanel.jsx # PAN-OS 5-tier appliance containment tree panel
    │       ├── InspectorDrawer.jsx# Entity inspector with PAN-OS 'set' excerpts
    │       ├── ReachabilitySimulator.jsx # Layer-7 App-ID policy test modal
    │       ├── ChatAssistantDrawer.jsx   # Strata AI assistant drawer
    │       ├── LogStreamViewer.jsx       # CSV syslog stream & filter modal
    │       └── DiffSummaryBanner.jsx     # CR-4910 commit changes banner
    ├── dist/                      # Pre-compiled static web bundle (ready to serve)
    └── package.json               # Frontend dependencies & Vite scripts
```

---

## 🎯 Example Policy Scenarios to Try

| Source Host | Destination Host | Port | App-ID | Expected Decision | Enforced PAN-OS Policy |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `198.51.100.45` *(Untrust)* | `192.168.10.80` *(DMZ)* | `443` | `ssl` | **ALLOW** | `Allow-Inbound-Web` |
| `198.51.100.22` *(Untrust)* | `192.168.10.80` *(DMZ)* | `22` | `ssh` | **DROP** | `Block-Untrust-Scanners` |
| `192.168.10.80` *(DMZ)* | `10.100.1.50` *(Trust)* | `5432` | `postgresql` | **DROP** | `Deny-DMZ-to-DB` |
| `10.100.1.20` *(Trust App)* | `10.100.1.50` *(Trust DB)*| `5432` | `postgresql` | **ALLOW** | `Allow-App-to-DB` |
| `192.168.10.80` *(DMZ)* | `10.200.50.25` *(PCI)* | `443` | `ssl` | **ALLOW** | `Allow-DMZ-to-Payment-GW` *(CR-4910)* |

---

## 📄 License
MIT License. Created for Palo Alto Networks network engineering and security operations teams.
