# AI Log Analyzer (v2.0)

AI Log Analyzer is a production-grade Python system for detecting threats, suspicious behavior, and anomalous operational patterns in server logs.

With the release of v2.0, the platform has been fully upgraded with a **streaming data pipeline**, **real-time directory watching**, **IP Intelligence profiling**, and **Offline HTML Dashboard exports**, all wrapped in a beautiful CLI.

---

## 🎯 What it does

The analyzer processes log lines and passes them through multiple intelligence engines:

1. **Format Engine:** Automatically detects plain-text, Apache/Nginx, or JSON structures and normalizes them into a unified format.
2. **Feature Extractor:** Extracts data lengths, requests-per-second, login failure flags, and HTTP status codes to build quantitative feature rows.
3. **Threat Engine:**
   - **Rule Engine:** Scans logs for high-risk config-driven keywords.
   - **IP Profiler (v2):** Tracks every IP's fail rates and velocity over time, labeling them **CLEAN**, **SUSPICIOUS**, or **MALICIOUS**.
   - **Anomaly Detector:** Uses Isolation Forests (via `scikit-learn`) or statistical variance to detect outlier IP behaviours.
   - **Root Cause Combiner (v2):** Clusters similar errors using TF-IDF + KMeans and categorizes them automatically (e.g. `Database Failure`, `Memory Pressure`).
4. **Export Engine (v2):** Pushes results to an interactive Terminal UI, JSON, or standalone HTML file.

---

## 🚀 How to use the CLI

You can interact with the app via the `cli.py` script. The UI uses the `rich` library to render interactive, colored terminal tables.

### 1. Try the demo

Verify the pipeline works correctly with built-in mock data:

```powershell
python cli.py --sample
```

### 2. Process a Log File (Batch Mode)

You can pass raw text logs, Apache access logs, or JSONL files into the pipeline.
The tool automatically determines the format per line using lazy-generators, meaning you can comfortably parse huge multi-GB files without running out of RAM.

```powershell
python cli.py --input logs/sample.log
```

*(You can find a sample multi-format file in the `logs/` directory)*

### 3. Watch for Logs in Real-Time 

The Log Monitor actively watches a server directory or specific file. As your app writes new log lines, they are immediately piped through the threat engine natively. Any high-severity alerts print to your terminal instantly.

```powershell
# Watch an entire directory for any .log or .jsonl changes
python cli.py --watch logs/

# Watch a single live app log
python cli.py --watch /var/log/nginx/access.log
```
Press `CTRL+C` to stop the monitor stream.

### 4. Exporting Reports

If you want to view the resulting data outside the terminal, or send it to your team, use the Export Engine:

**Generate a self-contained HTML Dashboard (No internet/JS-frameworks required):**
```powershell
python cli.py --input logs/sample.log --format html --output report.html
```

**Generate structured JSON for API routing:**
```powershell
python cli.py --input logs/sample.log --format json --output report.json --no-dashboard
```

---

## ⚙️ Configuration & Customization

The system is highly modular.

- **Adding rules:** You can add new threat detection keywords by editing `config/detection_rules.json`. No python code changes needed.
- **Root Cause taxonomy:** Open `threat_engine/log_clustering.py` and add new regex entries to the `ROOT_CAUSE_RULES` array to add custom classifiers.

## 📦 Requirements

- **Python 3.8+**
- **Rich** (Terminal UI): `pip install rich`
- **scikit-learn** *(Optional, but highly recommended for Isolation Forest anomalies and TF-IDF clustering)*. If not installed, the tool gracefully falls back to statistical/keyword categorization loops.