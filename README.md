# AI Log Analyzer

AI Log Analyzer is a Python command-line project for detecting threats, suspicious behavior, and unusual operational patterns in logs.

The current version focuses on the threat-analysis layer:
- rule-based detection
- behavior detection
- anomaly detection
- log clustering
- text or JSON reporting

At the moment, the project works best with structured JSON input. The future version should add a full data-ingestion layer for raw `.log` files, Apache logs, JSONL logs, and folders of mixed sources.

## Project Goal

Modern applications generate large amounts of logs. This project is designed to reduce manual log inspection by:
- converting logs into analyzable events
- detecting known threat patterns
- identifying suspicious behavior such as repeated login failures
- flagging anomalous activity from numeric features
- grouping similar logs to help identify root causes
- generating readable output for admins and developers

## Current Status

Implemented now:
- CLI entrypoint in [cli.py](cli.py)
- threat orchestration in [threat_engine/threat_engine.py](threat_engine/threat_engine.py)
- rule matching in [threat_engine/rule_engine.py](threat_engine/rule_engine.py)
- behavior detection in [threat_engine/behaviour_engine.py](threat_engine/behaviour_engine.py)
- anomaly detection in [threat_engine/anomaly_detector.py](threat_engine/anomaly_detector.py)
- log clustering in [threat_engine/log_clustering.py](threat_engine/log_clustering.py)
- report generation in [reporter/report_generator.py](reporter/report_generator.py)
- configurable detection rules in [config/detection_rules.json](config/detection_rules.json)

Still missing for a full production-style pipeline:
- raw log file ingestion
- log format detection
- multi-format parsing
- automatic feature extraction from raw logs
- folder scanning and recursive log loading
- richer export targets such as HTML dashboards

## How It Works

The current execution flow is:

1. The CLI loads input.
2. The threat engine normalizes the logs.
3. Rule detection matches messages against configured keywords.
4. Behavior detection checks for brute-force and traffic bursts.
5. Anomaly detection scores numeric feature rows.
6. Clustering groups similar log messages.
7. The reporter returns text or JSON output.

Flow summary:

```text
CLI Input
  -> ThreatEngine
  -> RuleEngine
  -> BehaviourDetector
  -> AnomalyDetector
  -> LogClustering
  -> Report Generator
  -> Output
```

## Input Model

The current version expects structured JSON input.

Supported forms:

1. A list of log objects
2. An object with `logs` and optional `features`

Example:

```json
{
  "logs": [
    {
      "timestamp": "2026-03-14 12:20:01",
      "level": "ERROR",
      "message": "Database timeout while processing checkout request",
      "ip": "192.168.1.10",
      "source": "api-gateway"
    },
    {
      "timestamp": "2026-03-14 12:20:10",
      "level": "ERROR",
      "message": "Authentication failure for admin user",
      "ip": "192.168.1.10",
      "source": "auth-service"
    }
  ],
  "features": [
    {
      "ip": "192.168.1.10",
      "request_rate": 120,
      "error_rate": 0.6,
      "data_transfer_rate": 15,
      "login_failures": 7,
      "log_length": 46
    }
  ]
}
```

If `features` are not supplied, the engine derives simple feature rows from the logs automatically.

## Demo Usage

Run the built-in sample dataset:

```powershell
c:/python313/python.exe cli.py --sample
```

Run the sample and get JSON output:

```powershell
c:/python313/python.exe cli.py --sample --format json
```

Run the analyzer against your own JSON file:

```powershell
c:/python313/python.exe cli.py --input your_logs.json
```

Write the result to a file:

```powershell
c:/python313/python.exe cli.py --input your_logs.json --output report.txt
```

Run the standalone test script:

```powershell
c:/python313/python.exe test_engine.py
```

## Detection Components

### Rule Engine

The rule engine loads configurable detection rules from [config/detection_rules.json](config/detection_rules.json).

Each rule contains:
- name
- category
- severity
- keywords
- description

When a keyword appears inside a log message, the engine emits an alert.

### Behavior Detector

The behavior detector currently checks for:
- repeated login failures from the same IP
- request bursts inside a one-minute window

This is useful for brute-force or abuse-style patterns that may not be visible from a single log entry.

### Anomaly Detector

The anomaly detector works on numeric feature rows such as:
- request rate
- error rate
- data transfer rate
- login failures
- log length

If `scikit-learn` is available, it uses Isolation Forest.
If not, it falls back to a pure-Python statistical distance method.

### Log Clustering

The clustering module groups similar log messages.

If `scikit-learn` is available, it uses TF-IDF and KMeans.
If not, it uses keyword-based grouping.

## Project Structure

```text
log-analyzer/
├── cli.py
├── README.md
├── test_engine.py
├── config/
│   └── detection_rules.json
├── reporter/
│   └── report_generator.py
└── threat_engine/
    ├── __init__.py
    ├── anomaly_detector.py
    ├── behavior_engine.py
    ├── behaviour_engine.py
    ├── dbtimout.py
    ├── log_clustering.py
    ├── rule_engine.py
    └── threat_engine.py
```

## What Needs To Be Built Next

To make this project work directly on real log files in the future, the next major step is a `data_engine` package.

Recommended modules:

1. `data_engine/log_parser.py`
   Parse raw log lines into structured objects.

2. `data_engine/format_detector.py`
   Detect whether a file is plain text, Apache, JSON, or another format.

3. `data_engine/feature_extractor.py`
   Aggregate request counts, error rates, login failures, and related metrics.

4. `data_engine/time_series_analyzer.py`
   Build sliding windows such as requests per minute and errors per minute.

5. CLI file/folder ingestion
   Support commands like:

```powershell
c:/python313/python.exe cli.py --input logs/app.log
c:/python313/python.exe cli.py --input logs/ --recursive
```

## Future End-State Workflow

The intended future architecture is:

```text
Raw log file or log folder
  -> input loader
  -> format detector
  -> parser
  -> normalized log events
  -> feature extractor
  -> threat engine
  -> report generator
  -> text / JSON / dashboard output
```

## Notes

- The project currently runs without requiring `scikit-learn`, but can use it when available.
- The strongest current path is the demo and structured JSON input.
- The main missing capability is real-world raw log ingestion.

## Next Improvements

Good next tasks for this repository:

1. Build the missing `data_engine` package.
2. Add sample raw log files under a `logs/` folder.
3. Add unit tests for each engine.
4. Add HTML reporting.
5. Add severity scoring and triage summaries.