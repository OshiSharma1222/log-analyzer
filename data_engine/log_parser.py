import json
import logging
from pathlib import Path
from typing import Dict, Any, Generator, Optional
from data_engine.format_detector import detect_format, LogFormat, APACHE_REGEX, STANDARD_REGEX

logger = logging.getLogger(__name__)

def parse_json(line: str) -> Dict[str, Any]:
    """Parse JSON log format into a unified structure."""
    try:
        data = json.loads(line)
        return {
            "timestamp": data.get("timestamp", ""),
            "level": data.get("level", "INFO").upper(),
            "message": data.get("message", data.get("event", "Unknown Event")),
            "ip": data.get("ip", ""),
            "source": data.get("source", "json"),
            "metadata": {k: v for k, v in data.items() if k not in ["timestamp", "level", "message", "event", "ip", "source"]}
        }
    except Exception as e:
        logger.error(f"Failed to parse JSON line: {e}")
        return _empty_log("json_error")

def parse_apache(line: str) -> Dict[str, Any]:
    """Parse Apache/Nginx log format into a unified structure."""
    match = APACHE_REGEX.match(line)
    if not match:
        return _empty_log("apache_parse_error")
    
    gd = match.groupdict()
    status = gd.get("status", "200")
    level = "ERROR" if int(status) >= 400 else "INFO"
    
    # Store standard fields directly, rest in metadata
    return {
        "timestamp": gd.get("time", ""),
        "level": level,
        "message": gd.get("request", ""),
        "ip": gd.get("ip", ""),
        "source": "apache",
        "metadata": {"status_code": status, "bytes_sent": gd.get("size")}
    }

def parse_standard(line: str) -> Dict[str, Any]:
    """Parse Standard text log format into a unified structure."""
    match = STANDARD_REGEX.match(line)
    if not match:
        return _empty_log("standard_parse_error")
    
    gd = match.groupdict()
    return {
        "timestamp": gd.get("time", ""),
        "level": (gd.get("level") or "INFO").upper(),
        "message": gd.get("message", ""),
        "ip": "",  # IPs typically not upfront in plain layouts, usually requires deeper regex on message.
        "source": "standard",
        "metadata": {}
    }

def _empty_log(source: str = "unknown") -> Dict[str, Any]:
    """Return fallback object for broken parser streams to avoid crashing downstream ML."""
    return {
        "timestamp": "",
        "level": "UNKNOWN",
        "message": "",
        "ip": "",
        "source": source,
        "metadata": {}
    }

def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Route a log line through format detection and to its specific parser.
    """
    fmt = detect_format(line)
    if fmt == LogFormat.JSON:
        return parse_json(line)
    elif fmt == LogFormat.APACHE:
        return parse_apache(line)
    elif fmt == LogFormat.STANDARD:
        return parse_standard(line)
    
    return None

def ingest_file(file_path: str) -> Generator[Dict[str, Any], None, None]:
    """
    Ingest a log file sequentially using a lazy generator to prevent memory overflow.
    This allows very large log files to stream directly into the feature detection layer.
    
    Args:
        file_path (str): The absolute or relative file URI to scan.
        
    Yields:
        Dict[str, Any]: The parsed and normalized log entry.
    """
    path = Path(file_path)
    if not path.is_file():
        logger.error(f"File not found: {file_path}")
        return

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
                
            parsed = parse_log_line(stripped)
            if parsed:
                yield parsed
