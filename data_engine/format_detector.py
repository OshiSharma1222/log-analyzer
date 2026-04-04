import json
import re
from enum import Enum

class LogFormat(Enum):
    JSON = "json"
    APACHE = "apache"
    STANDARD = "standard"
    UNKNOWN = "unknown"

# Matches Apache/Nginx combined and common log formats
APACHE_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

# Matches standard timestamped logs like: `2026-03-14 12:20:01 ERROR Database timeout`
STANDARD_REGEX = re.compile(
    r'^(?P<time>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*(?P<level>[A-Z]+)?\s*(?P<message>.*)'
)

def detect_format(line: str) -> LogFormat:
    """
    Detect the format of a log line.

    Args:
        line (str): A single line from a log file.

    Returns:
        LogFormat: System enum identifying the format class.
    """
    line = line.strip()
    if not line:
        return LogFormat.UNKNOWN

    # Fast check for JSON structure
    if line.startswith('{') and line.endswith('}'):
        try:
            json.loads(line)
            return LogFormat.JSON
        except json.JSONDecodeError:
            pass

    # Check Apache Nginx common/combined patterns
    if APACHE_REGEX.match(line):
        return LogFormat.APACHE

    # Check standard log entries
    if STANDARD_REGEX.match(line):
        return LogFormat.STANDARD

    return LogFormat.UNKNOWN
