from reporter.report_generator import generate_report
from threat_engine.threat_engine import ThreatEngine


logs = [
	{
		"timestamp": "2026-03-14 12:20:01",
		"level": "ERROR",
		"message": "Database timeout",
		"ip": "192.168.1.10",
		"source": "db-service",
	},
	{
		"timestamp": "2026-03-14 12:20:10",
		"level": "ERROR",
		"message": "Authentication failure",
		"ip": "192.168.1.10",
		"source": "auth-service",
	},
	{
		"timestamp": "2026-03-14 12:20:15",
		"level": "ERROR",
		"message": "Authentication failure",
		"ip": "192.168.1.10",
		"source": "auth-service",
	},
	{
		"timestamp": "2026-03-14 12:20:18",
		"level": "CRITICAL",
		"message": "Unauthorized access from admin panel",
		"ip": "192.168.1.11",
		"source": "web-server",
	},
	{
		"timestamp": "2026-03-14 12:20:30",
		"level": "ERROR",
		"message": "Authentication failure",
		"ip": "192.168.1.10",
		"source": "auth-service",
	},
	{
		"timestamp": "2026-03-14 12:20:40",
		"level": "ERROR",
		"message": "Authentication failure",
		"ip": "192.168.1.10",
		"source": "auth-service",
	},
]

features = [
	{
		"ip": "192.168.1.10",
		"request_rate": 120,
		"error_rate": 0.5,
		"data_transfer_rate": 15,
		"login_failures": 7,
		"log_length": 100,
	},
	{
		"ip": "192.168.1.11",
		"request_rate": 10,
		"error_rate": 0.2,
		"data_transfer_rate": 2,
		"login_failures": 0,
		"log_length": 30,
	},
	{
		"ip": "192.168.1.20",
		"request_rate": 2,
		"error_rate": 0.0,
		"data_transfer_rate": 1,
		"login_failures": 0,
		"log_length": 15,
	},
]

engine = ThreatEngine()
result = engine.analyze(logs, features)

print(generate_report(result))