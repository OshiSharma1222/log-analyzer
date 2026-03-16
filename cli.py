import argparse
import json
from pathlib import Path

from reporter.report_generator import generate_report
from threat_engine.threat_engine import ThreatEngine


SAMPLE_PAYLOAD = {
	"logs": [
		{
			"timestamp": "2026-03-14 12:20:01",
			"level": "ERROR",
			"message": "Database timeout while processing checkout request",
			"ip": "192.168.1.10",
			"source": "api-gateway",
		},
		{
			"timestamp": "2026-03-14 12:20:10",
			"level": "ERROR",
			"message": "Authentication failure for admin user",
			"ip": "192.168.1.10",
			"source": "auth-service",
		},
		{
			"timestamp": "2026-03-14 12:20:15",
			"level": "ERROR",
			"message": "Authentication failure for admin user",
			"ip": "192.168.1.10",
			"source": "auth-service",
		},
		{
			"timestamp": "2026-03-14 12:20:20",
			"level": "CRITICAL",
			"message": "Unauthorized access attempt detected on admin panel",
			"ip": "192.168.1.11",
			"source": "web-server",
		},
		{
			"timestamp": "2026-03-14 12:20:30",
			"level": "WARNING",
			"message": "Database timeout while processing checkout request",
			"ip": "192.168.1.10",
			"source": "api-gateway",
		},
	],
	"features": [
		{
			"ip": "192.168.1.10",
			"request_rate": 120,
			"error_rate": 0.6,
			"data_transfer_rate": 15,
			"login_failures": 7,
			"log_length": 46,
		},
		{
			"ip": "192.168.1.11",
			"request_rate": 12,
			"error_rate": 0.2,
			"data_transfer_rate": 4,
			"login_failures": 0,
			"log_length": 39,
		},
		{
			"ip": "192.168.1.15",
			"request_rate": 3,
			"error_rate": 0.0,
			"data_transfer_rate": 1,
			"login_failures": 0,
			"log_length": 18,
		},
	],
}


def _load_payload(input_path):
	with Path(input_path).open("r", encoding="utf-8") as handle:
		payload = json.load(handle)

	if isinstance(payload, list):
		return {"logs": payload, "features": []}
	return payload


def main():
	parser = argparse.ArgumentParser(description="AI Log Analyzer CLI")
	parser.add_argument("--input", help="Path to a JSON file containing logs or {logs, features}")
	parser.add_argument("--format", choices=["text", "json"], default="text", help="Report output format")
	parser.add_argument("--output", help="Optional path to write the generated report")
	parser.add_argument("--sample", action="store_true", help="Run the built-in demo dataset")
	args = parser.parse_args()

	if not args.sample and not args.input:
		parser.error("provide --input or use --sample")

	payload = SAMPLE_PAYLOAD if args.sample else _load_payload(args.input)
	engine = ThreatEngine()
	result = engine.analyze(payload.get("logs", []), payload.get("features", []))
	report = generate_report(result, output_format=args.format)

	if args.output:
		Path(args.output).write_text(report, encoding="utf-8")
	else:
		print(report)


if __name__ == "__main__":
	main()
