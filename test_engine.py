from threat_engine.threat_engine import ThreatEngine

logs = [
{
"timestamp":"2026-03-14 12:20:01",
"level":"ERROR",
"message":"Database timeout",
"ip":"192.168.1.10"
},
{
"timestamp":"2026-03-14 12:20:10",
"level":"ERROR",
"message":"Authentication failed",
"ip":"192.168.1.10"
},
{
"timestamp":"2026-03-14 12:20:15",
"level":"ERROR",
"message":"Authentication failed",
"ip":"192.168.1.10"
}
]

features = [
{
"ip":"192.168.1.10",
"request_rate":120,
"error_rate":0.3,
"login_failures":7,
"log_length":100
}
]

engine = ThreatEngine()

result = engine.analyze(logs, features)

print(result)