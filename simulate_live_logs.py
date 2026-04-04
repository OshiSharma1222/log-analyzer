import time
import random
from datetime import datetime

# Sample log templates
TEMPLATES = [
    '{ip} - - [{time} +0000] "GET /api/v1/users" 200 {size}',
    '{ip} - - [{time} +0000] "POST /login" {status} 54',
    '{time} {level} database timeout observed in pool',
    '{{"timestamp": "{iso_time}", "event": "unauthorized access", "ip": "{ip}", "level": "critical"}}',
    '{time} WARNING authentication failure for user admin'
]

IPS = ["192.168.1.10", "192.168.1.50", "10.0.0.99"]

print("Starting live log simulation... (Press Ctrl+C to stop)")
print("Writing a new log to logs/live.log every 2 seconds.")

with open("logs/live.log", "a") as f:
    while True:
        try:
            # Generate random log data
            template = random.choice(TEMPLATES)
            ip = random.choice(IPS)
            now = datetime.now()
            
            # Format time for different log types
            apache_time = now.strftime("%d/%b/%Y:%H:%M:%S")
            std_time = now.strftime("%Y-%m-%d %H:%M:%S")
            iso_time = now.isoformat()
            
            level = random.choice(["INFO", "WARNING", "ERROR"])
            status = random.choice(["200", "401", "500"])
            size = random.randint(100, 5000)
            
            # Build the log string
            log_line = template.format(
                ip=ip, 
                time=apache_time if " +0000" in template else std_time,
                iso_time=iso_time,
                level=level, 
                status=status, 
                size=size
            )
            
            # Write and flush to disk
            f.write(log_line + "\n")
            f.flush()
            
            print(f"--> Wrote: {log_line}")
            time.sleep(2)
            
        except KeyboardInterrupt:
            print("\nSimulation stopped.")
            break
