# monitor.py 
import time
import re
import json
from datetime import datetime
import os

LOG_FILE = "edr_shared.log"
ALERTS_FILE = "edr_alerts.jsonl"

def parse_log(line):
    match = re.match(r'Process:\s*([^|]+)\s*\|\s*PID:\s*(\d+)\s*\|\s*(.+)', line.strip())
    if match:
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "process_name": match.group(1).strip(),
            "pid": int(match.group(2)),
            "event": match.group(3).strip()
        }
    return None

def main():
    print("[+] Tailing edr_shared.log for EDR events...")
    print("[+] Press Ctrl+C to exit")
    
    if not os.path.exists(LOG_FILE):
        print(f"[-] Waiting for {LOG_FILE} to be created by Agent.exe...")
        while not os.path.exists(LOG_FILE):
            time.sleep(0.5)
    
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            # Go to end of file
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    event = parse_log(line)
                    if event:
                        print(f"[ALERT] {event['process_name']}({event['pid']}) → {event['event']}")
                        if any(kw in event["event"] for kw in ["EXECUTE_READWRITE", "executable", "Blocked"]):
                            print("HIGH RISK DETECTED")
                        with open(ALERTS_FILE, "a", encoding="utf-8") as af:
                            af.write(json.dumps(event) + "\n")
                else:
                    # Sleep briefly AND allow interruption
                    time.sleep(0.1)  # Short sleep = responsive to Ctrl+C
    except KeyboardInterrupt:
        print("\n[!] Caught Ctrl+C. Exiting gracefully...")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
    finally:
        print("[+] Monitor stopped.")

if __name__ == "__main__":
    main()
