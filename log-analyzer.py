"""
Log Analyzer / Failed Login Detector
Author: Abel Mwedihanga - github.com/abelMwedihanga
Detects brute-force attacks by finding many failed logins from same IP.
"""

from collections import Counter, defaultdict

# How many failed logins = attack?
THRESHOLD = 5

def analyze_log(filename="sample.log"):
    failed_ips = []
    failed_users = []
    total_lines = 0

    try:
        with open(filename, 'r') as f:
            for line in f:
                total_lines += 1
                line = line.strip().lower()
                # Look for failed login lines
                if "failed" in line and "login" in line:
                    # Extract IP - assumes format: ... from 192.168.1.10 ...
                    parts = line.split()
                    for i, word in enumerate(parts):
                        if word == "from" and i+1 < len(parts):
                            ip = parts[i+1]
                            failed_ips.append(ip)
                        if word == "for" and i+1 < len(parts):
                            failed_users.append(parts[i+1])
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found!")
        return

    print("="*50)
    print("  LOG ANALYSIS REPORT")
    print("="*50)
    print(f"Total lines scanned: {total_lines}")
    print(f"Total failed logins: {len(failed_ips)}")
    print("")

    if not failed_ips:
        print("✅ No failed logins found. System looks clean.")
        return

    # Count per IP
    ip_counts = Counter(failed_ips)
    print("Failed logins per IP:")
    for ip, count in ip_counts.most_common():
        status = "🚨 POSSIBLE BRUTE-FORCE ATTACK!" if count >= THRESHOLD else "⚠️  Suspicious"
        print(f"  {ip} : {count} attempts - {status}")

    print("")
    print("Most targeted usernames:")
    for user, count in Counter(failed_users).most_common(5):
        print(f"  {user} : {count} attempts")

    print("")
    print("RECOMMENDATION:")
    for ip, count in ip_counts.items():
        if count >= THRESHOLD:
            print(f"  -> BLOCK IP {ip} in firewall immediately.")

if __name__ == "__main__":
    analyze_log("sample.log")