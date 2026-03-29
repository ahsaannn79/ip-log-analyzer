import re

def extract(filename):
    file = open(filename, "r")
    ip_list = []

    for line in file:
        line = line.strip()
        result = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
        ip_list.extend(result)

    file.close()
    return ip_list


def count(ip_list):
    ip_log = {}

    for ip in ip_list:
        ip_log[ip] = ip_log.get(ip, 0) + 1

    return ip_log


def analyse(ip_dictionary, threshold):

    report_lines = []

    report_lines.append("IP Analysis Report\n")

    if not ip_dictionary:
        report_lines.append("No IP data found\n")
        return report_lines

    # Most Active IP
    max_count = max(ip_dictionary.values())

    report_lines.append("Most Active IP(s):")
    for key, count in ip_dictionary.items():
        if count == max_count:
            report_lines.append(f"{key} -> {count}")
    report_lines.append("")

    # Suspicious IP
    report_lines.append(f"Suspicious IP(s) (>= {threshold}):")
    for key, count in ip_dictionary.items():
        if count >= threshold:
            report_lines.append(f"{key} -> {count}")
    report_lines.append("")

    return report_lines


def save_report(report_lines, filename="report.txt"):
    file = open(filename, "w")

    for line in report_lines:
        file.write(line + "\n")

    file.close()
    print(f"Report saved as {filename}")


# MAIN

ips = extract("logs.txt")
logs = count(ips)

# User-defined threshold
threshold = int(input("Enter suspicious IP threshold: "))

report = analyse(logs, threshold)
save_report(report)