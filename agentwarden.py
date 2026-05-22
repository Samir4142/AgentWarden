import os
import datetime
import time
import hashlib
import threading
from validator import layer_regex_check, layer_groq_check, layer_keyword_check

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

file_hashes = {}


def hash_file(filepath):
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()


def analyze_logs():
    for filename in os.listdir(LOGS_DIR):
        filepath = os.path.join(LOGS_DIR, filename)
        if os.path.isfile(filepath):
            current_hash = hash_file(filepath)
            if filename not in file_hashes or file_hashes[filename] != current_hash:
                print(f"Analyzing {filename}...")
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    regex_result = layer_regex_check(content)
                    groq_result = layer_groq_check(content)
                    keyword_result = layer_keyword_check(content)

                    if regex_result == "suspicious" or groq_result == "suspicious" or keyword_result == "suspicious":
                        print(f"[THREAT DETECTED] {filename}")
                        report_path = os.path.join(
                            REPORTS_DIR, "threat_report.txt")
                        with open(report_path, "a") as report_file:
                            report_file.write(
                                f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: Threat Detected in {filename}:\n")
                            report_file.write(f"Regex Check: {regex_result}\n")
                            report_file.write(f"Groq Check: {groq_result}\n")
                            report_file.write(
                                f"Keyword Check: {keyword_result}\n")
                            report_file.write("-" * 40 + "\n")
                    else:
                        print(f"[SAFE] {filename} — All Layers Clean")
                file_hashes[filename] = current_hash


stop_event = threading.Event()


def listen_for_quit():
    while not stop_event.is_set():
        user_input = input("Press 'Q' To Quit: \n")
        if user_input.upper() == 'Q':
            stop_event.set()
            print("\n[AgentWarden] Shutting Down. Stay Safe.")


if __name__ == "__main__":
    threading.Thread(target=listen_for_quit, daemon=True).start()
    while not stop_event.is_set():
        analyze_logs()
        time.sleep(10)  # Sleep For 10 Seconds Before Next Check
