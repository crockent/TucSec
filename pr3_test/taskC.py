import argparse
import hashlib
import logging
import os
import shutil
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Set up logging
logging.basicConfig(filename="detection_report.log", level=logging.INFO)

class MalwareMonitorHandler(FileSystemEventHandler):
    def __init__(self, signature_file, output_file, quarantine_dir):
        self.signatures = self.load_signatures(signature_file)
        self.output_file = output_file
        self.quarantine_dir = quarantine_dir

    def load_signatures(self, signature_file):
        # Load malware signatures from file into a list of dictionaries
        signatures = []
        with open(signature_file, "r") as file:
            for line in file.readlines()[2:]:  # Skip headers if any
                parts = line.strip().split(" | ")
                signatures.append({
                    "MD5": parts[0],
                    "SHA256": parts[1],
                    "Malware Type": parts[2],
                    "Infection Date": parts[3],
                    "Severity Level": parts[4]
                })
        return signatures

    def calculate_hashes(self, file_path):
        """Calculate MD5, SHA1, SHA256, and SHA512 hashes for the given file."""
        hash_md5 = hashlib.md5()
        hash_sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            content = f.read()
            hash_md5.update(content)
            hash_sha256.update(content)
        
        return {
            "MD5": hash_md5.hexdigest(),
            "SHA256": hash_sha256.hexdigest()
        }

    def is_malware(self, file_path):
        # Check if file contains malware based on hashes against signatures
        file_hashes = self.calculate_hashes(file_path)
        for signature in self.signatures:
            if (file_hashes["MD5"] == signature["MD5"] and
                file_hashes["SHA256"] == signature["SHA256"]):
                logging.info(
                    f"Detected Malware: {file_path}, MD5: {signature['MD5']}, "
                    f"SHA256: {signature['SHA256']} Threat Level: {signature['Severity Level']}, "
                    f"Timestamp: {datetime.now()}"
                )
                return True, signature  # Return true with signature details
        return False, None

    def quarantine_file(self, file_path):
        # Set the quarantine directory as an absolute path
        self.quarantine_dir = os.path.abspath("files/quarantine")

        # Print statements to debug path values
        print(f"Quarantine directory: {self.quarantine_dir}")
        print(f"File path before move: {file_path}")

        # Ensure the quarantine directory exists
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

        # Define the quarantine path and print it
        quarantine_path = os.path.join(self.quarantine_dir, os.path.basename(file_path))
        print(f"Quarantine path: {quarantine_path}")

        # Move the file
        shutil.move(file_path, quarantine_path)
        return quarantine_path


    def log_infected_file(self, file_path, signature):
        # Log infected file to output report
        with open(self.output_file, 'a') as f:
            f.write(
                f"Infected file quarantined: {file_path}, "
                f"Malware Type: {signature['Malware Type']}, "
                f"Severity Level: {signature['Severity Level']}, "
                f"Infection Date: {signature['Infection Date']}\n"
            )

    def on_created(self, event):
        if event.is_directory:
            return
        print(f"File created: {event.src_path}")
        infected, signature = self.is_malware(event.src_path)
        if infected:
            quarantine_path = self.quarantine_file(event.src_path)
            output_report = self.output_file
            self.log_infected_file(quarantine_path, signature)
            print(f"Infected file quarantined: {quarantine_path}")
            open(output_report, 'a').write(f"Infected file quarantined: {quarantine_path}, Malware Type: {signature['Malware Type']}, Severity Level: {signature['Severity Level']}, Infection Date: {signature['Infection Date']}\n")

    def on_modified(self, event):
        if event.is_directory:
            return
        print(f"File modified: {event.src_path}")
        infected, signature = self.is_malware(event.src_path)
        if infected:
            quarantine_path = self.quarantine_file(event.src_path)
            output_report = self.output_file
            self.log_infected_file(quarantine_path, signature)
            print(f"Infected file quarantined: {quarantine_path}")
            open(output_report, 'a').write(f"Infected file quarantined: {quarantine_path}, Malware Type: {signature['Malware Type']}, Severity Level: {signature['Severity Level']}, Infection Date: {signature['Infection Date']}\n")

def monitor_directory(directory, signature_file, output_file, run_real_time):
    quarantine_dir = os.path.join(directory, "files/quarantine")
    event_handler = MalwareMonitorHandler(signature_file, output_file, quarantine_dir)
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)

    print("Starting monitoring...")
    observer.start()

    try:
        while run_real_time:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-time Malware Monitoring Tool")
    parser.add_argument("-d", "--directory", required=True, help="Directory to scan")
    parser.add_argument("-s", "--signature_file", required=True, help="Path to the malware signature database")
    parser.add_argument("-o", "--output_file", required=True, help="File to save a report of infected files")
    parser.add_argument("-r", "--realtime", action="store_true", help="Run in real-time mode to monitor the directory")

    args = parser.parse_args()
    monitor_directory(args.directory, args.signature_file, args.output_file, args.realtime)
