import os
import sys
import time
import shutil
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class MonitorHandler(FileSystemEventHandler):
    def __init__(self, signature_file, output_file):
        self.signature_file = signature_file
        self.output_file = output_file
        self.signatures = self.load_signatures()

    def load_signatures(self):
        with open(self.signature_file, 'r') as f:
            return [line.strip() for line in f]

    def is_infected(self, file_path):
        with open(file_path, 'r') as f:
            content = f.read()
            for signature in self.signatures:
                if signature in content:
                    return True
        return False

    def quarantine_file(self, file_path):
        quarantine_dir = 'quarantine'
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)
        shutil.move(file_path, os.path.join(quarantine_dir, os.path.basename(file_path)))

    def log_infected(self, file_path):
        with open(self.output_file, 'a') as f:
            f.write(f"Infected file detected: {file_path}\n")

    def on_created(self, event):
        if not event.is_directory:
            print(f"File created: {event.src_path}")
            if self.is_infected(event.src_path):
                self.quarantine_file(event.src_path)
                self.log_infected(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            print(f"File modified: {event.src_path}")
            if self.is_infected(event.src_path):
                self.quarantine_file(event.src_path)
                self.log_infected(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"File deleted: {event.src_path}")

def main():
    parser = argparse.ArgumentParser(description="Real-Time Directory Monitoring Tool")
    parser.add_argument('-d', '--directory', required=True, help="The directory to scan.")
    parser.add_argument('-s', '--signature', required=True, help="Path to the malware signature database.")
    parser.add_argument('-o', '--output', required=True, help="File to save a report of infected files.")
    parser.add_argument('-r', '--realtime', action='store_true', help="Run in real-time mode to monitor the directory.")
    args = parser.parse_args()

    event_handler = MonitorHandler(args.signature, args.output)
    observer = Observer()
    observer.schedule(event_handler, args.directory, recursive=True)

    if args.realtime:
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    else:
        print("Real-time mode not enabled. Use -r to enable real-time monitoring.")

if __name__ == "__main__":
    main()