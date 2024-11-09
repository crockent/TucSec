import hashlib
import os
import shutil

FILESFORQUARANTINE = "files_for_quarantine.txt"

# Function to quarantine malware files
def send_files_to_quarantine():
    with open(FILESFORQUARANTINE, "r") as file:
        for line in file.readlines():
            file_path = line.strip()
            # Move file to quarantine directory
            shutil.move(file_path, "quarantine/")
            
            print(f"File moved to quarantine: {file_path}")

def revert_quarantine():
    with open(FILESFORQUARANTINE, "r") as file:
        for line in file.readlines():
            file_path = line.strip()
            # Move file back to original directory
            shutil.move(f"quarantine/{os.path.basename(file_path)}", os.path.dirname(file_path))
            
            print(f"File moved back to original directory: {file_path}")

# Run the function to quarantine files
#send_files_to_quarantine()

# Run the function to revert quarantine
revert_quarantine()
