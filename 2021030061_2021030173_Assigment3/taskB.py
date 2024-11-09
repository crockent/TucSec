import argparse
import os
import shutil
import logging
from datetime import datetime

# Constants
QUARANTINE_DIR = "files/quarantine"  # Directory to store quarantined files
LOG_FILE = "detection_report.log"  # Log file for the malware detection report
DIR_TO_SCAN = "files"  # Directory to scan for malware

# Function to setup logging
def setup_logging():
    """Setup logging to write to a log file."""
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                        format="%(asctime)s - %(levelname)s - %(message)s")

# Function to quarantine a file
def quarantine_file(file_path, threat_level, description):
    """Move the suspicious file to the quarantine directory."""
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)

    # Generate quarantine path
    file_name = os.path.basename(file_path)
    quarantine_path = os.path.join(QUARANTINE_DIR, file_name)
    
    # Move the file to quarantine
    shutil.move(file_path, quarantine_path)
    
    # Log the quarantine action
    logging.info(f"Quarantined file: {file_path}, Threat Level: {threat_level}, Description: {description}, Timestamp: {datetime.now()}")
    print(f"File quarantined: {file_name} (Threat Level: {threat_level})")

# Function to calculate file hashes (MD5 and SHA256)
def calculate_hashes(file_path):
    """Calculate MD5 and SHA256 hashes for a given file."""
    import hashlib

    hash_md5 = hashlib.md5()
    hash_sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        content = f.read()
        hash_md5.update(content)
        hash_sha256.update(content)

    return hash_md5.hexdigest(), hash_sha256.hexdigest()

# Function to load signatures from Task A
def load_signatures(signature_file="malware_signatures.txt"):
    """Load malware signatures from file and return them as a list of dictionaries."""
    signatures = []
    with open(signature_file, "r") as file:
        for line in file.readlines()[2:]:  # Skip headers
            parts = line.strip().split(" | ")
            signatures.append({
                "MD5": parts[0],
                "SHA256": parts[1],
                "Malware Type": parts[2],
                "Infection Date": parts[3],
                "Severity Level": parts[4]
            })
    return signatures

# Recursive scanning function
def scan_directory_for_malware(directory, signatures):
    """Recursively scan the directory for files and detect malware."""
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)

            # Calculate file hashes
            md5_hash, sha256_hash = calculate_hashes(file_path)

            # Compare with signature database
            for signature in signatures:
                if md5_hash == signature["MD5"] and sha256_hash == signature["SHA256"]:
                    print(f"Malware detected in file: {file}")
                    logging.info(f"Malware detected: {file_path}, MD5: {md5_hash}, SHA256: {sha256_hash}, Threat Level: {signature['Severity Level']}, Timestamp: {datetime.now()}")

                    # Quarantine the file
                    quarantine_file(file_path, signature["Severity Level"], signature["Malware Type"])
                    break

# Main function for Task B: Search and Quarantine
def search_and_quarantine(directory=DIR_TO_SCAN):
    """Main function to execute Task B - Search and Quarantine."""
    # Load malware signatures from the database
    signatures = load_signatures()

    # Setup logging
    setup_logging()

    # Start scanning the directory and subdirectories for malware
    print(f"Scanning directory '{directory}' and subdirectories for malware...")
    scan_directory_for_malware(directory, signatures)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run specific functions from the script.")
    parser.add_argument("--function", type=str, required=True, help="")
    args = parser.parse_args()

    # Map function names to actual functions
    functions = {
        "search_and_quarantine": search_and_quarantine
    }

    if args.function in functions:
        functions[args.function]()
    else:
        print("Function not recognized. Please choose from:", ", ".join(functions.keys()))