from datetime import datetime
import hashlib
import logging
import os
import shutil

# Setup logging
logging.basicConfig(filename="detection_log.log", level=logging.INFO)

# Constants
DIRECTORIES_TO_SCAN = ["files/test_files", "files/sample_pdfs"]
SIGNATURE_FILE = "malware_signatures.txt"

# Function to calculate hashes
def calculate_hashes(file_path):
    """Calculate MD5, SHA1, SHA256, and SHA512 hashes for the given file."""
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    hash_sha512 = hashlib.sha512()

    with open(file_path, "rb") as f:
        content = f.read()
        hash_md5.update(content)
        hash_sha1.update(content)
        hash_sha256.update(content)
        hash_sha512.update(content)
    
    return {
        "MD5": hash_md5.hexdigest(),
        "SHA1": hash_sha1.hexdigest(),
        "SHA256": hash_sha256.hexdigest(),
        "SHA512": hash_sha512.hexdigest()
    }

# Load malware signatures
def load_signatures(signature_file):
    """Load malware signatures from file and return as dictionary."""
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

# Function to quarantine malware files
def quarantine(file_path):
    shutil.move(file_path, "quarantine/")
    print(f"File moved to quarantine: {file_path}")
            

# Malware detection function
def detect_malware():
    """Scan files in the TEST_DIR and check against malware signatures."""
    signatures = load_signatures(SIGNATURE_FILE)

    # List of directories to scan
    with open("files_for_quarantine.txt", "w") as file:

        for directory in DIRECTORIES_TO_SCAN:
            # Using os.walk to walk through the directory and subdirectories
            for root, dirs, files in os.walk(directory):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    # Calculate file hashes
                    file_hashes = calculate_hashes(file_path)
                
                    # Compare hashes with signature database
                    for signature in signatures:
                        if (file_hashes["MD5"] == signature["MD5"] and
                            file_hashes["SHA256"] == signature["SHA256"]):
                            print(f"Malware detected in file: {filename}")
                            print(f" - Malware Type: {signature['Malware Type']}")
                            print(f" - Severity Level: {signature['Severity Level']}")
                            print(f" - Infection Date: {signature['Infection Date']}")
                            #quarantine(file_path)
                            logging.info(f"Detected Malware: {file_path}, MD5: {signature['MD5']}, SHA256: {signature['SHA256']} Threat Level: {signature['Severity Level']}, Timestamp: {datetime.now()}")
                            break

def show_file_hashes():
    """Scan files in the TEST_DIR and check against malware signatures."""
    for filename in os.listdir("files/test_files"):
        file_path = os.path.join("files/test_files", filename)
        
        # Calculate file hashes
        file_hashes = calculate_hashes(file_path)
        print(f" {file_path} - MD5: {file_hashes['MD5']}, SHA1:{file_hashes['SHA1']}, SHA256: {file_hashes['SHA256']}, SHA512: {file_hashes['SHA512']}")

# Show hashes for PDF files
show_file_hashes()

# Run the detection
#detect_malware()
