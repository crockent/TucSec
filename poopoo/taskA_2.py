import hashlib
import os

# Constants
#TEST_DIR = "files/test_files"
TEST_DIR = "files/sample_pdfs"
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

# Malware detection function
def detect_malware():
    """Scan files in the TEST_DIR and check against malware signatures."""
    signatures = load_signatures(SIGNATURE_FILE)

    print(f"Scanning files in directory: {TEST_DIR}\n")
    for filename in os.listdir(TEST_DIR):
        file_path = os.path.join(TEST_DIR, filename)
        
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
                break

# Run the detection
detect_malware()
