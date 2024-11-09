import argparse
import hashlib
import os
import random
import shutil
import string
from datetime import datetime, timedelta

# Constants
DIRECTORIES_TO_SCAN = ["files/test_files", "files/sample_pdfs"]
TEST_DIR = "files/test_files"
PDF_DIR = "files/sample_pdfs"
NUM_FILES = 15  # Total number of files to generate
MALWARE_FILE_PATH = "MALWARE"  # Path to a known malware file
SIGNATURE_FILE = "malware_signatures.txt"

## Task A_1: Signature Database Creation ##
def generate_random_string(length=10):
    """Generate a random string of fixed length"""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def compute_hashes(data):
    """Compute MD5 and SHA256 hashes for given data"""
    md5_hash = hashlib.md5(data.encode()).hexdigest()
    sha256_hash = hashlib.sha256(data.encode()).hexdigest()
    return md5_hash, sha256_hash

def generate_random_date(start_date="2022-01-01", end_date="2024-12-31"):
    """Generate a random date between start_date and end_date"""
    start_dt = datetime.strptime(start_date, "%Y-%m-%d")
    end_dt = datetime.strptime(end_date, "%Y-%m-%d")
    random_date = start_dt + timedelta(days=random.randint(0, (end_dt - start_dt).days))
    return random_date.strftime("%Y-%m-%d")

def create_database(filename=SIGNATURE_FILE, num_entries=50):
    """Create a signature database with random entries following the specified format"""
    malware_types = ["Worm", "Virus", "Spyware", "Ransomware"]
    severity_levels = ["Low", "Medium", "High", "Critical"]

    with open(filename, "w") as file:
        file.write("MD5 Hash | SHA256 Hash | Malware Type | Infection Date | Severity Level\n")
        file.write("-------------------------------------------------------------------------------------\n")

        for _ in range(num_entries):
            data = generate_random_string(random.randint(8, 15))
            md5_hash, sha256_hash = compute_hashes(data)
            malware_type = random.choice(malware_types)
            infection_date = generate_random_date()
            severity_level = random.choice(severity_levels)
            
            # Write the entry in the specified format
            file.write(f"{md5_hash} | {sha256_hash} | {malware_type} | {infection_date} | {severity_level}\n")

    print(f"Signature database '{filename}' created with {num_entries} entries.")

## Task A_2: Malware detection ##

def generate_random_content(size=50):
    """Generate random binary content for file using os.urandom."""
    return os.urandom(size)

def write_file(path, content):
    """Write binary content to a file at the given path."""
    with open(path, "wb") as f:
        f.write(content)

def compute_hashes(data):
    """Compute MD5 and SHA256 hashes for given data (ensure it's in bytes)"""
    # Ensure the input data is in bytes
    if isinstance(data, str):
        data = data.encode()  # Encode string to bytes if it's not already

    md5_hash = hashlib.md5(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()
    return md5_hash, sha256_hash


# Function to generate test files
def create_test_files():
    """Generate test files, some with malware signature hashes as content."""
    if not os.path.exists(TEST_DIR):
        os.makedirs(TEST_DIR)
    
    # Load malware signatures from the file
    with open(SIGNATURE_FILE, "r") as sig_file:
        signatures = [line.strip().split(" | ")[0] for line in sig_file.readlines()[2:]]  # Get MD5 hashes

    for i in range(NUM_FILES):
        file_path = os.path.join(TEST_DIR, f"test_file_{i+1}.txt")

        # Generate random binary content
        content = generate_random_content()
        write_file(file_path, content)

        # Compute and print hashes for verification
        with open(file_path, "rb") as f:
            content = f.read()
        md5_hash, sha256_hash = compute_hashes(content)
        print(f"Generated {file_path} - MD5: {md5_hash}, SHA256: {sha256_hash}")

    # Copy the malware file to the test directory
    shutil.copytree(MALWARE_FILE_PATH, TEST_DIR, dirs_exist_ok=True)
    print(f"Created 5 malware files in '{TEST_DIR}'.")

    # Now, compute and write hashes for the malware files
    malware_files = [f for f in os.listdir(MALWARE_FILE_PATH) if os.path.isfile(os.path.join(MALWARE_FILE_PATH, f))]
    
    with open(SIGNATURE_FILE, "a") as sig_file:
        malware_types = ["Worm", "Virus", "Spyware", "Ransomware"]
        severity_levels = ["Low", "Medium", "High", "Critical"]
        
        for malware_file in malware_files:
            malware_file_path = os.path.join(TEST_DIR, malware_file)
            with open(malware_file_path, "rb") as f:
                content = f.read()
            md5_hash, sha256_hash = compute_hashes(content)
            malware_type = random.choice(malware_types)
            infection_date = generate_random_date()
            severity_level = random.choice(severity_levels)

            # Write the malware file's signature to the database
            sig_file.write(f"{md5_hash} | {sha256_hash} | {malware_type} | {infection_date} | {severity_level}\n")
            print(f"Malware file {malware_file} - MD5: {md5_hash}, SHA256: {sha256_hash} written to database.")

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

# Malware detection function
def detect_malware():
    """Scan files in the TEST_DIR and check against malware signatures."""
    signatures = load_signatures(SIGNATURE_FILE)

    # Scan only the TEST_DIR for files
    for filename in os.listdir(TEST_DIR):
        file_path = os.path.join(TEST_DIR, filename)
        
        # Ensure we're processing only files, not directories
        if os.path.isfile(file_path):
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

## Task A_3: Multi-Hash Validation
def show_pdf_hashes():
    for filename in os.listdir(PDF_DIR):
        file_path = os.path.join(PDF_DIR, filename)
        
        # Calculate file hashes
        file_hashes = calculate_hashes(file_path)
        print(f" {file_path} - MD5: {file_hashes['MD5']}, SHA1:{file_hashes['SHA1']}, SHA256: {file_hashes['SHA256']}, SHA512: {file_hashes['SHA512']}")

# Run the function to create the signature database
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run specific functions from the script.")
    parser.add_argument("--function", type=str, required=True, help="")
    args = parser.parse_args()

    # Map function names to actual functions
    functions = {
        "create_database": create_database,
        "create_test_files": create_test_files,
        "detect_malware": detect_malware,
        "show_pdf_hashes": show_pdf_hashes
    }

    if args.function in functions:
        functions[args.function]()
    else:
        print("Function not recognized. Please choose from:", ", ".join(functions.keys()))
