import hashlib
import os
import random
import string

# Constants
TEST_DIR = "files/test_files"
NUM_FILES = 20  # Total number of files to generate
MALWARE_FILES = 5  # Number of "malicious" files

# Helper Functions
def generate_random_content(size=50):
    """Generate random binary content for file using os.urandom."""
    return os.urandom(size)

def write_file(path, content):
    """Write binary content to a file at the given path."""
    with open(path, "wb") as f:
        f.write(content)

def compute_hashes(content):
    """Compute MD5 and SHA256 hashes for the content."""
    md5_hash = hashlib.md5(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()
    return md5_hash, sha256_hash

# Function to generate test files
def generate_test_files():
    """Generate test files, some with malware signature hashes as content."""
    if not os.path.exists(TEST_DIR):
        os.makedirs(TEST_DIR)
    
    # Load malware signatures from the file
    with open("malware_signatures.txt", "r") as sig_file:
        signatures = [line.strip().split(" | ")[0] for line in sig_file.readlines()[2:]]  # Get MD5 hashes
    
    for i in range(NUM_FILES):
        file_path = os.path.join(TEST_DIR, f"test_file_{i+1}.bin")

        if i < MALWARE_FILES:
            # Select a malware signature hash (MD5) and use it as content
            malicious_content = bytes.fromhex(random.choice(signatures))
            write_file(file_path, malicious_content)
        else:
            # Generate random binary content
            content = generate_random_content()
            write_file(file_path, content)

        # Compute and print hashes for verification
        with open(file_path, "rb") as f:
            content = f.read()
        md5_hash, sha256_hash = compute_hashes(content)
        print(f"Generated {file_path} - MD5: {md5_hash}, SHA256: {sha256_hash}")

# Run the file generation
generate_test_files()
