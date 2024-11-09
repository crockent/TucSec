import hashlib
import random
import string
from datetime import datetime, timedelta

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

def create_signature_database(filename="malware_signatures.txt", num_entries=50):
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

# Run the function to create the signature database
create_signature_database()
