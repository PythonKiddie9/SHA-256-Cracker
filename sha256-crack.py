import sys
import hashlib  # Importing hashlib for SHA-256 hashing

# Function to compute SHA-256 hash in hexadecimal format
def sha256sumhex(data):
    hash_object = hashlib.sha256()
    hash_object.update(data)
    return hash_object.hexdigest()

# Checking if exactly one command-line argument is provided
if len(sys.argv) != 2:
    print("Invalid arguments!")
    print("Usage: {} <sha256sum>".format(sys.argv[0]))
    exit()

# Extracting the SHA-256 hash value provided as a command-line argument
wanted_hash = sys.argv[1]
password_file = "rockyou.txt"  # Assuming this file contains a list of passwords
attempts = 0

# Simulating a progress logger with a context manager, assuming it's a custom implementation
# Replace with appropriate logging or print statements for clarity
print("Attempting to crack hash: {}!".format(wanted_hash))

# Opening the password file for reading, assuming it's encoded in latin-1
with open(password_file, "r", encoding='latin-1') as password_list:
    for password in password_list:
        password = password.strip('\n').encode('latin-1')  # Removing newline and encoding to latin-1
        password_hash = sha256sumhex(password)  # Calculating SHA-256 hash of the password

        # Logging the attempt number, password decoded from latin-1, and its hash
        print("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))

        # Checking if the calculated hash matches the desired hash
        if password_hash == wanted_hash:
            # If match found, print success message and exit
            print("Password hash found after {} attempts: {} hashes to {}".format(attempts, password.decode('latin-1'), password_hash))
            exit()

        attempts += 1  # Incrementing attempts counter for each password checked

# If no match found after checking all passwords
print("Password hash not found!")
