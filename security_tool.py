from cryptography.fernet import Fernet
import hashlib
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(os.path.dirname(BASE_DIR), "encryption.key")

INPUT_FILE = "student_record.txt"
ENCRYPTED_FILE = "student_record.enc"
DECRYPTED_FILE = "student_record_decrypted.txt"


def generate_key():
    """Generate an encryption key if one does not already exist."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()

        with open(KEY_FILE, "wb") as file:
            file.write(key)

        print("Encryption key generated successfully.")
    else:
        print("Encryption key already exists.")


def load_key():
    """Load the encryption key."""
    if not os.path.exists(KEY_FILE):
        print("Error: Encryption key not found.")
        print("Run: python security_tool.py key")
        return None

    with open(KEY_FILE, "rb") as file:
        return file.read()


def encrypt_file():
    """Encrypt the student record file."""
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found.")
        return

    key = load_key()

    if key is None:
        return

    try:
        fernet = Fernet(key)

        with open(INPUT_FILE, "rb") as file:
            data = file.read()

        encrypted_data = fernet.encrypt(data)

        with open(ENCRYPTED_FILE, "wb") as file:
            file.write(encrypted_data)

        print("Encryption successful.")
        print(f"Encrypted file created: {ENCRYPTED_FILE}")

    except Exception as error:
        print(f"Encryption error: {error}")


def decrypt_file():
    """Decrypt the encrypted student record."""
    if not os.path.exists(ENCRYPTED_FILE):
        print(f"Error: {ENCRYPTED_FILE} not found.")
        return

    key = load_key()

    if key is None:
        return

    try:
        fernet = Fernet(key)

        with open(ENCRYPTED_FILE, "rb") as file:
            encrypted_data = file.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        with open(DECRYPTED_FILE, "wb") as file:
            file.write(decrypted_data)

        print("Decryption successful.")
        print(f"Decrypted file created: {DECRYPTED_FILE}")

        # Verify that decrypted data matches original
        with open(INPUT_FILE, "rb") as original_file:
            original_data = original_file.read()

        if decrypted_data == original_data:
            print("Verification successful: decrypted file matches original.")
        else:
            print("WARNING: decrypted file does not match original.")

    except Exception as error:
        print(f"Decryption error: {error}")


def calculate_hash(filename):
    """Calculate SHA-256 hash of a file."""
    if not os.path.exists(filename):
        print(f"Error: {filename} not found.")
        return

    try:
        sha256 = hashlib.sha256()

        with open(filename, "rb") as file:
            while True:
                data = file.read(4096)

                if not data:
                    break

                sha256.update(data)

        print(f"SHA-256 hash of {filename}:")
        print(sha256.hexdigest())

    except Exception as error:
        print(f"Hashing error: {error}")


def verify_integrity():
    """Compare the original file with a saved hash."""
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found.")
        return

    current_hash = hashlib.sha256()

    with open(INPUT_FILE, "rb") as file:
        while True:
            data = file.read(4096)

            if not data:
                break

            current_hash.update(data)

    print("Current SHA-256 hash:")
    print(current_hash.hexdigest())


def show_help():
    print("\nCryptography Security Toolkit")
    print("-----------------------------")
    print("Commands:")
    print("  key       Generate encryption key")
    print("  encrypt   Encrypt student record")
    print("  decrypt   Decrypt student record")
    print("  hash      Calculate SHA-256 hash")
    print("  verify    Check current file integrity")
    print("  help      Show this help message")


def main():

    if len(sys.argv) < 2:
        show_help()
        return

    command = sys.argv[1].lower()

    if command == "key":
        generate_key()

    elif command == "encrypt":
        encrypt_file()

    elif command == "decrypt":
        decrypt_file()

    elif command == "hash":
        calculate_hash(INPUT_FILE)

    elif command == "verify":
        verify_integrity()

    elif command == "help":
        show_help()

    else:
        print(f"Error: Invalid command '{command}'.")
        show_help()


if __name__ == "__main__":
    main()