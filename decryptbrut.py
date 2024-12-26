import hashlib

def brute_force_decrypt(hash_to_crack, dictionary_file):
    try:
        with open(dictionary_file, 'r') as file:
            passwords = file.readlines()

        for password in passwords:
            password = password.strip()
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if hashed_password == hash_to_crack:
                return password  

        return None  

    except FileNotFoundError:
        print(f"Dictionary file '{dictionary_file}' not found.")
        return None



def main():
    print("=== Hash Cracker ===")
    hash_to_crack = input("Enter SHA-256 hash to decrypt: ")
    dictionary_file = input("Enter dictionary file path: ")

    result = brute_force_decrypt(hash_to_crack, dictionary_file)
    if result:
        print(f"Password found: {result}")
    else:
        print("Password could not be cracked.")

if __name__ == "__main__":
    main()




