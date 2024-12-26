import hashlib

def validate_password(username, password):
    # Hash the entered password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    try:
        # Read stored credentials
        with open('passwords.txt', 'r') as file:
            credentials = file.readlines()

        # Check if username and password match
        for line in credentials:
            stored_username, stored_hashed_password = line.strip().split(':')
            if username == stored_username:
                if hashed_password == stored_hashed_password:
                    return True
                else:
                    return False
        return False  # Username not found

    except FileNotFoundError:
        print("No saved credentials found.")
        return False


# Main program to validate a username-password pair
def main():
    print("=== Password Validator ===")
    username = input("Enter Username: ")
    password = input("Enter Password: ")

    if validate_password(username, password):
        print("Password is valid!")
    else:
        print("Invalid username or password!")


if __name__ == "__main__":
    main()
