import hashlib


def register():
        
    def validate_username(username):
        if len(username) < 8:
            return "Username must be at least 8 characters long."
        if not username.isalnum():
            return "Username must only contain alphanumeric characters."
        common_usernames = ['admin', 'user', 'guest']
        if any(pattern in username.lower() for pattern in common_usernames):
            return "Username is too common."
        return None

    def validate_password(password):
        if len(password) < 8:
            return "Password must be at least 8 characters long."
        if not any(char.isdigit() for char in password):
            return "Password must contain at least one digit."
        if not any(char.isupper() for char in password):
            return "Password must contain at least one uppercase letter."
        if not any(char.islower() for char in password):
            return "Password must contain at least one lowercase letter."
        common_patterns = ['password', '123456', 'qwerty', 'admin', 'user', 'guest']
        if any(pattern in password.lower() for pattern in common_patterns):
            return "Password is too common."
        return None

    while True:
        username = input("Enter Username: ")
        username_error = validate_username(username)
        if username_error:
            print(username_error)
            continue

        password = input("Enter Password: ")
        password_error = validate_password(password)
        if password_error:
            print(password_error)
            continue

        confirm_password = input("Confirm Password: ")
        if password != confirm_password:
            print("Passwords do not match.")
            continue

        # Hash the password and save it
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        with open('passwords.txt', 'a') as file:
            file.write(f'{username}:{hashed_password}\n')

        print("Password saved successfully!")
        break





def login():
    print("=== Login ===")
    while True:
        username = input("Enter Username: ")
        password = input("Enter Password: ")

        # Hash the entered password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Read the stored credentials from the file
        try:
            with open('passwords.txt', 'r') as file:
                credentials = file.readlines()
        except FileNotFoundError:
            print("No registered users found. Please register first.")
            return

        # Check if the username and hashed password match any stored credential
        for line in credentials:
            stored_username, stored_hashed_password = line.strip().split(':')
            if username == stored_username and hashed_password == stored_hashed_password:
                print("Login successful! Welcome.")
                return

        # If no match found
        print("Invalid username or password. Please try again.")

# Example usage

def Exit():
    print("Goodbye!")
    exit()


print('Welcome----------------------------------------------------------------')
print('josky credentals hash bomb')

while True:
    print("\nChoose an option:")
    print("1. Register")
    print("2. Login")
    print("3. Exit")
    choice = input("Enter your choice (1-3): ")
    
    if choice == '1':
        register()
        continue
    elif choice == '2':
        login()
        continue
    elif choice == '3':
        Exit()
        break
    
