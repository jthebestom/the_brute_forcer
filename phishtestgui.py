import os
import hashlib
import tkinter as tk
from tkinter import messagebox

# File to store user credentials
CREDENTIALS_FILE = "credentials.txt"

# Hash password function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Register function
def register_user(username, password, confirm_password, root):
    if len(username) < 8 or not username.isalnum():
        messagebox.showerror("Error", "Username must be at least 8 characters long and contain only alphanumeric characters.")
        return

    if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password) or not any(char.islower() for char in password):
        messagebox.showerror("Error", "Password must be at least 8 characters long, include one uppercase letter, one lowercase letter, and one digit.")
        return

    if password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match.")
        return

    hashed_password = hash_password(password)

    # Check if username already exists
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as file:
            for line in file:
                stored_username, _ = line.strip().split(":")
                if username == stored_username:
                    messagebox.showerror("Error", "Username already exists.")
                    return

    # Save credentials
    with open(CREDENTIALS_FILE, "a") as file:
        file.write(f"{username}:{hashed_password}\n")

    messagebox.showinfo("Success", "Registration successful!")
    root.destroy()  # Close the registration page

# Login function
def login_user(username, password):
    hashed_password = hash_password(password)

    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as file: 
            for line in file:
                stored_username, stored_password = line.strip().split(":")
                if username == stored_username and hashed_password == stored_password:
                    messagebox.showinfo("Success", f"Welcome, {username}!")
                    return
    messagebox.showerror("Error", "Invalid username or password.")

# Registration page
def open_register_page():
    register_page = tk.Toplevel()
    register_page.title("Register")
    register_page.geometry("400x300")
    register_page.configure(bg="#f3f3f3")

    tk.Label(register_page, text="Register", font=("Arial", 16, "bold"), bg="#f3f3f3").pack(pady=10)

    tk.Label(register_page, text="Username:", bg="#f3f3f3").pack(anchor=tk.W, padx=20)
    reg_username_entry = tk.Entry(register_page, width=30)
    reg_username_entry.pack(padx=20, pady=5)

    tk.Label(register_page, text="Password:", bg="#f3f3f3").pack(anchor=tk.W, padx=20)
    reg_password_entry = tk.Entry(register_page, show="*", width=30)
    reg_password_entry.pack(padx=20, pady=5)

    tk.Label(register_page, text="Confirm Password:", bg="#f3f3f3").pack(anchor=tk.W, padx=20)
    reg_confirm_password_entry = tk.Entry(register_page, show="*", width=30)
    reg_confirm_password_entry.pack(padx=20, pady=5)

    tk.Button(
        register_page,
        text="Register",
        bg="#4CAF50",
        fg="white",
        font=("Arial", 12),
        command=lambda: register_user(
            reg_username_entry.get(), reg_password_entry.get(), reg_confirm_password_entry.get(), register_page
        )
    ).pack(pady=10)

# Login page
def open_login_page():
    root = tk.Tk()
    root.title("Login")
    root.geometry("400x300")
    root.configure(bg="#f3f3f3")

    tk.Label(root, text="Login", font=("Arial", 16, "bold"), bg="#f3f3f3").pack(pady=10)

    tk.Label(root, text="Username:", bg="#f3f3f3").pack(anchor=tk.W, padx=20)
    login_username_entry = tk.Entry(root, width=30)
    login_username_entry.pack(padx=20, pady=5)

    tk.Label(root, text="Password:", bg="#f3f3f3").pack(anchor=tk.W, padx=20)
    login_password_entry = tk.Entry(root, show="*", width=30)
    login_password_entry.pack(padx=20, pady=5)

    tk.Button(
        root,
        text="Login",
        bg="#007BFF",
        fg="white",
        font=("Arial", 12),
        command=lambda: login_user(login_username_entry.get(), login_password_entry.get())
    ).pack(pady=10)

    tk.Label(root, text="Don't have an account?", bg="#f3f3f3").pack(pady=5)
    tk.Button(
        root,
        text="Register Here",
        bg="#f3f3f3",
        fg="blue",
        font=("Arial", 10, "underline"),
        command=open_register_page
    ).pack(pady=5)

    root.mainloop()

# Launch login page
open_login_page()
