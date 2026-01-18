import tkinter as tk
from tkinter import messagebox
import re
from database.db_utils import register_user  # Database utility import


class RegistrationPage:
    def __init__(self, root):
        self.root = root
        self.root.title("Register - EncryptSafe Local")
        self.root.geometry("600x600")
        self.root.configure(bg="#FFFFFF")  # White background

        # App Name (Top Left)
        tk.Label(
            root, text="EncryptSafe Local", font=("Helvetica", 18, "bold"), fg="#000000", bg="#FFFFFF"
        ).place(x=10, y=10)

        # Navigate Back Button
        tk.Button(
            root,
            text="←",
            command=self.navigate_back,
            font=("Helvetica", 16, "bold"),
            fg="#000000",
            bg="#FFFFFF",
            borderwidth=0,
        ).place(x=10, y=50)

        # Registration Title
        tk.Label(
            root, text="Create an Account", font=("Helvetica", 20, "bold"), fg="#000000", bg="#FFFFFF"
        ).pack(pady=40)

        # Username Field
        tk.Label(root, text="Username", font=("Helvetica", 14), fg="#000000", bg="#FFFFFF").pack(pady=5)
        self.username_entry = tk.Entry(root, font=("Helvetica", 14), width=30, bg="#F0F0F0", fg="#000000")
        self.username_entry.pack(pady=5)

        # Password Field
        tk.Label(root, text="Password", font=("Helvetica", 14), fg="#000000", bg="#FFFFFF").pack(pady=5)
        self.password_entry = tk.Entry(root, font=("Helvetica", 14), width=30, bg="#F0F0F0", fg="#000000", show="*")
        self.password_entry.pack(pady=5)
        self.password_entry.bind("<KeyRelease>", self.update_password_strength)

        # Password Strength Bar
        self.strength_bar = tk.Frame(root, bg="#DDDDDD", width=300, height=10)
        self.strength_bar.pack(pady=5)
        self.strength_label = tk.Label(root, text="Password Strength", font=("Helvetica", 10), fg="#000000", bg="#FFFFFF")
        self.strength_label.pack(pady=5)

        # Register Button
        tk.Button(
            root,
            text="Register",
            command=self.register,
            font=("Helvetica", 14),
            bg="#4CAF50",
            fg="#FFFFFF",
            activebackground="#388E3C",
            activeforeground="#FFFFFF",
            width=20,
        ).pack(pady=20)

    def update_password_strength(self, event=None):
        """Updates the password strength bar and label based on the password."""
        password = self.password_entry.get()
        strength, color = self.check_password_strength(password)
        self.strength_bar.configure(bg=color)
        self.strength_label.config(text=f"Strength: {strength}")

    def check_password_strength(self, password):
        """
        Checks the strength of the password.
        Returns a tuple of (strength, color).
        """
        if len(password) < 8:
            return "Weak", "#FF0000"
        if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
            return "Moderate", "#FFA500"
        if not re.search(r"\d", password) or not re.search(r"[!@#$%^&*()_+\-={}<>?]"):
            return "Strong", "#FFFF00"
        return "Very Strong", "#00FF00"

    def register(self):
        """Handles user registration."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        # Validate username
        if not username:
            messagebox.showerror("Error", "Username cannot be empty.")
            return

        # Validate password
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long.")
            return

        if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
            messagebox.showerror("Error", "Password must include at least one uppercase and one lowercase letter.")
            return

        if not re.search(r"\d", password) or not re.search(r"[!@#$%^&*()_+\-={}<>?]"):
            messagebox.showerror("Error", "Password must include at least one number and one special character.")
            return

        # Attempt to register the user
        try:
            success = register_user(username, password)

            if success:
                messagebox.showinfo("Success", "Registration successful! You can now log in.")
                self.navigate_back()
            else:
                messagebox.showerror("Error", "Username already exists. Please try another one.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during registration: {e}")

    def navigate_back(self):
        """Navigates back to the login page."""
        self.root.destroy()
        from gui.login_page import LoginPage  # Import here to avoid circular dependencies
        LoginPage(tk.Tk())


if __name__ == "__main__":
    root = tk.Tk()
    RegistrationPage(root)
    root.mainloop()
