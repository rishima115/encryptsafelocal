import tkinter as tk
from tkinter import messagebox
import re
from database.db_utils import register_user  # Ensure this path matches your project structure


class RegistrationPage:
    def __init__(self, root):
        self.root = root
        self.root.title("Register - EncryptSafe Local")
        self.root.attributes("-fullscreen", True)  # Enable full-screen mode
        self.root.configure(bg="#FFFFFF")  # White background

        # Close button for exiting full-screen
        close_button = tk.Button(
            root,
            text="X",
            command=self.exit_fullscreen,
            font=("Helvetica", 14, "bold"),
            bg="#F44336",
            fg="#FFFFFF",
            activebackground="#D32F2F",
            activeforeground="#FFFFFF",
            width=3,
            bd=0
        )
        close_button.place(x=10, y=10)

        # Application Name (Centered)
        tk.Label(
            root, text="EncryptSafe Local", font=("Helvetica", 36, "bold"), fg="#000000", bg="#FFFFFF"
        ).pack(pady=20)

        # Navigate Back Button (Large Arrow)
        tk.Button(
            root,
            text="←",
            command=self.navigate_back,
            font=("Helvetica", 24, "bold"),
            fg="#000000",
            bg="#FFFFFF",
            borderwidth=0,
        ).place(x=20, y=60)

        # Registration Title
        tk.Label(
            root, text="Create an Account", font=("Helvetica", 32, "bold"), fg="#000000", bg="#FFFFFF"
        ).pack(pady=20)

        # Username Field
        tk.Label(root, text="Username", font=("Helvetica", 20), fg="#000000", bg="#FFFFFF").pack(pady=5)
        self.username_entry = tk.Entry(root, font=("Helvetica", 18), width=40, bg="#F0F0F0", fg="#000000")
        self.username_entry.pack(pady=5)

        # Password Field
        tk.Label(root, text="Password", font=("Helvetica", 20), fg="#000000", bg="#FFFFFF").pack(pady=5)
        self.password_entry = tk.Entry(root, font=("Helvetica", 18), width=40, bg="#F0F0F0", fg="#000000", show="*")
        self.password_entry.pack(pady=5)
        self.password_entry.bind("<KeyRelease>", self.update_password_strength)

        # Show Password Checkbox
        self.show_password_var = tk.IntVar()
        self.show_password_checkbox = tk.Checkbutton(
            root,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            font=("Helvetica", 16),
            bg="#FFFFFF",
            fg="#000000",
            activebackground="#FFFFFF",
            activeforeground="#000000",
        )
        self.show_password_checkbox.pack(pady=5)

        # Password Rules
        password_rules = (
            "Password must include:\n"
            "- At least 8 characters\n"
            "- One uppercase and one lowercase letter\n"
            "- One number\n"
            "- One special character (!@#$%^&*()_+)"
        )
        tk.Label(
            root, text=password_rules, font=("Helvetica", 14), fg="#000000", bg="#FFFFFF", justify="left"
        ).pack(pady=10)

        # Password Strength Bar
        self.strength_bar = tk.Frame(root, bg="#DDDDDD", width=300, height=10)
        self.strength_bar.pack(pady=5)
        self.strength_label = tk.Label(root, text="Password Strength", font=("Helvetica", 14), fg="#000000", bg="#FFFFFF")
        self.strength_label.pack(pady=5)

        # Register Button
        tk.Button(
            root,
            text="Register",
            command=self.register,
            font=("Helvetica", 18, "bold"),
            bg="#4CAF50",
            fg="#FFFFFF",
            activebackground="#388E3C",
            activeforeground="#FFFFFF",
            width=20,
        ).pack(pady=20)

        # Success/Error Message Label (Hidden Initially)
        self.message_label = tk.Label(root, text="", font=("Helvetica", 16), fg="#000000", bg="#FFFFFF")
        self.message_label.pack(pady=10)

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

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
            return "Weak", "#FF0000"  # Red for weak passwords
        if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
            return "Moderate", "#FFA500"  # Orange for moderate
        if not re.search(r"\d", password) or not re.search(r"[!@#$%^&*()_+\-={}<>?]", password):
            return "Strong", "#FFFF00"  # Yellow for strong
        return "Very Strong", "#00FF00"  # Green for very strong

    def register(self):
        """Handles user registration."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        # Validate username
        if not username:
            self.message_label.config(text="Error: Username cannot be empty.", fg="#FF0000")
            return

        # Validate password
        if len(password) < 8:
            self.message_label.config(text="Error: Password must be at least 8 characters long.", fg="#FF0000")
            return

        if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
            self.message_label.config(
                text="Error: Password must include at least one uppercase and one lowercase letter.", fg="#FF0000"
            )
            return

        if not re.search(r"\d", password) or not re.search(r"[!@#$%^&*()_+\-={}<>?]", password):
            self.message_label.config(
                text="Error: Password must include at least one number and one special character.", fg="#FF0000"
            )
            return

        # Attempt to register the user
        try:
            success = register_user(username, password)

            if success:
                self.message_label.config(text="Registration successful! Redirecting...", fg="#00FF00")
                self.root.after(2000, self.navigate_back)  # Redirect after 2 seconds
            else:
                self.message_label.config(text="Error: Username already exists. Please try another one.", fg="#FF0000")
        except Exception as e:
            self.message_label.config(text=f"Error: An error occurred during registration: {e}", fg="#FF0000")

    def navigate_back(self):
        """Navigates back to the login page."""
        self.root.destroy()
        from gui.login_page import LoginPage  # Import here to avoid circular dependencies
        LoginPage(tk.Tk())

    def exit_fullscreen(self):
        self.root.attributes("-fullscreen", False)


# Run this code if executing the file directly
if __name__ == "__main__":
    root = tk.Tk()
    RegistrationPage(root)
    root.mainloop()
