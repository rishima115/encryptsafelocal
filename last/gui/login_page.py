# gui/login_page.py
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../database')))

import tkinter as tk
from database.db_utils import authenticate_user


class LoginPage:
    def __init__(self, root):
        self.root = root
        self.root.title("Login - EncryptSafe Local")
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

        # Frame for Center Alignment
        main_frame = tk.Frame(root, bg="#FFFFFF")
        main_frame.place(relx=0.5, rely=0.5, anchor="center")  # Center the frame

        # App Name Label (Top Center)
        tk.Label(
            main_frame, text="EncryptSafe Local", font=("Helvetica", 36, "bold"), fg="#000000", bg="#FFFFFF"
        ).pack(pady=20)

        # Title Label
        tk.Label(
            main_frame, text="Login", font=("Helvetica", 32, "bold"), fg="#000000", bg="#FFFFFF"
        ).pack(pady=20)

        # Username Label and Entry
        tk.Label(
            main_frame, text="Username", font=("Helvetica", 20), fg="#000000", bg="#FFFFFF"
        ).pack(pady=10)
        self.username_entry = tk.Entry(
            main_frame, font=("Helvetica", 18), width=40, bg="#F0F0F0", fg="#000000"
        )
        self.username_entry.pack(pady=5)

        # Password Label and Entry
        tk.Label(
            main_frame, text="Password", font=("Helvetica", 20), fg="#000000", bg="#FFFFFF"
        ).pack(pady=10)
        self.password_entry = tk.Entry(
            main_frame, show="*", font=("Helvetica", 18), width=40, bg="#F0F0F0", fg="#000000"
        )
        self.password_entry.pack(pady=5)

        # Show Password Checkbox
        self.show_password_var = tk.IntVar()
        self.show_password_checkbox = tk.Checkbutton(
            main_frame,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            font=("Helvetica", 16),
            bg="#FFFFFF",
            fg="#000000",
            activebackground="#FFFFFF",
            activeforeground="#000000",
        )
        self.show_password_checkbox.pack(pady=10)

        # Login Button
        tk.Button(
            main_frame,
            text="Login",
            command=self.login_user,
            font=("Helvetica", 18, "bold"),
            bg="#4CAF50",
            fg="#FFFFFF",
            activebackground="#388E3C",
            activeforeground="#FFFFFF",
            width=20,
        ).pack(pady=30)

        # Error Message Label (Hidden Initially)
        self.error_label = tk.Label(
            main_frame, text="", font=("Helvetica", 16), fg="#FF0000", bg="#FFFFFF"
        )
        self.error_label.pack()

        # Navigate to Registration Page
        tk.Label(
            main_frame,
            text="Don't have an account?",
            font=("Helvetica", 16),
            fg="#000000",
            bg="#FFFFFF",
        ).pack(pady=10)
        tk.Button(
            main_frame,
            text="Sign Up",
            command=self.navigate_to_signup,
            font=("Helvetica", 16, "bold"),
            bg="#03A9F4",
            fg="#FFFFFF",
            activebackground="#0288D1",
            activeforeground="#FFFFFF",
            width=15,
        ).pack(pady=5)

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def login_user(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if len(username) == 0 or len(password) == 0:
            self.error_label.config(text="Both fields are required!")
            return

        if authenticate_user(username, password):
            self.root.destroy()
            from gui.manager_page import PasswordManagerPage
            PasswordManagerPage(tk.Tk(), username)
        else:
            self.error_label.config(text="Invalid username or password!")
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)

    def navigate_to_signup(self):
        self.root.destroy()
        from gui.registration_page import RegistrationPage
        RegistrationPage(tk.Tk())

    def exit_fullscreen(self):
        self.root.attributes("-fullscreen", False)


if __name__ == "__main__":
    root = tk.Tk()
    LoginPage(root)
    root.mainloop()
