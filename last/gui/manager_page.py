import tkinter as tk
from tkinter import ttk
from encryption.aes_encryption import encrypt_password, decrypt_password
from database.db_utils import DATABASE_FILE
import sqlite3
import pyotp
import qrcode
from PIL import Image, ImageTk


class PasswordManagerPage:
    def __init__(self, root, username):
        self.root = root
        self.root.title("Password Manager - EncryptSafe Local")
        self.root.attributes('-fullscreen', True)  # Full-screen mode
        self.root.configure(bg="#FFFFFF")  # White background
        self.username = username
        self.password_view_frame = None  # To track the password view section
        self.app_dropdown = None  # To dynamically update the dropdown
        self.google_auth_frame = None  # For Google Authenticator setup
        self.totp = None  # To store the TOTP instance
        self.reveal_key_frame = None  # Frame for entering key to reveal or delete password

        # Create a frame to hold the back button and app name label
        header_frame = tk.Frame(self.root, bg="#FFFFFF")
        header_frame.pack(fill=tk.X)

        # Back Button (Arrow) at top left corner
        self.back_button = tk.Button(
            header_frame, 
            text="←", 
            command=self.back_to_home,
            font=("Helvetica", 16),
            bg="#FFFFFF",
            fg="#000000",
            activebackground="#FFFFFF",
            activeforeground="#000000",
            bd=0
        )
        self.back_button.pack(side=tk.LEFT, padx=10, pady=10)

        # App Name Label (Center)
        self.app_name_label = tk.Label(
            header_frame, text="EncryptSafe Local", font=("Helvetica", 28, "bold"), fg="#000000", bg="#FFFFFF"
        )
        self.app_name_label.pack(side=tk.TOP, pady=10)

        # Add Password Section
        tk.Label(self.root, text="App Name", font=("Helvetica", 14), fg="#000000", bg="#FFFFFF").pack(pady=5)
        self.app_name_entry = tk.Entry(self.root, font=("Helvetica", 14), width=40, bg="#F0F0F0", fg="#000000")
        self.app_name_entry.pack(pady=5)

        tk.Label(self.root, text="Password", font=("Helvetica", 14), fg="#000000", bg="#FFFFFF").pack(pady=5)
        self.password_entry = tk.Entry(self.root, font=("Helvetica", 14), width=40, bg="#F0F0F0", fg="#000000")
        self.password_entry.pack(pady=5)

        tk.Label(self.root, text="Encryption Key", font=("Helvetica", 14), fg="#000000", bg="#FFFFFF").pack(pady=5)
        self.key_entry = tk.Entry(self.root, font=("Helvetica", 14), width=40, bg="#F0F0F0", fg="#000000")
        self.key_entry.pack(pady=5)

        # Buttons Layout (Save Password, Delete All Passwords)
        button_frame = tk.Frame(self.root, bg="#FFFFFF")
        button_frame.pack(pady=10)

        tk.Button(
            button_frame,
            text="Save Password",
            command=self.save_password,
            font=("Helvetica", 14),
            bg="#4CAF50",
            fg="#FFFFFF",
            activebackground="#388E3C",
            activeforeground="#FFFFFF",
            width=20,
        ).pack(side=tk.LEFT, padx=10)

        tk.Button(
            button_frame,
            text="Delete All Passwords",
            command=self.delete_all_passwords,
            font=("Helvetica", 14),
            bg="#F44336",
            fg="#FFFFFF",
            activebackground="#D32F2F",
            activeforeground="#FFFFFF",
            width=20,
        ).pack(side=tk.LEFT, padx=10)

        # View Passwords Section and Set Up Google Authenticator next to each other
        button_frame_2 = tk.Frame(self.root, bg="#FFFFFF")
        button_frame_2.pack(pady=10)

        tk.Button(
            button_frame_2,
            text="View Saved Passwords",
            command=self.view_passwords,
            font=("Helvetica", 14),
            bg="#03A9F4",
            fg="#FFFFFF",
            activebackground="#0288D1",
            activeforeground="#FFFFFF",
            width=20,
        ).pack(side=tk.LEFT, padx=10)

        tk.Button(
            button_frame_2,
            text="Set Up Google Authenticator",
            command=self.setup_google_authenticator,
            font=("Helvetica", 14),
            bg="#FF9800",
            fg="#FFFFFF",
            activebackground="#F57C00",
            activeforeground="#FFFFFF",
            width=25,
        ).pack(side=tk.LEFT, padx=10)

        # Logout Button
        tk.Button(
            self.root,
            text="Logout",
            command=self.logout,
            font=("Helvetica", 14),
            bg="#F44336",
            fg="#FFFFFF",
            activebackground="#D32F2F",
            activeforeground="#FFFFFF",
            width=20,
        ).pack(pady=10)

        # Label to display decrypted password or actions
        self.message_label = tk.Label(self.root, text="", font=("Helvetica", 14), fg="#000000", bg="#FFFFFF")
        self.message_label.pack(pady=10)

    def back_to_home(self):
        """Navigates back to the home page or performs an action."""
        self.root.destroy()  # Destroy the current window to go back to the home page or login page

    def save_password(self):
        self.clear_current_section()  # Clear the current section when switching to another action
        app_name = self.app_name_entry.get().strip()
        password = self.password_entry.get().strip()
        key = self.key_entry.get().strip()

        if not app_name or not password or not key:
            self.show_message("Error: All fields are required!", "#FF0000")
            return

        try:
            encrypted_password = encrypt_password(password, key)

            connection = sqlite3.connect(DATABASE_FILE)
            cursor = connection.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (self.username,))
            user_id = cursor.fetchone()[0]

            cursor.execute(
                "INSERT INTO passwords (user_id, app_name, encrypted_password) VALUES (?, ?, ?)",
                (user_id, app_name, encrypted_password),
            )
            connection.commit()
            connection.close()

            self.show_message("Password saved successfully!", "#4CAF50")
            self.app_name_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.key_entry.delete(0, tk.END)

            # Update the dropdown dynamically
            if self.password_view_frame and self.app_dropdown:
                current_values = list(self.app_dropdown['values'])
                current_values.append(app_name)
                self.app_dropdown['values'] = current_values

            # Hide the Google Authenticator setup frame if it exists
            if self.google_auth_frame:
                self.google_auth_frame.destroy()

        except Exception as e:
            self.show_message(f"Error saving password: {e}", "#FF0000")

    def delete_all_passwords(self):
        self.clear_current_section()  # Clear the current section when switching to another action
        """Deletes all passwords for the logged-in user.""" 
        try:
            # Connect to the database
            connection = sqlite3.connect(DATABASE_FILE)
            cursor = connection.cursor()

            # Get the user ID based on the username
            cursor.execute("SELECT id FROM users WHERE username = ?", (self.username,))
            user_id = cursor.fetchone()

            if user_id is None:
                self.show_message("Error: User not found", "#FF0000")
                return

            user_id = user_id[0]

            # Perform the delete operation for all passwords of the user
            cursor.execute(
                "DELETE FROM passwords WHERE user_id = ?",
                (user_id, ),
            )
            connection.commit()
            connection.close()

            # Show success message
            self.show_message("All passwords deleted successfully!", "#4CAF50")

            # Update the dropdown dynamically (if view section exists)
            if self.password_view_frame and self.app_dropdown:
                self.app_dropdown['values'] = []
                self.selected_app.set("")  # Reset the selected app dropdown

        except Exception as e:
            self.show_message(f"Error deleting passwords: {e}", "#FF0000")

    def setup_google_authenticator(self):
        self.clear_current_section()  # Clear the current section when switching to another action
        """Sets up Google Authenticator.""" 
        if self.google_auth_frame:
            return  # Avoid recreating the frame if it already exists

        self.google_auth_frame = tk.Frame(self.root, bg="#FFFFFF")
        self.google_auth_frame.pack(pady=10)

        secret = pyotp.random_base32()
        self.totp = pyotp.TOTP(secret)
        auth_url = self.totp.provisioning_uri(name=self.username, issuer_name="EncryptSafe Local")

        qr = qrcode.make(auth_url)
        
        # Resize the QR code to fit within the available space
        qr_size = 200  # You can adjust this size as needed
        qr = qr.resize((qr_size, qr_size), Image.Resampling.LANCZOS)
        
        qr_img = ImageTk.PhotoImage(qr)
        qr_label = tk.Label(self.google_auth_frame, image=qr_img, bg="#FFFFFF")
        qr_label.image = qr_img  # Keep a reference to avoid garbage collection
        qr_label.pack(pady=10)

        tk.Label(self.google_auth_frame, text="Scan the QR code with Google Authenticator.", font=("Helvetica", 14), fg="#000000", bg="#FFFFFF").pack(pady=10)

        self.show_message("Scan QR code in Google Authenticator app.", "#4CAF50")

    def view_passwords(self):
        """View the list of saved passwords and display the entry key.""" 
        self.clear_current_section()  # Clear the current section when switching to another action
        self.password_view_frame = tk.Frame(self.root, bg="#FFFFFF")
        self.password_view_frame.pack(pady=10)

        try:
            connection = sqlite3.connect(DATABASE_FILE)
            cursor = connection.cursor()

            cursor.execute(
                "SELECT app_name FROM passwords WHERE user_id = (SELECT id FROM users WHERE username = ?)",
                (self.username,)
            )
            app_names = cursor.fetchall()
            connection.close()

            if not app_names:
                self.show_message("No saved passwords found.", "#FF0000")
                return

            app_names = [app[0] for app in app_names]

            self.selected_app = ttk.Combobox(self.password_view_frame, values=app_names, font=("Helvetica", 14), width=40)
            self.selected_app.set("Select an app")
            self.selected_app.pack(pady=5)

            tk.Button(
                self.password_view_frame,
                text="View Password",
                command=self.view_password,
                font=("Helvetica", 14),
                bg="#03A9F4",
                fg="#FFFFFF",
                activebackground="#0288D1",
                activeforeground="#FFFFFF",
                width=20,
            ).pack(pady=10)

        except Exception as e:
            self.show_message(f"Error retrieving passwords: {e}", "#FF0000")

    def view_password(self):
        self.clear_current_section()  # Clear the current section when switching to another action
        self.password_view_frame = tk.Frame(self.root, bg="#FFFFFF")
        self.password_view_frame.pack(pady=10)

        try:
            connection = sqlite3.connect(DATABASE_FILE)
            cursor = connection.cursor()
            cursor.execute(
                "SELECT app_name FROM passwords WHERE user_id = (SELECT id FROM users WHERE username = ?)",
                (self.username,)
            )
            app_names = cursor.fetchall()
            connection.close()

            if not app_names:
                self.show_message("No saved passwords found.", "#FF0000")
                return

            app_names = [app[0] for app in app_names]
            self.selected_app = ttk.Combobox(self.password_view_frame, values=app_names, font=("Helvetica", 14), width=40)
            self.selected_app.set("Select an app")
            self.selected_app.pack(pady=5)

            tk.Button(
                self.password_view_frame,
                text="View Password",
                command=self.view_password_input,
                font=("Helvetica", 14),
                bg="#03A9F4",
                fg="#FFFFFF",
                activebackground="#0288D1",
                activeforeground="#FFFFFF",
                width=20,
            ).pack(pady=10)

        except Exception as e:
            self.show_message(f"Error retrieving passwords: {e}", "#FF0000")

    def view_password_input(self):
        """Display inputs for Encryption Key and TOTP verification."""
        if self.reveal_key_frame:
            self.reveal_key_frame.destroy()

        self.reveal_key_frame = tk.Frame(self.password_view_frame, bg="#FFFFFF")
        self.reveal_key_frame.pack(pady=10)

        # Encryption Key Input
        tk.Label(self.reveal_key_frame, text="Enter Encryption Key", font=("Helvetica", 14), fg="#000000", bg="#FFFFFF").pack(pady=5)
        self.key_entry_view = tk.Entry(self.reveal_key_frame, font=("Helvetica", 14), width=40, bg="#F0F0F0", fg="#000000")
        self.key_entry_view.pack(pady=5)

        # TOTP Input
        tk.Label(self.reveal_key_frame, text="Enter Google Authenticator Code", font=("Helvetica", 14), fg="#000000", bg="#FFFFFF").pack(pady=5)
        self.totp_entry = tk.Entry(self.reveal_key_frame, font=("Helvetica", 14), width=40, bg="#F0F0F0", fg="#000000")
        self.totp_entry.pack(pady=5)

        # Button for TOTP Validation
        tk.Button(
            self.reveal_key_frame,
            text="Verify and View Password",
            command=self.verify_totp_and_show_password,
            font=("Helvetica", 14),
            bg="#4CAF50",
            fg="#FFFFFF",
            activebackground="#388E3C",
            activeforeground="#FFFFFF",
            width=20,
        ).pack(pady=10)

    def verify_totp_and_show_password(self):
        """Verify TOTP and decrypt the password if valid."""
        app_name = self.selected_app.get().strip()
        key = self.key_entry_view.get().strip()
        totp_code = self.totp_entry.get().strip()

        if not key or not totp_code:
            self.show_message("Please enter both the encryption key and TOTP.", "#FF0000")
            return

        if not self.totp.verify(totp_code):
            self.show_message("Invalid Google Authenticator code.", "#FF0000")
            return

        self.show_decrypted_password(app_name)

    def show_decrypted_password(self, app_name):
        """Decrypt and show the password using the key entered by the user.""" 
        key = self.key_entry_view.get().strip()

        if not key:
            self.show_message("Please enter the encryption key.", "#FF0000")
            return

        try:
            connection = sqlite3.connect(DATABASE_FILE)
            cursor = connection.cursor()

            cursor.execute(
                "SELECT encrypted_password FROM passwords WHERE app_name = ? AND user_id = (SELECT id FROM users WHERE username = ?)",
                (app_name, self.username),
            )
            result = cursor.fetchone()

            if result is None:
                self.show_message("Password not found for this app.", "#FF0000")
                return

            encrypted_password = result[0]
            decrypted_password = decrypt_password(encrypted_password, key)
            self.show_message(f"Decrypted Password: {decrypted_password}", "#000000")

            # Add delete password functionality next to the password entry
            self.delete_button = tk.Button(
                self.reveal_key_frame,
                text="Delete Password",
                command=lambda: self.delete_password(app_name),
                font=("Helvetica", 14),
                bg="#F44336",
                fg="#FFFFFF",
                activebackground="#D32F2F",
                activeforeground="#FFFFFF",
                width=20,
            )
            self.delete_button.pack()

            connection.close()

        except Exception as e:
            self.show_message(f"Error decrypting password: {e}", "#FF0000")

    def delete_password(self, app_name):
        """Deletes the selected password from the database."""
        try:
            connection = sqlite3.connect(DATABASE_FILE)
            cursor = connection.cursor()

            cursor.execute(
                "DELETE FROM passwords WHERE app_name = ? AND user_id = (SELECT id FROM users WHERE username = ?)",
                (app_name, self.username),
            )
            connection.commit()
            connection.close()

            self.show_message(f"Password for {app_name} deleted successfully.", "#4CAF50")

            # Update the dropdown dynamically
            if self.password_view_frame and self.app_dropdown:
                current_values = list(self.app_dropdown['values'])
                current_values.remove(app_name)
                self.app_dropdown['values'] = current_values

            # Reset the view after password deletion
            self.clear_current_section()

        except Exception as e:
            self.show_message(f"Error deleting password: {e}", "#FF0000")

    def show_message(self, message, color):
        """Displays messages with a specific color.""" 
        self.message_label.config(text=message, fg=color)

    def clear_current_section(self):
        """Clears the current section's contents.""" 
        if self.password_view_frame:
            self.password_view_frame.destroy()
        if self.google_auth_frame:
            self.google_auth_frame.destroy()

    def logout(self):
        """Logs out and exits the application.""" 
        self.root.quit()