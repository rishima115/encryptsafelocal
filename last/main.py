from database.setup import setup_database
from gui.login_page import LoginPage
import tkinter as tk

if __name__ == "__main__":
    setup_database()  # Initialize the database on first run
    root = tk.Tk()
    LoginPage(root)  # Launch the login page
    root.mainloop()
