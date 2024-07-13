import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import simpledialog
from cryptography.fernet import Fernet

# Constants
BUFFER_SIZE = 1024
FORMAT = "utf-8"

# Load the key
with open("key.key", "rb") as key_file:
    SECRET_KEY = key_file.read()
cipher_suite = Fernet(SECRET_KEY)

# Client Class
class Client:
    def __init__(self, host, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        self.username = ""

        self.gui_done = False
        self.running = True

        gui_thread = threading.Thread(target=self.gui_loop)
        receive_thread = threading.Thread(target=self.receive_message)

        gui_thread.start()
        receive_thread.start()

    def gui_loop(self):
        self.root = tk.Tk()
        self.root.title("Real Time Chat Client")
        self.root.geometry("350x400")  # Adjusted size for fitting 4 clients on screen
        self.root.configure(bg="#2E2E2E")

        self.username = simpledialog.askstring("Username", "Please enter your username:", parent=self.root)
        encrypted_username = cipher_suite.encrypt(self.username.encode(FORMAT))
        self.client_socket.send(encrypted_username)

        self.chat_label = tk.Label(self.root, text="Chat:", bg="#2E2E2E", fg="white")
        self.chat_label.grid(column=0, row=0, padx=10, pady=5)

        self.text_area = scrolledtext.ScrolledText(self.root, state='disabled', bg="#1E1E1E", fg="white", insertbackground="white", width=40, height=10)
        self.text_area.grid(column=0, row=1, padx=10, pady=5)

        self.msg_label = tk.Label(self.root, text="Message:", bg="#2E2E2E", fg="white")
        self.msg_label.grid(column=0, row=2, padx=10, pady=5)

        self.input_area = tk.Text(self.root, height=3, bg="#1E1E1E", fg="white", insertbackground="white", width=30)
        self.input_area.grid(column=0, row=3, padx=10, pady=5)

        self.send_button = tk.Button(self.root, text="Send", command=self.write_message, bg="#4CAF50", fg="white")
        self.send_button.grid(column=0, row=4, padx=10, pady=5)

        self.logout_button = tk.Button(self.root, text="Logout", command=self.stop, bg="#F44336", fg="white")
        self.logout_button.grid(column=0, row=5, padx=10, pady=5)

        self.gui_done = True
        self.root.protocol("WM_DELETE_WINDOW", self.stop)
        self.root.mainloop()

    def write_message(self):
        message = self.input_area.get('1.0', 'end').strip()
        self.input_area.delete('1.0', 'end')

        if message.startswith('@'):
            encrypted_message = cipher_suite.encrypt(message.encode(FORMAT))
            self.client_socket.send(encrypted_message)
        else:
            message = f"{self.username}: {message}"
            encrypted_message = cipher_suite.encrypt(message.encode(FORMAT))
            self.client_socket.send(encrypted_message)

        self.text_area.config(state="normal")
        self.text_area.insert('end', message + "\n")
        self.text_area.yview('end')
        self.text_area.config(state="disabled")

    def stop(self):
        self.running = False
        self.client_socket.close()
        self.root.destroy()

    def receive_message(self):
        while self.running:
            try:
                encrypted_message = self.client_socket.recv(BUFFER_SIZE)
                if encrypted_message:
                    message = cipher_suite.decrypt(encrypted_message).decode(FORMAT)
                    if self.gui_done:
                        if message.startswith("Private message from"):
                            self.text_area.config(state="normal")
                            self.text_area.insert('end', message + "\n")
                            self.text_area.yview('end')
                            self.text_area.config(state="disabled")
                        else:
                            self.text_area.config(state="normal")
                            self.text_area.insert('end', message + "\n")
                            self.text_area.yview('end')
                            self.text_area.config(state="disabled")
            except:
                break

# Connection
host = simpledialog.askstring("IP Address", "Please enter the server IP address:")
port = simpledialog.askinteger("Port", "Please enter the server port:")
client = Client(host, port)
