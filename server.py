import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from cryptography.fernet import Fernet

# Constants
HOST = '127.0.0.1'
PORT = 4457
BUFFER_SIZE = 1024
FORMAT = "utf-8"

# Load the key
with open("key.key", "rb") as key_file:
    SECRET_KEY = key_file.read()
cipher_suite = Fernet(SECRET_KEY)

# Global variables
clients = {}
usernames = {}

# Server GUI
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    def handle_client(client, address):
        while True:
            try:
                encrypted_message = client.recv(BUFFER_SIZE)
                if encrypted_message:
                    message = cipher_suite.decrypt(encrypted_message).decode(FORMAT)
                    log_message(f"Received from {usernames[client]}: {message}")
                    if message.startswith('@'):
                        target_username, msg = message.split(' ', 1)
                        target_username = target_username[1:]
                        send_private_message(target_username, msg, client, encrypted_message)
                    else:
                        broadcast(message, client)
                else:
                    remove_client(client)
                    break
            except Exception as e:
                log_message(f"Error: {str(e)}")
                remove_client(client)
                break

    def send_private_message(target_username, message, sender_socket, encrypted_message):
        if target_username in usernames.values():
            target_socket = list(usernames.keys())[list(usernames.values()).index(target_username)]
            sender_username = usernames[sender_socket]
            private_message = f"Private message from {sender_username}: {message}"
            encrypted_private_message = cipher_suite.encrypt(private_message.encode(FORMAT))
            log_message(f"Private message to {target_username} (encrypted): {encrypted_message.decode(FORMAT)}")
            try:
                target_socket.send(encrypted_private_message)
            except Exception as e:
                log_message(f"Error: {str(e)}")
                remove_client(target_socket)
        else:
            error_message = f"User {target_username} not found."
            encrypted_error_message = cipher_suite.encrypt(error_message.encode(FORMAT))
            sender_socket.send(encrypted_error_message)
            log_message(error_message)

    def broadcast(message, client_socket):
        encrypted_message = cipher_suite.encrypt(message.encode(FORMAT))
        for client in clients:
            if client != client_socket:
                try:
                    client.send(encrypted_message)
                    log_message(f"Broadcast message: {message}")
                except Exception as e:
                    log_message(f"Error: {str(e)}")
                    remove_client(client)

    def remove_client(client):
        if client in clients:
            client.close()
            del clients[client]
            username = usernames[client]
            del usernames[client]
            update_client_list()
            broadcast(f"{username} has left the chat.", client)

    def accept_connections():
        while True:
            client, address = server.accept()
            username = cipher_suite.decrypt(client.recv(BUFFER_SIZE)).decode(FORMAT)
            clients[client] = address
            usernames[client] = username
            update_client_list()
            broadcast(f"{username} has joined the chat.", client)
            threading.Thread(target=handle_client, args=(client, address)).start()

    def update_client_list():
        client_list.configure(state='normal')
        client_list.delete(1.0, tk.END)
        for username in usernames.values():
            client_list.insert(tk.END, f"{username}\n")
        client_list.configure(state='disabled')

    def log_message(message):
        status_text.configure(state='normal')
        status_text.insert(tk.END, message + "\n")
        status_text.configure(state='disabled')
        status_text.yview(tk.END)

    server_thread = threading.Thread(target=accept_connections)
    server_thread.start()

# GUI Functions
def start_server_gui():
    start_server()
    status_text.configure(state='normal')
    status_text.insert(tk.END, "Server started...\n")
    status_text.configure(state='disabled')

def stop_server():
    for client in clients:
        client.close()
    root.destroy()

# GUI Setup
root = tk.Tk()
root.title("Real time Message Server")
root.geometry("350x400")  # Adjusted size for fitting 4 clients on screen
root.configure(bg="#2E2E2E")

frame = tk.Frame(root, bg="#2E2E2E")
frame.grid(column=0, row=0, padx=10, pady=10)

start_button = tk.Button(frame, text="Start Server", command=start_server_gui, bg="#4CAF50", fg="white")
start_button.grid(column=0, row=0, padx=5, pady=5)

stop_button = tk.Button(frame, text="Stop Server", command=stop_server, bg="#F44336", fg="white")
stop_button.grid(column=1, row=0, padx=5, pady=5)

status_text = scrolledtext.ScrolledText(root, state='disabled', bg="#1E1E1E", fg="white", insertbackground="white", width=40, height=10)
status_text.grid(column=0, row=1, padx=10, pady=10)

client_list_label = tk.Label(root, text="Connected Clients:", bg="#2E2E2E", fg="white")
client_list_label.grid(column=0, row=2, padx=10, pady=5)

client_list = scrolledtext.ScrolledText(root, state='disabled', bg="#1E1E1E", fg="white", insertbackground="white", width=40, height=10)
client_list.grid(column=0, row=3, padx=10, pady=10)

root.mainloop()
