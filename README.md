# SecAnalyzer MCP - Installation Guide (Arch Linux)

## 🛠️ System Requirements

For this server to function, the following tools must be installed on the host Linux system (Arch):

1. **Nmap**: For network reconnaissance.
   ```bash
   sudo pacman -S nmap
   ```

2. **theHarvester**: For OSINT gathering.
   ```bash
   # Available via AUR
   yay -S theharvester
   ```

3. **Exploit-DB (SearchSploit)**: For vulnerability lookup.
   ```bash
   # Available via AUR
   yay -S exploitdb
   ```

## 🚀 Setup Instructions

1. **Navigate to the project folder**:
   ```bash
   cd "SecAnalyzer MCP"
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## 🔌 Configuration for MCP Client (Claude Desktop / etc.)

Add the following to your MCP config file:

```json
{
  "mcpServers": {
    "sec-analyzer": {
      "command": "/home/USER/SecAnalyzer MCP/venv/bin/python",
      "args": ["/home/USER/SecAnalyzer MCP/server.py"]
    }
  }
}
```
*(Replace `/home/USER/` with your actual absolute path)*.
