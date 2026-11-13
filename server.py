import subprocess
import json
import re
import socket
from typing import Optional, List, Dict, Any
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("SecAnalyzer")

# --- SECURITY UTILS ---

def validate_ip(ip: str) -> bool:
    """Validates if a string is a valid IPv4 or IPv6 address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

def validate_domain(domain: str) -> bool:
    """Validates if a string is a valid domain name to prevent command injection."""
    # Regex for a valid domain name (RFC 1035)
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
    return bool(re.match(pattern, domain))

def sanitize_input(text: str) -> str:
    """Removes any character that could be used for shell injection."""
    # Only allow alphanumeric, dots, dashes, and underscores
    return re.sub(r"[^a-zA-Z0-9.\-_ ]", "", text)

# --- MCP TOOLS ---

@mcp.tool()
def run_recon_scan(target: str) -> str:
    """
    Executes a secure nmap scan on a target IP or domain.
    Returns structured JSON of open ports and services.
    """
    # Input Validation
    is_ip = validate_ip(target)
    is_domain = validate_domain(target)
    
    if not (is_ip or is_domain):
        return json.dumps({"error": "Invalid target. Please provide a valid IP address or domain name."}, indent=2)

    try:
        # Use a list for subprocess.run to avoid shell=True and prevent injection
        # -sV: Service version detection
        # -T4: Faster execution
        # -oX -: Output to XML on stdout for reliable parsing
        cmd = ["nmap", "-sV", "-T4", "-oX", "-", target]
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=300, # 5 min timeout
            check=True
        )
        
        # For simplicity in this implementation, we return the raw XML as a string 
        # But a production version would use an XML parser like defusedxml
        return f"Nmap scan completed successfully for {target}:\n\n{result.stdout}"
        
    except subprocess.CalledProcessError as e:
        return json.dumps({"error": f"Nmap execution failed: {e.stderr}"}, indent=2)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "Nmap scan timed out after 5 minutes."}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"An unexpected error occurred: {str(e)}"}, indent=2)

@mcp.tool()
def run_osint_module(domain: str) -> str:
    """
    Performs basic OSINT gathering for a domain using theHarvester.
    Returns found emails and subdomains.
    """
    if not validate_domain(domain):
        return json.dumps({"error": "Invalid domain name provided."}, indent=2)

    try:
        # -d: domain, -b: source (google, bing, etc. - 'all' is often too slow)
        # Using 'google' as a basic example
        cmd = ["theHarvester", "-d", domain, "-b", "google", "-l", "100"]
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=600, 
            check=True
        )
        
        return f"OSINT Results for {domain}:\n\n{result.stdout}"
        
    except subprocess.CalledProcessError as e:
        return json.dumps({"error": f"theHarvester failed: {e.stderr}"}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error executing OSINT module: {str(e)}"}, indent=2)

@mcp.tool()
def search_exploits(service_version: str) -> str:
    """
    Searches for known exploits using SearchSploit.
    Input: Service name and version (e.g., 'Apache 2.4.49')
    """
    # Sanitize input strictly to prevent command injection
    sanitized_query = sanitize_input(service_version)
    
    if not sanitized_query:
        return json.dumps({"error": "Invalid service version provided."}, indent=2)

    try:
        # searchsploit [query]
        cmd = ["searchsploit", sanitized_query]
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=60, 
            check=True
        )
        
        if not result.stdout.strip():
            return f"No exploits found for {sanitized_query}."
            
        return f"Exploits found for {sanitized_query}:\n\n{result.stdout}"
        
    except subprocess.CalledProcessError as e:
        return json.dumps({"error": f"searchsploit failed: {e.stderr}"}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error searching exploits: {str(e)}"}, indent=2)

if __name__ == "__main__":
    # Run the server using stdio transport
    mcp.run(transport="stdio")
