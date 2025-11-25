from mitmproxy import http
from mitmproxy.proxy.layers import tls
import os

# Load blocked domains from hosts.txt
BLOCKED_DOMAINS = set()

def load_blocked_domains():
    """Load domains from hosts.txt file"""
    global BLOCKED_DOMAINS
    hosts_path = os.path.join(os.path.dirname(__file__), "hosts.txt")
    
    try:
        with open(hosts_path, "r") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#"):
                    # Extract domain (handle format: "0.0.0.0 domain.com" or just "domain.com")
                    parts = line.split()
                    domain = parts[-1] if parts else line
                    BLOCKED_DOMAINS.add(domain.lower())
        print(f"[+] Loaded {len(BLOCKED_DOMAINS)} blocked domains from hosts.txt")
    except FileNotFoundError:
        print(f"[!] WARNING: hosts.txt not found at {hosts_path}")
    except Exception as e:
        print(f"[!] ERROR loading hosts.txt: {e}")

# Load domains when script initializes
load_blocked_domains()

def is_blocked(hostname: str) -> bool:
    """Check if hostname matches any blocked domain"""
    hostname_lower = hostname.lower()
    for blocked in BLOCKED_DOMAINS:
        if blocked in hostname_lower:
            return True
    return False

def tls_clienthello(data: tls.ClientHelloData) -> None:
    if data.context.server.address:
        hostname = data.context.server.address[0]
        
        # Block domains at TLS layer
        if is_blocked(hostname):
            raise ConnectionRefusedError(f"[*] Blocked HTTPS connection to: {hostname}")


def request(flow: http.HTTPFlow) -> None:
    """Handle HTTP/HTTPS requests after TLS handshake"""
    hostname = flow.request.pretty_host
    
    # Special handling for Netflix - corrupt the response
    if "netflix" in hostname:
        flow.response = http.Response.make( 
            200,
            b"uwu",  # probably don't need this many uwus. just corrupt the response 
            {"Content-Type": "application/x-msl+json"}
        )
        print(f"[*] Corrupted Netflix response for: {hostname}")
        return

    # Block other domains from hosts.txt
    if is_blocked(hostname):
        flow.response = http.Response.make( 
            404,
            b"uwu",
        )
        print(f"[*] Blocked HTTP request to: {hostname}")
        return

    # Map error text js to inject.js
    if "/js/common/config/text/config.text.lruderrorpage" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "inject_elfldr_automated.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read()
                print(f"[+] Loaded {len(content)} bytes from inject.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
        except FileNotFoundError:
            print(f"[!] ERROR: inject.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: inject.js",
                {"Content-Type": "text/plain"}
            )

    # Map 1_lapse_prepare_1 to 1_lapse_prepare_1.js
    if "/js/lapse.js" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "payloads", "lapse.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read()
                print(f"[+] Loaded {len(content)} bytes from lapse.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
        except FileNotFoundError:
            print(f"[!] ERROR: lapse.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: 1_lapse_prepare_1.js",
                {"Content-Type": "text/plain"}
            )
            
    if "/js/elf_loader.js" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "payloads", "elf_loader.js")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read()
                print(f"[+] Loaded {len(content)} bytes from elf_loader.js")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
        except FileNotFoundError:
            print(f"[!] ERROR: lapse.js not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: elf_loader.js",
                {"Content-Type": "text/plain"}
            )
    # Map elfldr.elf to elfldr.elf (binary)
    if "/js/elfldr.elf" in flow.request.path:
        inject_path = os.path.join(os.path.dirname(__file__), "payloads", "elfldr.elf")
        print(f"[*] Injecting JavaScript from: {inject_path}")

        try:
            with open(inject_path, "rb") as f:
                content = f.read()
                print(f"[+] Loaded {len(content)} bytes from elfldr.elf")
                flow.response = http.Response.make(
                    200,
                    content,
                    {"Content-Type": "application/javascript"}
                )
        except FileNotFoundError:
            print(f"[!] ERROR: elfldr.elf not found at {inject_path}")
            flow.response = http.Response.make(
                404,
                b"File not found: elfldr.elf",
                {"Content-Type": "text/plain"}
            )
