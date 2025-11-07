# File: backend/scanners/ssl_scanner.py
import ssl
import socket
from typing import Dict

class SSLScanner:
    def scan(self, domain: str) -> Dict:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        "valid": True,
                        "issuer": cert.get('issuer', []),
                        "expires": cert.get('notAfter', ''),
                        "cipher": cipher,
                        "grade": self._calculate_grade(cert, cipher)
                    }
        except Exception as e:
            return {"valid": False, "error": str(e)}
