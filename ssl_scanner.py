import ssl
import socket
from datetime import datetime
import concurrent.futures

class SSLScanner:
    def __init__(self):
        self.timeout = 10
    
    def check_ssl_certificate(self, domain):
        """Scan SSL/TLS certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Parse certificate info
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    return {
                        "domain": domain,
                        "valid": True,
                        "issuer": issuer.get('organizationName', 'Unknown'),
                        "subject": subject.get('commonName', 'Unknown'),
                        "expires": cert['notAfter'],
                        "days_until_expiry": days_until_expiry,
                        "cipher_suite": f"{cipher[0]} {cipher[1]}",
                        "protocol": ssock.version(),
                        "grade": self._calculate_ssl_grade(days_until_expiry, cipher[0]),
                        "recommendations": self._generate_recommendations(ssock.version(), cipher[0])
                    }
        except Exception as e:
            return {
                "domain": domain,
                "valid": False,
                "error": str(e),
                "grade": "F"
            }
    
    def _calculate_ssl_grade(self, days_until_expiry, cipher):
        """Calculate SSL security grade"""
        if days_until_expiry < 0:
            return "F"
        elif days_until_expiry < 30:
            return "D"
        elif "3DES" in cipher or "RC4" in cipher:
            return "C"
        elif "TLS13" in cipher or "ECDHE" in cipher:
            return "A"
        else:
            return "B"
    
    def _generate_recommendations(self, protocol, cipher):
        """Generate security recommendations"""
        recommendations = []
        
        if protocol != "TLSv1.3":
            recommendations.append("Upgrade to TLS 1.3 for better security")
        
        if "3DES" in cipher or "RC4" in cipher:
            recommendations.append("Disable weak ciphers (3DES, RC4)")
            
        if "CBC" in cipher:
            recommendations.append("Consider using AEAD ciphers instead of CBC")
            
        return recommendations

    def scan_multiple(self, domains):
        """Scan multiple domains concurrently"""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_domain = {executor.submit(self.check_ssl_certificate, domain): domain for domain in domains}
            for future in concurrent.futures.as_completed(future_to_domain):
                results.append(future.result())
        return results
