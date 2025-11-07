from ssl_scanner import SSLScanner
from headers_scanner import HeadersScanner

class EnhancedScanner:
    def __init__(self):
        self.ssl_scanner = SSLScanner()
        self.headers_scanner = HeadersScanner()
    
    def comprehensive_scan(self, target):
        """Perform comprehensive security scan"""
        results = {
            "target": target,
            "ssl_scan": {},
            "headers_scan": {},
            "port_scan": {},
            "technology_scan": {},
            "timestamp": None
        }
        
        # SSL Scan
        try:
            results["ssl_scan"] = self.ssl_scanner.check_ssl_certificate(target)
        except Exception as e:
            results["ssl_scan"] = {"error": str(e)}
        
        # Headers Scan  
        try:
            results["headers_scan"] = self.headers_scanner.scan_headers(target)
        except Exception as e:
            results["headers_scan"] = {"error": str(e)}
        
        # TODO: Integrate existing port scanning
        # TODO: Add technology detection
        
        return results
