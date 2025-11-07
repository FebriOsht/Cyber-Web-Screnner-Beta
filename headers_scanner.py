import requests
from urllib.parse import urlparse

class HeadersScanner:
    def __init__(self):
        self.security_headers = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy',
            'Permissions-Policy',
            'X-XSS-Protection'
        ]
        
        self.optimal_values = {
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }
    
    def scan_headers(self, url):
        """Scan security headers of a website"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            response = requests.get(url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            results = {
                "url": url,
                "status_code": response.status_code,
                "headers_found": {},
                "missing_headers": [],
                "score": 0,
                "recommendations": []
            }
            
            total_headers = len(self.security_headers)
            found_count = 0
            
            for header in self.security_headers:
                if header in headers:
                    found_count += 1
                    results["headers_found"][header] = {
                        "value": headers[header],
                        "optimal": self.optimal_values.get(header),
                        "is_optimal": self._check_optimal(header, headers[header])
                    }
                else:
                    results["missing_headers"].append(header)
                    results["recommendations"].append(f"Add {header} header")
            
            # Calculate security score
            results["score"] = round((found_count / total_headers) * 100)
            results["grade"] = self._calculate_grade(results["score"])
            
            return results
            
        except requests.RequestException as e:
            return {
                "url": url,
                "error": str(e),
                "score": 0,
                "grade": "F"
            }
    
    def _check_optimal(self, header, value):
        """Check if header value is optimal"""
        optimal = self.optimal_values.get(header)
        if optimal and value:
            return optimal.lower() in value.lower()
        return False
    
    def _calculate_grade(self, score):
        """Calculate security grade based on score"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B" 
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
