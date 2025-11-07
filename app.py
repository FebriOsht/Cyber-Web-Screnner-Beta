from ssl_scanner import SSLScanner
from headers_scanner import HeadersScanner
from scanner import EnhancedScanner

# Tambahkan routes baru
@app.route('/api/ssl-scan', methods=['POST'])
def ssl_scan():
    data = request.get_json()
    target = data.get('target')
    
    scanner = SSLScanner()
    results = scanner.check_ssl_certificate(target)
    
    # Save to database
    scan_id = save_scan_result({
        'type': 'ssl_scan',
        'target': target,
        'results': results
    })
    
    return jsonify({
        'scan_id': scan_id,
        'results': results
    })

@app.route('/api/headers-scan', methods=['POST'])  
def headers_scan():
    data = request.get_json()
    target = data.get('target')
    
    scanner = HeadersScanner()
    results = scanner.scan_headers(target)
    
    scan_id = save_scan_result({
        'type': 'headers_scan', 
        'target': target,
        'results': results
    })
    
    return jsonify({
        'scan_id': scan_id,
        'results': results
    })

@app.route('/api/comprehensive-scan', methods=['POST'])
def comprehensive_scan():
    data = request.get_json()
    target = data.get('target')
    
    scanner = EnhancedScanner()
    results = scanner.comprehensive_scan(target)
    
    scan_id = save_scan_result({
        'type': 'comprehensive_scan',
        'target': target, 
        'results': results
    })
    
    return jsonify({
        'scan_id': scan_id,
        'results': results
    })
