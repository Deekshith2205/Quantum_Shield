import urllib.request
import json
import sys

def test_scan(domain, probe_pqc=False):
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/scan",
        data=json.dumps({"domain": domain, "port": 443, "probe_pqc": probe_pqc}).encode(),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            tls = data["tls"]
            pqc = tls.get("pqc_evidence") or {}
            score = data["score"]
            kx_role = next(r for r in data["role_assessments"] if r["category_id"] == "key_establishment")
            kx_findings = [f for f in data["findings"] if f["category"] == "key_exchange"]
            kx_audit = next((a for a in data["audit_findings"] if a["control"] == "TLS Key Establishment"), None)
            
            print(f"==================================================")
            print(f"Target: {domain} (probe_pqc={probe_pqc})")
            print(f"==================================================")
            print(f"Protocol:             {tls.get('negotiated_protocol')}")
            print(f"Cipher Suite:         {tls.get('negotiated_cipher')}")
            print(f"Key Exchange Value:   {tls.get('key_exchange_value')}")
            print(f"Evidence Status:      {tls.get('key_exchange_evidence')}")
            print(f"PQC Raw Group:        {pqc.get('raw_group')}")
            print(f"Classical Component:  {pqc.get('classical_component')}")
            print(f"PQC Component:        {pqc.get('pqc_component')}")
            print(f"Is Hybrid:            {pqc.get('is_hybrid')}")
            print(f"Probe Result:         {pqc.get('probe_result')}")
            print(f"KX Readiness Score:   {kx_role['readiness_score']} / 100 ({kx_role['status']})")
            print(f"Overall Score:        {score['readiness_score']} / 100 (Grade: {score['grade']})")
            print(f"Key Findings Count:   {len(kx_findings)} (Expected: exactly 1)")
            if kx_findings:
                print(f"Finding Title:        {kx_findings[0]['title']}")
                print(f"Finding Severity:     {kx_findings[0]['risk_level']}")
            if kx_audit:
                print(f"Audit Finding Domain: {kx_audit['domain']}")
                print(f"Audit Observability:  {kx_audit['observability']}")
                print(f"Audit Severity:       {kx_audit['severity']}")
            print()
    except Exception as e:
        print(f"ERROR scanning {domain}: {e}\n")

if __name__ == "__main__":
    targets = [
        ("cloudflare.com", False),
        ("google.com", False),
        ("python.org", False),
        ("wikipedia.org", False),
        ("wikipedia.org", True),
    ]
    for dom, probe in targets:
        test_scan(dom, probe)

