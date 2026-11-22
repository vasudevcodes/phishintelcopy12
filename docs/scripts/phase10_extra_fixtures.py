import json
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = ROOT_DIR / "backend" / "tests" / "fixtures"
OUTPUT_DIR = ROOT_DIR / "docs" / "phase10"

boundary = "----PhishIntelAcceptanceBoundary7bc62544"
crlf = b"\r\n"

def upload(fname):
    file_bytes = (FIXTURES_DIR / fname).read_bytes()
    body = (
        f"--{boundary}".encode() + crlf +
        f'Content-Disposition: form-data; name="file"; filename="{fname}"'.encode() + crlf +
        b"Content-Type: message/rfc822" + crlf + crlf +
        file_bytes + crlf +
        f"--{boundary}--".encode() + crlf
    )
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/email/analyze",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "Content-Length": str(len(body))},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

res4 = upload("04_attachments.eml")
print("04_attachments.eml:")
print("  Attachments count:", len(res4.get("attachments", [])))
for att in res4.get("attachments", []):
    print(f"    - {att.get('filename')} ({att.get('content_type')}, {att.get('size_bytes')} bytes, SHA-256: {att.get('sha256')})")

res6 = upload("06_multiple_received_hops.eml")
print("06_multiple_received_hops.eml:")
print("  IP Candidates count:", len(res6.get("ip_candidates", [])))
ip_intel = res6.get("ip_intelligence", {})
orig = ip_intel.get("origin_candidate") or {}
print(f"  Apparent Origin IP: {orig.get('ip')} (Classification: {orig.get('classification')}, Routable: {orig.get('is_routable')})")
print(f"  Transit Assessment: {ip_intel.get('origin_assessment')}")

# Update live_api_responses.json with these 2 additional fixtures
json_path = OUTPUT_DIR / "live_api_responses.json"
with open(json_path, "r", encoding="utf-8") as f:
    existing = json.load(f)

existing["04_attachments.eml"] = {"description": "Email with attachments", "status_code": 200, "response": res4}
existing["06_multiple_received_hops.eml"] = {"description": "Email with multiple Received hops", "status_code": 200, "response": res6}

with open(json_path, "w", encoding="utf-8") as f:
    json.dump(existing, f, indent=2)
print("Updated live_api_responses.json with all fixtures.")
