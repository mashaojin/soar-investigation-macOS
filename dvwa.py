"""Bounded, credential-free evidence for the single DVWA SQLi lab scenario."""
from urllib.parse import urlsplit, parse_qsl, urlencode

SID = 9001002
ASSET = "ubuntu-dvwa"
ASSET_CONTEXT = {
    "asset_id": ASSET, "address": "192.168.64.6", "port": 80,
    "application": "DVWA lab, SQL Injection exercise",
    "expected_normal_request": "/vulnerabilities/sqli/?id=1&Submit=Submit",
    "demo_attack": "id=1' OR '1'='1",
    "interpretation": "A tautology may bypass the intended single-record WHERE filter. "
                      "No application response body is collected; HTTP 200 does not prove extraction.",
    "response_policy": "Report only. No firewall or configuration action.",
}


def safe_http(http):
    if not isinstance(http, dict):
        return {"evidence_available": False}
    # Allowlist, rather than blacklist, query parameters. Never retain headers,
    # cookies, bodies, authorization, or arbitrary URL credentials.
    raw = str(http.get("url", ""))[:8192]
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return {"evidence_available": False, "reason": "Malformed URI omitted"}
    query = [(k, v[:256]) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
             if k in {"id", "Submit"}][:4]
    uri = parsed.path[:256] + ("?" + urlencode(query) if query else "")
    result = {"uri": uri[:1200], "method": str(http.get("http_method", ""))[:12],
              "response_evidence": "No response body collected; attack success undetermined."}
    status = http.get("status")
    if type(status) is int and 100 <= status <= 599:
        result["status"] = status
    return result


def sanitize_event(event):
    alert = event.get("alert")
    if event.get("event_type") != "alert" or not isinstance(alert, dict) or alert.get("signature_id") != SID:
        return event
    # Keep only fields used in grouping and analysis for this web scenario.
    cleaned = {k: event[k] for k in ("timestamp", "event_type", "src_ip", "src_port",
               "dest_ip", "dest_port", "flow_id", "tx_id", "proto") if k in event}
    cleaned["alert"] = {"signature_id": SID}
    cleaned["http"] = safe_http(event.get("http"))
    return cleaned
