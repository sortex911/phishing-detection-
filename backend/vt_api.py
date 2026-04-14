import os
import re
import requests
import base64
from urllib.parse import urlparse
from typing import Dict, Any

# ─────────────────────────────────────────────
# Suspicious keyword list (phishing triggers)
# ─────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "verify", "verification", "validate", "login", "signin", "sign-in",
    "bank", "account", "update", "secure", "security", "password",
    "credential", "confirm", "alert", "warning", "suspended", "blocked",
    "recover", "restore", "unlock", "limited", "urgent", "immediate",
    "click-here", "access", "support", "paypal", "ebay", "amazon",
    "apple", "microsoft", "google", "facebook", "netflix", "webscr",
    "cmd=_s-xclick", "billing", "invoice", "submit", "wallet"
]

# ─────────────────────────────────────────────
# Heuristic local scoring engine
# ─────────────────────────────────────────────
class HeuristicScorer:
    """
    Rule-based URL scorer that runs BEFORE the VirusTotal API call.
    Each rule adds to a risk score; thresholds determine classification.
    """

    def score_url(self, url: str) -> Dict[str, Any]:
        score = 0
        reasons = []
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        full_url = url.lower()

        # ── Rule 1: HTTP (not HTTPS) ──────────────────────────────────────
        if parsed.scheme == "http":
            score += 20
            reasons.append("Uses insecure HTTP (not HTTPS)")

        # ── Rule 2: Suspicious keywords in URL ───────────────────────────
        keyword_hits = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
        if keyword_hits:
            score += min(len(keyword_hits) * 15, 60)  # cap at 60
            reasons.append(f"Suspicious keywords found: {', '.join(keyword_hits[:5])}")

        # ── Rule 3: Excessive subdomains (dot count > 3) ─────────────────
        dot_count = hostname.count(".")
        if dot_count > 3:
            score += 20
            reasons.append(f"Too many subdomains ({dot_count} dots in hostname)")
        elif dot_count > 2:
            score += 10
            reasons.append(f"Elevated subdomain count ({dot_count} dots)")

        # ── Rule 4: Long URL length (>75 chars is suspicious, >100 is bad) ─
        url_len = len(url)
        if url_len > 100:
            score += 20
            reasons.append(f"Very long URL ({url_len} characters)")
        elif url_len > 75:
            score += 10
            reasons.append(f"Long URL ({url_len} characters)")

        # ── Rule 5: IP address used as hostname ───────────────────────────
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if ip_pattern.match(hostname):
            score += 30
            reasons.append("IP address used instead of domain name")

        # ── Rule 6: Hyphens in domain (common phishing trick) ─────────────
        domain_parts = hostname.split(".")
        tld_plus_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname
        hyphen_count = tld_plus_domain.count("-")
        if hyphen_count >= 3:
            score += 20
            reasons.append(f"Excessive hyphens in domain ({hyphen_count})")
        elif hyphen_count >= 1:
            score += 5
            reasons.append(f"Hyphens in domain ({hyphen_count})")

        # ── Rule 7: Uncommon or risky TLD ────────────────────────────────
        risky_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".xyz",
                      ".top", ".click", ".loan", ".work", ".date", ".link"]
        for tld in risky_tlds:
            if hostname.endswith(tld):
                score += 25
                reasons.append(f"High-risk TLD detected: {tld}")
                break

        # ── Rule 8: Numeric-heavy domain ─────────────────────────────────
        digits_in_hostname = sum(c.isdigit() for c in hostname)
        if digits_in_hostname > 4:
            score += 10
            reasons.append(f"Many digits in hostname ({digits_in_hostname})")

        # ── Classify by score ─────────────────────────────────────────────
        if score >= 50:
            heuristic_status = "malicious"
        elif score >= 25:
            heuristic_status = "suspicious"
        else:
            heuristic_status = "safe"

        return {
            "heuristic_status": heuristic_status,
            "heuristic_score": score,
            "heuristic_reasons": reasons
        }


# ─────────────────────────────────────────────
# VirusTotal API integration
# ─────────────────────────────────────────────
class VTAPI:
    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key,
        }
        self.heuristic = HeuristicScorer()

    def encode_url(self, url: str) -> str:
        """VirusTotal requires base64url encoding with no padding."""
        url_bytes = url.encode("utf-8")
        b64 = base64.urlsafe_b64encode(url_bytes).decode("utf-8")
        return b64.strip("=")

    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Multi-layer URL check:
         1. Local heuristic scoring (fast, always runs)
         2. VirusTotal cloud lookup  (slower, more authoritative)
         3. Merge results: worst-case classification wins
        """
        # ── Layer 1: Heuristic fast-pass ─────────────────────────────────
        heuristic_result = self.heuristic.score_url(url)

        # ── Layer 2: VirusTotal lookup ────────────────────────────────────
        vt_result = self._fetch_vt_report(url)

        # ── Layer 3: Merge — most severe classification wins ──────────────
        severity_rank = {"malicious": 3, "suspicious": 2, "safe": 1}

        h_status = heuristic_result["heuristic_status"]
        vt_status = vt_result.get("status", "safe")   # default safe if VT errored

        # If VT errored, we still return heuristic results — never hide them
        final_status = (
            h_status if severity_rank[h_status] >= severity_rank[vt_status]
            else vt_status
        )

        return {
            "status": final_status,
            "stats": vt_result.get("stats", {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0
            }),
            "heuristic": {
                "score": heuristic_result["heuristic_score"],
                "status": h_status,
                "reasons": heuristic_result["heuristic_reasons"]
            },
            "vt_error": vt_result.get("error")   # surface VT error to frontend, but don't block
        }

    def _fetch_vt_report(self, url: str) -> Dict[str, Any]:
        """Attempts to fetch URL analysis from VirusTotal. Always returns a safe fallback."""
        if not self.api_key:
            return {"error": "VT API key not configured."}

        url_id = self.encode_url(url)
        endpoint = f"{self.base_url}/urls/{url_id}"

        try:
            response = requests.get(endpoint, headers=self.headers, timeout=15)

            if response.status_code == 404:
                # Not in VT DB — submit for scanning, return pending notice
                self._submit_for_scan(url)
                return {"error": "URL not in VirusTotal DB — submitted for scanning. Re-scan in 30s for VT results."}

            if response.status_code == 429:
                return {"error": "VirusTotal rate limit exceeded. Heuristic results only."}

            if response.status_code == 401:
                return {"error": "Invalid VirusTotal API key."}

            response.raise_for_status()
            return self._parse_report(response.json())

        except requests.exceptions.Timeout:
            return {"error": "VirusTotal request timed out. Heuristic results only."}
        except Exception as e:
            return {"error": f"VirusTotal lookup failed: {str(e)}"}

    def _submit_for_scan(self, url: str):
        """Fire-and-forget URL submission to VirusTotal for future lookups."""
        try:
            endpoint = f"{self.base_url}/urls"
            headers = {**self.headers, "content-type": "application/x-www-form-urlencoded"}
            requests.post(endpoint, data={"url": url}, headers=headers, timeout=10)
        except Exception:
            pass  # Submission failure is non-critical

    def _parse_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract analysis stats from a VirusTotal API response."""
        try:
            stats = (
                data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
            )
            if not stats:
                return {"error": "VT scan still pending. Heuristic results only."}

            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            # Map VT stats to status
            if malicious > 0:
                status = "malicious"
            elif suspicious > 0:
                status = "suspicious"
            else:
                status = "safe"

            return {
                "status": status,
                "stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected
                }
            }
        except Exception as e:
            return {"error": f"Failed to parse VT report: {str(e)}"}
