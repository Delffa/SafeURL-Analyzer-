import argparse
import json
import re
import ipaddress
from urllib.parse import urlparse
from analyzer import analyze_url


# =========================
# COLORS
# =========================

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"


# =========================
# BANNER
# =========================

def banner():
    print(CYAN + r"""
  ███████╗ █████╗ ███████╗██████╗ ██╗   ██╗██████╗ ██╗
  ██╔════╝██╔══██╗██╔════╝██╔══██╗██║   ██║██╔══██╗██║
  ███████╗███████║█████╗  ██║  ██║██║   ██║██████╔╝██║
  ╚════██║██╔══██║██╔══╝  ██║  ██║██║   ██║██╔══██╗██║
  ███████║██║  ██║███████╗██████╔╝╚██████╔╝██║  ██║██║
  ╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝

        BASIC URL SAFETY ANALYZER
        Developer By Delfa
    """ + RESET)


# =========================
# IP CHECK
# =========================

def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


# =========================
# URL ANALYZER
# =========================

def analyze_url(url):

    result = {
        "url": url,
        "risk_score": 0,
        "risk_level": "LOW",
        "checks": [],
        "warnings": []
    }

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:

        result["risk_score"] = 100
        result["risk_level"] = "HIGH"
        result["warnings"].append("Invalid URL")

        return result

    # HTTPS
    if parsed.scheme == "https":
        result["checks"].append("HTTPS is enabled")
    else:
        result["warnings"].append("HTTPS is not enabled")
        result["risk_score"] += 15

    # IP ADDRESS
    if is_ip_address(hostname):
        result["warnings"].append(
            "The URL uses an IP address instead of a domain"
        )
        result["risk_score"] += 20
    else:
        result["checks"].append("A domain name is used")

    # URL LENGTH
    if len(url) > 100:
        result["warnings"].append("URL is unusually long")
        result["risk_score"] += 10
    else:
        result["checks"].append("URL length is normal")

    # DOMAIN LENGTH
    if len(hostname) > 40:
        result["warnings"].append("Domain name is unusually long")
        result["risk_score"] += 10

    # @ SYMBOL
    if "@" in url:
        result["warnings"].append(
            "The URL contains an @ symbol"
        )
        result["risk_score"] += 20

    # SUBDOMAIN COUNT
    subdomains = hostname.count(".")

    if subdomains >= 4:
        result["warnings"].append(
            "The domain contains many subdomains"
        )
        result["risk_score"] += 15

    # PUNYCODE
    if "xn--" in hostname.lower():
        result["warnings"].append(
            "Punycode domain detected"
        )
        result["risk_score"] += 15

    # SUSPICIOUS CHARACTERS
    suspicious_chars = ["%", "\\", "<", ">", "{", "}"]

    found = [
        char for char in suspicious_chars
        if char in url
    ]

    if found:
        result["warnings"].append(
            f"Suspicious characters detected: {', '.join(found)}"
        )
        result["risk_score"] += 10

    # SUSPICIOUS KEYWORDS
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "confirm",
        "password"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if len(found_words) >= 3:
        result["warnings"].append(
            "Multiple security-related keywords detected"
        )
        result["risk_score"] += 10

    # LIMIT SCORE
    result["risk_score"] = min(
        result["risk_score"],
        100
    )

    # RISK LEVEL
    if result["risk_score"] >= 50:
        result["risk_level"] = "HIGH"

    elif result["risk_score"] >= 25:
        result["risk_level"] = "MEDIUM"

    else:
        result["risk_level"] = "LOW"

    return result


# =========================
# PRINT REPORT
# =========================

def print_report(result):

    print("\n" + "=" * 60)

    print(f"{BOLD}TARGET:{RESET} {result['url']}")
    print(
        f"{BOLD}RISK SCORE:{RESET} "
        f"{result['risk_score']}/100"
    )

    level = result["risk_level"]

    if level == "HIGH":
        level_color = RED

    elif level == "MEDIUM":
        level_color = YELLOW

    else:
        level_color = GREEN

    print(
        f"{BOLD}RISK LEVEL:{RESET} "
        f"{level_color}{level}{RESET}"
    )

    print("\n" + GREEN + "[+] CHECKS" + RESET)

    if result["checks"]:

        for check in result["checks"]:
            print(f"  {GREEN}[OK]{RESET} {check}")

    else:
        print("  No positive checks")

    print("\n" + YELLOW + "[!] WARNINGS" + RESET)

    if result["warnings"]:

        for warning in result["warnings"]:
            print(f"  {YELLOW}[!]{RESET} {warning}")

    else:
        print("  No suspicious indicators found")

    print("\n" + "=" * 60)

    print(
        CYAN +
        "Basic URL analysis only. "
        "This tool is not a phishing detector." +
        RESET
    )


# =========================
# MAIN
# =========================

def main():

    parser = argparse.ArgumentParser(
        description="SafeURL - Basic URL Safety Analyzer"
    )

    parser.add_argument(
        "-u",
        "--url",
        help="URL to analyze"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Save result as JSON"
    )

    args = parser.parse_args()

    banner()

    if args.url:

        url = args.url

    else:

        url = input(
            f"\n{CYAN}Enter URL: {RESET}"
        )

    result = analyze_url(url)

    print_report(result)

    if args.output:

        with open(
            args.output,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                result,
                file,
                indent=4,
                ensure_ascii=False
            )

        print(
            f"\n{GREEN}[+] Report saved to "
            f"{args.output}{RESET}"
        )


if __name__ == "__main__":
    main()
