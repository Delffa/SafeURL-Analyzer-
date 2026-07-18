import ipaddress
from urllib.parse import urlparse


def is_ip_address(hostname):
    """
    Hostname bir IP adresi mi kontrol eder.
    """

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def analyze_url(url):
    """
    URL'yi analiz eder ve sonuçları dictionary olarak döndürür.
    """

    result = {
        "url": url,
        "risk_score": 0,
        "risk_level": "LOW",
        "checks": [],
        "warnings": []
    }

    # Scheme yoksa HTTP varsay
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    # Geçersiz URL kontrolü
    if not hostname:

        result["risk_score"] = 100
        result["risk_level"] = "HIGH"

        result["warnings"].append(
            "Invalid URL"
        )

        return result

    # HTTPS kontrolü
    if parsed.scheme == "https":

        result["checks"].append(
            "HTTPS is enabled"
        )

    else:

        result["warnings"].append(
            "HTTPS is not enabled"
        )

        result["risk_score"] += 15

    # IP adresi kontrolü
    if is_ip_address(hostname):

        result["warnings"].append(
            "The URL uses an IP address instead of a domain"
        )

        result["risk_score"] += 20

    else:

        result["checks"].append(
            "A domain name is used"
        )

    # URL uzunluğu
    if len(url) > 100:

        result["warnings"].append(
            "URL is unusually long"
        )

        result["risk_score"] += 10

    else:

        result["checks"].append(
            "URL length is normal"
        )

    # Domain uzunluğu
    if len(hostname) > 40:

        result["warnings"].append(
            "Domain name is unusually long"
        )

        result["risk_score"] += 10

    # @ karakteri
    if "@" in url:

        result["warnings"].append(
            "The URL contains an @ symbol"
        )

        result["risk_score"] += 20

    # Subdomain kontrolü
    subdomains = hostname.count(".")

    if subdomains >= 4:

        result["warnings"].append(
            "The domain contains many subdomains"
        )

        result["risk_score"] += 15

    # Punycode kontrolü
    if "xn--" in hostname.lower():

        result["warnings"].append(
            "Punycode domain detected"
        )

        result["risk_score"] += 15

    # Şüpheli karakterler
    suspicious_chars = [
        "%",
        "\\",
        "<",
        ">",
        "{",
        "}"
    ]

    found_chars = [
        char
        for char in suspicious_chars
        if char in url
    ]

    if found_chars:

        result["warnings"].append(
            "Suspicious characters detected: "
            + ", ".join(found_chars)
        )

        result["risk_score"] += 10

    # Şüpheli kelimeler
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
        word
        for word in suspicious_words
        if word in url.lower()
    ]

    if len(found_words) >= 3:

        result["warnings"].append(
            "Multiple security-related keywords detected"
        )

        result["risk_score"] += 10

    # Maksimum skor 100
    result["risk_score"] = min(
        result["risk_score"],
        100
    )

    # Risk seviyesi
    if result["risk_score"] >= 50:

        result["risk_level"] = "HIGH"

    elif result["risk_score"] >= 25:

        result["risk_level"] = "MEDIUM"

    else:

        result["risk_level"] = "LOW"

    return result
