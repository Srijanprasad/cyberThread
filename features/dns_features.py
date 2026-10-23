"""
DNS Feature Extraction Engine.
Detects DNS tunneling (iodine, dnscat2), DGA domains, and exfiltration
from passively observed unidirectional DNS queries.
"""

import math
from collections import Counter
from typing import Dict, Any, Tuple


def calculate_entropy(string: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not string:
        return 0.0
    entropy = 0.0
    length = len(string)
    counts = Counter(string.lower())
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_dns_features(domain: str, qtype: str = "A") -> Dict[str, Any]:
    """
    Extracts statistical and lexical features from DNS domain query.
    Tunneling tools like iodine or dnscat2 encode payload chunks in labels,
    resulting in high entropy, extreme length, and high consonant/digit ratios.
    """
    if not domain:
        return {
            "domain_length": 0,
            "subdomain_length": 0,
            "max_label_length": 0,
            "label_count": 0,
            "entropy": 0.0,
            "digit_ratio": 0.0,
            "hex_ratio": 0.0,
            "is_suspicious_qtype": False,
            "is_tunnel_signature": False,
        }

    clean_domain = domain.strip(".").lower()
    labels = clean_domain.split(".")
    subdomains = labels[:-2] if len(labels) > 2 else labels[:-1]
    subdomain_str = "".join(subdomains)

    total_len = len(clean_domain)
    subdomain_len = len(subdomain_str)
    max_label_len = max((len(lbl) for lbl in labels), default=0)
    label_count = len(labels)

    entropy = calculate_entropy(subdomain_str) if subdomain_str else calculate_entropy(clean_domain)

    # Character distributions
    digits = sum(c.isdigit() for c in subdomain_str)
    hex_chars = sum(c in "0123456789abcdef" for c in subdomain_str)
    total_chars = max(1, len(subdomain_str))

    digit_ratio = digits / total_chars
    hex_ratio = hex_chars / total_chars

    # Suspicious query types often abused in DNS tunneling (TXT, NULL, CNAME, CNAME base64)
    suspicious_types = {"TXT", "NULL", "ANY", "CNAME", "SRV"}
    is_susp_qtype = qtype.upper() in suspicious_types

    # Signature check for obvious iodine / dnscat2 chunks
    # (e.g. 50+ chars subdomain or base32/base64 chunks with entropy > 3.8)
    is_tunnel_sig = (subdomain_len > 45 and entropy > 3.7) or (hex_ratio > 0.85 and subdomain_len > 30)

    return {
        "domain_length": total_len,
        "subdomain_length": subdomain_len,
        "max_label_length": max_label_len,
        "label_count": label_count,
        "entropy": round(entropy, 4),
        "digit_ratio": round(digit_ratio, 4),
        "hex_ratio": round(hex_ratio, 4),
        "is_suspicious_qtype": is_susp_qtype,
        "is_tunnel_signature": is_tunnel_sig,
    }
