"""Event enrichment service for Spork-IDS."""
import ipaddress
from typing import Dict, Any


def enrich_ip(ip_str: str) -> Dict[str, Any]:
    """
    Enriches an IP address with network classification, reputation heuristics,
    and simulated geo-metadata for cybersecurity inspection.
    """
    enrichment = {
        "ip": ip_str,
        "is_valid": False,
        "ip_type": "unknown",
        "is_private": False,
        "is_loopback": False,
        "country": "Unknown",
        "country_code": "XX",
        "asn": "AS0000 Private/Unknown",
        "reputation_score": 0,
        "threat_tags": [],
    }

    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        enrichment["is_valid"] = True
        enrichment["is_loopback"] = ip_obj.is_loopback
        enrichment["is_private"] = ip_obj.is_private

        if ip_obj.is_loopback:
            enrichment["ip_type"] = "loopback"
            enrichment["country"] = "Internal Host"
            enrichment["country_code"] = "LO"
            enrichment["asn"] = "AS-LOCALHOST"
        elif ip_obj.is_private:
            enrichment["ip_type"] = "rfc1918_private"
            enrichment["country"] = "Local Intranet"
            enrichment["country_code"] = "PR"
            enrichment["asn"] = "AS-PRIVATE Enterprise"
        elif ip_obj.is_multicast:
            enrichment["ip_type"] = "multicast"
            enrichment["country"] = "Multicast"
            enrichment["country_code"] = "MC"
        elif ip_obj.is_reserved:
            enrichment["ip_type"] = "reserved"
        else:
            enrichment["ip_type"] = "public"
            # Assign deterministic simulated geographic & ASN data based on IP octets for demo
            octets = ip_str.split(".")
            if len(octets) == 4:
                first = int(octets[0])
                if first in [1, 27, 43, 103]:
                    enrichment["country"] = "United States"
                    enrichment["country_code"] = "US"
                    enrichment["asn"] = "AS15169 Google LLC"
                elif first in [45, 80, 89, 94]:
                    enrichment["country"] = "Germany"
                    enrichment["country_code"] = "DE"
                    enrichment["asn"] = "AS24940 Hetzner Online GmbH"
                elif first in [185, 194, 195]:
                    enrichment["country"] = "Netherlands"
                    enrichment["country_code"] = "NL"
                    enrichment["asn"] = "AS16276 OVH SAS"
                elif first in [114, 116, 218]:
                    enrichment["country"] = "China"
                    enrichment["country_code"] = "CN"
                    enrichment["asn"] = "AS4134 Chinanet"
                elif first in [103, 106, 122]:
                    enrichment["country"] = "India"
                    enrichment["country_code"] = "IN"
                    enrichment["asn"] = "AS55836 Reliance Jio"
                else:
                    enrichment["country"] = "United States"
                    enrichment["country_code"] = "US"
                    enrichment["asn"] = "AS13335 Cloudflare, Inc."

    except ValueError:
        enrichment["is_valid"] = False

    return enrichment
