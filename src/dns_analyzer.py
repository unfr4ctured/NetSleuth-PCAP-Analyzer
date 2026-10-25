
from collections import Counter, defaultdict
from math import log2


def calculate_entropy(value):
    """Calculate Shannon entropy in bits per character."""
    if not value:
        return 0.0

    counts = Counter(value.lower())
    length = len(value)

    return -sum(
        (count / length) * log2(count / length)
        for count in counts.values()
    )


def detect_dns_anomalies(
    packets,
    long_name_threshold=100,
    entropy_threshold=3.5,
    unique_query_threshold=30,
):
    """
    Detect heuristic DNS anomalies from packet records.

    Expected fields:
        timestamp, source_ip, protocol, dns_query_name

    Returns a list of findings. These heuristics are not proof
    of malicious activity.
    """
    if long_name_threshold < 1:
        raise ValueError("long_name_threshold must be positive")

    if not 0 <= entropy_threshold <= 4:
        raise ValueError("entropy_threshold must be between 0 and 4")

    if unique_query_threshold < 1:
        raise ValueError("unique_query_threshold must be positive")

    findings = []
    source_queries = defaultdict(set)
    seen_long_names = set()
    seen_entropy_names = set()

    for packet in packets:
        query = str(packet.get("dns_query_name", "")).strip().rstrip(".")
        source = str(packet.get("source_ip", "")).strip()

        if not query or not source:
            continue

        if str(packet.get("protocol", "")).upper() not in ("UDP", "TCP"):
            continue

        if len(query) > long_name_threshold and query not in seen_long_names:
            seen_long_names.add(query)

            findings.append({
                "severity": "Medium",
                "rule": "Long DNS query name",
                "source_ip": source,
                "evidence": (
                    f"DNS query name is {len(query)} characters long: "
                    f"{query}"
                ),
                "recommendation": (
                    "Review the queried domain and determine whether "
                    "the long name is expected for this application."
                ),
            })

        labels = query.split(".")
        # Assess subdomains, excluding the final two labels as a
        # rough heuristic; this is not public-suffix aware.
        if len(labels) >= 3:
            subdomain = ".".join(labels[:-2])

            if (
                len(subdomain) >= 20
                and calculate_entropy(subdomain) >= entropy_threshold
                and subdomain not in seen_entropy_names
            ):
                seen_entropy_names.add(subdomain)

                findings.append({
                    "severity": "Medium",
                    "rule": "High-entropy DNS subdomain",
                    "source_ip": source,
                    "evidence": (
                        f"Subdomain has {len(subdomain)} characters "
                        f"and entropy "
                        f"{calculate_entropy(subdomain):.2f}: "
                        f"{subdomain}"
                    ),
                    "recommendation": (
                        "Investigate whether the subdomain contains "
                        "encoded or generated data. Confirm against "
                        "normal application behavior."
                    ),
                })

        source_queries[source].add(query)

    for source, unique_queries in source_queries.items():
        if len(unique_queries) >= unique_query_threshold:
            findings.append({
                "severity": "Medium",
                "rule": "High number of unique DNS queries",
                "source_ip": source,
                "evidence": (
                    f"Source made {len(unique_queries)} unique DNS "
                    f"queries in the analyzed capture."
                ),
                "recommendation": (
                    "Review the source's DNS activity and the domains "
                    "queried. Compare with a normal traffic baseline."
                ),
            })

    return findings
