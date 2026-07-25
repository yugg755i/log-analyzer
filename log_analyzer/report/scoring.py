SIGNAL_POINTS = {
    "malicious_ip": 40,
    "bruteforce": 30,
    "username_enum": 20,
    "breach": 10,
}

MITRE_TECHNIQUES = {
    ("sshd", "bruteforce"): {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
    ("sshd", "username_enum"): {"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials"},
    ("sshd", "malicious_ip"): {"id": "T1071", "name": "Application Layer Protocol (known malicious infrastructure)"},
    ("sshd", "breach"): {"id": "T1078", "name": "Valid Accounts"},

    ("sudo", "bruteforce"): {"id": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"},
    ("sudo", "username_enum"): {"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials"},
    ("sudo", "malicious_ip"): {"id": "T1071", "name": "Application Layer Protocol (known malicious infrastructure)"},
    ("sudo", "breach"): {"id": "T1078.003", "name": "Valid Accounts: Local Accounts"},

    ("su", "bruteforce"): {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
    ("su", "username_enum"): {"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials"},
    ("su", "malicious_ip"): {"id": "T1071", "name": "Application Layer Protocol (known malicious infrastructure)"},
    ("su", "breach"): {"id": "T1078.003", "name": "Valid Accounts: Local Accounts"},
}

THREAT_LEVEL_BANDS = (
    (70, "Critical"),
    (40, "High"),
    (20, "Medium"),
    (1, "Low"),
)

def _technique(log_type, signal):
    return MITRE_TECHNIQUES.get((log_type, signal), MITRE_TECHNIQUES[("sshd", signal)])


def threat_level(score):
    for floor, label in THREAT_LEVEL_BANDS:
        if score >= floor:
            return label
    return "Informational"


def score_ip(actor, log_type, bruteforce, username_enum, malicious_ips, timeline):
    checklist = []
    techniques = []
    score = 0

    if actor in malicious_ips:
        data = malicious_ips[actor]
        pts = SIGNAL_POINTS["malicious_ip"]
        score += pts
        checklist.append({
            "signal": "Threat intel match (AbuseIPDB)",
            "detail": f"{data.get('abuseConfidenceScore', 0)}% confidence, "
                      f"{data.get('totalReports', 0)} report(s), country {data.get('countryCode') or 'unknown'}",
            "points": pts,
            "met": True,
        })
        techniques.append(_technique(log_type, "malicious_ip"))
    else:
        checklist.append({
            "signal": "Threat intel match (AbuseIPDB)",
            "detail": "no match, or enrichment skipped",
            "points": 0,
            "met": False,
        })

    if actor in bruteforce:
        bf = bruteforce[actor]
        pts = SIGNAL_POINTS["bruteforce"]
        score += pts
        checklist.append({
            "signal": "Time-windowed brute-force pattern",
            "detail": f"{bf['count']} failed attempts, {bf['window_start']} \u2192 {bf['window_end']}",
            "points": pts,
            "met": True,
        })
        techniques.append(_technique(log_type, "bruteforce"))
    else:
        checklist.append({
            "signal": "Time-windowed brute-force pattern",
            "detail": "not observed",
            "points": 0,
            "met": False,
        })

    if actor in username_enum:
        ue = username_enum[actor]
        pts = SIGNAL_POINTS["username_enum"]
        score += pts
        checklist.append({
            "signal": "Username enumeration",
            "detail": f"{ue['distinct_usernames']} distinct usernames, {ue['window_start']} \u2192 {ue['window_end']}",
            "points": pts,
            "met": True,
        })
        techniques.append(_technique(log_type, "username_enum"))
    else:
        checklist.append({
            "signal": "Username enumeration",
            "detail": "not observed",
            "points": 0,
            "met": False,
        })

    breached = bool(timeline and timeline.get("breached"))
    if breached:
        pts = SIGNAL_POINTS["breach"]
        score += pts
        checklist.append({
            "signal": "Successful login on this IP",
            "detail": "at least one Accepted authentication recorded",
            "points": pts,
            "met": True,
        })
        techniques.append(_technique(log_type, "breach"))
    else:
        checklist.append({
            "signal": "Successful login on this IP",
            "detail": "no successful login",
            "points": 0,
            "met": False,
        })

    score = min(score, 100)

    return {
        "ip": actor,
        "actor": actor,
        "log_type": log_type,
        "score": score,
        "level": threat_level(score),
        "checklist": checklist,
        "mitre": techniques,
        "attack_type": _attack_type(actor, log_type, bruteforce, username_enum, malicious_ips, breached),
    }


def _attack_type(actor, log_type, bruteforce, username_enum, malicious_ips, breached):
    if log_type == "sshd":
        if breached and actor in bruteforce:
            return "Brute-force with successful compromise"
        if actor in bruteforce and actor in username_enum:
            return "Credential stuffing / brute-force with username enumeration"
        if actor in bruteforce:
            return "SSH brute-force"
        if actor in username_enum:
            return "Username enumeration"
        if actor in malicious_ips:
            return "Known malicious source (no local pattern match)"
        return "Unclassified"

    label = "sudo" if log_type == "sudo" else "su"
    if breached and actor in bruteforce:
        return f"Local privilege escalation via {label} with successful compromise"
    if actor in bruteforce:
        return f"Repeated failed {label} attempts (possible local brute-force)"
    return "Unclassified"


def build_narrative(actor, log_type, bruteforce, username_enum, malicious_ips, timeline, geoip=None):
    is_bf = actor in bruteforce
    is_ue = actor in username_enum
    is_mal = actor in malicious_ips
    breached = bool(timeline and timeline.get("breached"))
    verb = {"sshd": "SSH", "sudo": "sudo", "su": "su"}[log_type]

    sentences = []

    if breached:
        attempts = timeline["failed_attempts"]
        if log_type == "sshd":
            sentences.append(f"{actor} gained access to this host after {attempts} failed {verb} attempt(s).")
        else:
            sentences.append(f"{actor} obtained {verb} privileges after {attempts} failed attempt(s).")
    elif is_bf and is_ue:
        bf, ue = bruteforce[actor], username_enum[actor]
        sentences.append(
            f"{actor} combined a {bf['count']}-attempt password-guessing burst with enumeration across "
            f"{ue['distinct_usernames']} usernames, a pattern typical of credential stuffing."
        )
    elif is_bf:
        bf = bruteforce[actor]
        sentences.append(f"{actor} made {bf['count']} failed {verb} attempts, well past normal retry behavior.")
    elif is_ue:
        ue = username_enum[actor]
        names = ", ".join(ue["usernames"][:5])
        more = "..." if len(ue["usernames"]) > 5 else ""
        sentences.append(f"{actor} cycled through {ue['distinct_usernames']} usernames ({names}{more}) rather than targeting one account.")
    elif is_mal:
        data = malicious_ips[actor]
        sentences.append(
            f"{actor} shows no local attack pattern here but is flagged by AbuseIPDB at "
            f"{data.get('abuseConfidenceScore', 0)}% confidence."
        )
    else:
        return f"{actor} did not meet any detection threshold; included for context only."

    if breached and (is_bf or is_ue):
        parts = []
        if is_bf:
            parts.append(f"{bruteforce[actor]['count']} failed attempts")
        if is_ue:
            parts.append(f"{username_enum[actor]['distinct_usernames']} usernames tried")
        sentences.append(f"That followed {' and '.join(parts)}.")
    elif not breached and timeline:
        sentences.append(f"No login was accepted across {timeline['total_attempts']} attempt(s).")

    if is_mal and (breached or is_bf or is_ue):
        data = malicious_ips[actor]
        country = data.get("countryCode")
        loc = f" ({country})" if country else ""
        sentences.append(
            f"AbuseIPDB independently lists this host at {data.get('abuseConfidenceScore', 0)}% "
            f"confidence from {data.get('totalReports', 0)} report(s){loc}."
        )

    if geoip and actor in geoip:
        g = geoip[actor]
        bits = [b for b in [g.get("city"), g.get("regionName"), g.get("country")] if b]
        if bits:
            sentences.append(f"Geolocated to {', '.join(bits)}.")

    return " ".join(sentences)


def build_executive_summary(ip_scores):
    if not ip_scores:
        return {
            "threat_level": "Informational",
            "confidence": 0,
            "primary_attack_type": "No significant activity detected",
            "mitre_techniques": [],
            "headline_ip": None,
            "headline_actor_type": None,
        }

    ranked = sorted(ip_scores.values(), key=lambda s: (-s["score"], s["actor"]))
    top = ranked[0]

    seen = set()
    techniques = []
    for result in ranked:
        for tech in result["mitre"]:
            if tech["id"] not in seen:
                seen.add(tech["id"])
                techniques.append(tech)

    return {
        "threat_level": top["level"],
        "confidence": top["score"],
        "primary_attack_type": top["attack_type"],
        "mitre_techniques": techniques,
        "headline_ip": top["actor"],
        "headline_actor_type": "ip" if top["log_type"] == "sshd" else "user",
    }
