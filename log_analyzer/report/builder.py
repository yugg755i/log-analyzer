from collections import Counter, defaultdict
from datetime import datetime, timedelta

from log_analyzer.detector import (
    accepted_events,
    build_session_timeline,
    count_ips,
    detect_bruteforce,
    detect_username_enumeration,
    failed_events,
    top_ips,
)
from log_analyzer.enrichment import is_malicious
from log_analyzer.report.scoring import (
    build_executive_summary,
    build_narrative,
    score_ip,
)

EVIDENCE_LINE_LIMIT = 8


def _collect_evidence(events, actor, bruteforce, limit=EVIDENCE_LINE_LIMIT):
    actor_events = [e for e in events if e["actor"] == actor]

    window = bruteforce.get(actor)
    if window:
        windowed = [
            e for e in actor_events
            if window["window_start"] <= e["timestamp"] <= window["window_end"]
        ]
        if windowed:
            actor_events = windowed

    return [e["raw_line"] for e in actor_events[:limit] if e.get("raw_line")]


def _timeline_points(events, actor):
    actor_events = sorted((e for e in events if e["actor"] == actor), key=lambda e: e["timestamp"])
    if not actor_events:
        return []

    first = datetime.strptime(actor_events[0]["timestamp"], "%Y-%m-%d %H:%M:%S")
    last = datetime.strptime(actor_events[-1]["timestamp"], "%Y-%m-%d %H:%M:%S")
    duration = (last - first).total_seconds()

    points = []
    for e in actor_events:
        ts = datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S")
        offset_pct = 0.0 if duration == 0 else round((ts - first).total_seconds() / duration * 100, 2)
        points.append({
            "offset_pct": offset_pct,
            "status": e["status"],
            "timestamp": e["timestamp"],
            "user": e["user"],
        })
    return points


def _hourly_histogram(events):
    buckets = Counter()
    for e in events:
        ts = datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S")
        bucket_key = ts.strftime("%Y-%m-%d %H:00")
        buckets[bucket_key] += 1

    ordered_keys = sorted(buckets.keys())
    return [{"hour": k, "count": buckets[k]} for k in ordered_keys]


def _partition_by_log_type(events):
    by_log_type = defaultdict(list)
    for e in events:
        by_log_type[e["log_type"]].append(e)
    return by_log_type


def _log_type_breakdown(by_log_type):
    return {
        log_type: {
            "total": len(evs),
            "failed": len(failed_events(evs)),
            "accepted": len(accepted_events(evs)),
        }
        for log_type, evs in by_log_type.items()
    }


def _accepted_after_bruteforce(by_log_type, combined_bruteforce, grace_minutes):
    results = []
    grace = timedelta(minutes=grace_minutes)

    for data in combined_bruteforce.values():
        log_type, actor = data["log_type"], data["actor"]
        window_end = datetime.strptime(data["window_end"], "%Y-%m-%d %H:%M:%S")
        cutoff = window_end + grace

        for e in by_log_type.get(log_type, []):
            if e["actor"] != actor or e["status"] != "Accepted":
                continue
            ts = datetime.strptime(e["timestamp"], "%Y-%m-%d %H:%M:%S")
            if window_end <= ts <= cutoff:
                results.append(e)

    return results


def build_report_context(
    events,
    source_files,
    bruteforce_threshold=5,
    bruteforce_window_minutes=2,
    enum_threshold=5,
    enum_window_minutes=2,
    abuse_data=None,
    geoip_data=None,
    confidence_threshold=50,
):
    abuse_data = abuse_data or {}
    geoip_data = geoip_data or {}

    failed = failed_events(events)
    accepted = accepted_events(events)

    by_log_type = _partition_by_log_type(events)
    ssh_events = by_log_type.get("sshd", [])

    malicious_ips = {
        ip: data for ip, data in abuse_data.items()
        if is_malicious(data, confidence_threshold)
    }

    bruteforce_by_type = {}
    username_enum_by_type = {}
    combined_bruteforce = {}
    combined_username_enum = {}

    for log_type, type_events in by_log_type.items():
        bf = detect_bruteforce(type_events, threshold=bruteforce_threshold, window_minutes=bruteforce_window_minutes)
        ue = detect_username_enumeration(type_events, threshold=enum_threshold, window_minutes=enum_window_minutes)
        bruteforce_by_type[log_type] = bf
        username_enum_by_type[log_type] = ue
        for actor, data in bf.items():
            combined_bruteforce[f"{log_type}::{actor}"] = {**data, "log_type": log_type, "actor": actor}
        for actor, data in ue.items():
            combined_username_enum[f"{log_type}::{actor}"] = {**data, "log_type": log_type, "actor": actor}

    malicious_by_type = defaultdict(dict)
    malicious_by_type["sshd"] = malicious_ips

    timestamps = [e["timestamp"] for e in events]
    time_range = (min(timestamps), max(timestamps)) if timestamps else (None, None)

    flagged_keys = set(combined_bruteforce) | set(combined_username_enum)
    flagged_keys |= {f"sshd::{ip}" for ip in malicious_ips}

    def _key_parts(key):
        log_type, actor = key.split("::", 1)
        return log_type, actor

    timelines = {}
    ip_scores = {}
    narratives = {}
    evidence = {}
    timeline_points = {}

    for key in flagged_keys:
        log_type, actor = _key_parts(key)
        type_events = by_log_type.get(log_type, [])
        bf = bruteforce_by_type.get(log_type, {})
        ue = username_enum_by_type.get(log_type, {})
        mal = malicious_by_type.get(log_type, {})

        timeline = build_session_timeline(type_events, actor)
        timelines[key] = timeline
        ip_scores[key] = score_ip(actor, log_type, bf, ue, mal, timeline)
        narratives[key] = build_narrative(actor, log_type, bf, ue, mal, timeline, geoip_data if log_type == "sshd" else None)
        evidence[key] = _collect_evidence(type_events, actor, bf)
        timeline_points[key] = _timeline_points(type_events, actor)

    executive_summary = build_executive_summary(ip_scores)
    investigation_order = sorted(flagged_keys, key=lambda k: (-ip_scores[k]["score"], ip_scores[k]["actor"]))

    verdict = _build_verdict(malicious_ips, combined_bruteforce, combined_username_enum)

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_files": [str(f) for f in source_files],
        "time_range": time_range,
        "total_events": len(events),
        "total_failed": len(failed),
        "total_accepted": len(accepted),
        "unique_ips": len(count_ips(ssh_events)),
        "top_ips": top_ips(ssh_events, n=10),
        "log_type_breakdown": _log_type_breakdown(by_log_type),
        "bruteforce": sorted(combined_bruteforce.items(), key=lambda kv: -kv[1]["count"]),
        "bruteforce_threshold": bruteforce_threshold,
        "bruteforce_window_minutes": bruteforce_window_minutes,
        "username_enum": sorted(combined_username_enum.items(), key=lambda kv: -kv[1]["distinct_usernames"]),
        "enum_threshold": enum_threshold,
        "enum_window_minutes": enum_window_minutes,
        "malicious_ips": malicious_ips,
        "accepted_after_bruteforce": _accepted_after_bruteforce(by_log_type, combined_bruteforce, grace_minutes=bruteforce_window_minutes),
        "timelines": timelines,
        "hourly_histogram": _hourly_histogram(events),
        "verdict": verdict,
        "ip_scores": ip_scores,
        "narratives": narratives,
        "evidence": evidence,
        "timeline_points": timeline_points,
        "executive_summary": executive_summary,
        "investigation_order": investigation_order,
        "geoip": geoip_data,
    }


def _build_verdict(malicious_ips, combined_bruteforce, combined_username_enum):
    if not (malicious_ips or combined_bruteforce or combined_username_enum):
        return (
            "No evidence of brute-force activity, username enumeration, or confirmed malicious "
            "infrastructure was identified during the analysis window."
        )

    lead = None
    trailing = []

    if combined_bruteforce:
        n = len(combined_bruteforce)
        lead = f"Brute-force authentication activity was detected from {n} {'actor' if n == 1 else 'actors'}"

    if combined_username_enum:
        n = len(combined_username_enum)
        phrase = f"enumeration from {n} {'actor' if n == 1 else 'actors'}"
        (trailing if lead else None)
        if lead:
            trailing.append(phrase)
        else:
            lead = f"Username enumeration was observed from {n} {'actor' if n == 1 else 'actors'}"

    if malicious_ips:
        n = len(malicious_ips)
        if lead:
            trailing.append(f"{n} {'IP' if n == 1 else 'IPs'} independently confirmed malicious via AbuseIPDB")
        else:
            lead = f"Threat intelligence confirmed {n} malicious source {'IP' if n == 1 else 'IPs'}"

    if not trailing:
        return lead + "."
    if len(trailing) == 1:
        return f"{lead}, with {trailing[0]}."
    return f"{lead}, with {', '.join(trailing[:-1])} and {trailing[-1]}."
