from log_analyzer.detector import build_session_timeline
from log_analyzer.report.scoring import (
    build_executive_summary,
    build_narrative,
    score_ip,
    threat_level,
)
from tests.conftest import make_event


def test_threat_level_bands():
    assert threat_level(0) == "Informational"
    assert threat_level(10) == "Low"
    assert threat_level(20) == "Medium"
    assert threat_level(40) == "High"
    assert threat_level(70) == "Critical"
    assert threat_level(100) == "Critical"


def test_score_ip_accumulates_points_across_signals():
    bruteforce = {"1.1.1.1": {"count": 10, "window_start": "2026-01-01 00:00:00", "window_end": "2026-01-01 00:02:00"}}
    username_enum = {"1.1.1.1": {"distinct_usernames": 6, "usernames": ["a", "b"], "window_start": "x", "window_end": "y"}}
    malicious_ips = {"1.1.1.1": {"abuseConfidenceScore": 90, "totalReports": 50, "countryCode": "DE"}}
    events = [
        make_event("2026-01-01 00:00:00", "Failed", "1.1.1.1"),
        make_event("2026-01-01 00:00:05", "Accepted", "1.1.1.1"),
    ]
    timeline = build_session_timeline(events, "1.1.1.1")

    result = score_ip("1.1.1.1", "sshd", bruteforce, username_enum, malicious_ips, timeline)

    assert result["score"] == 100
    assert result["level"] == "Critical"
    assert len(result["mitre"]) == 4
    assert all(row["met"] for row in result["checklist"])


def test_score_ip_no_signals_scores_zero():
    result = score_ip("9.9.9.9", "sshd", {}, {}, {}, None)
    assert result["score"] == 0
    assert result["level"] == "Informational"
    assert all(not row["met"] for row in result["checklist"])


def test_score_ip_partial_signals_only_awards_matched_points():
    bruteforce = {"2.2.2.2": {"count": 8, "window_start": "x", "window_end": "y"}}
    result = score_ip("2.2.2.2", "sshd", bruteforce, {}, {}, None)
    assert result["score"] == 30
    assert result["level"] == "Medium"


def test_score_ip_sudo_bruteforce_maps_to_sudo_specific_technique():
    bruteforce = {"alice": {"count": 8, "window_start": "x", "window_end": "y"}}
    result = score_ip("alice", "sudo", bruteforce, {}, {}, None)
    assert result["score"] == 30
    assert result["mitre"][0]["id"] == "T1548.003"


def test_score_ip_su_bruteforce_maps_to_password_guessing():
    bruteforce = {"root": {"count": 8, "window_start": "x", "window_end": "y"}}
    result = score_ip("root", "su", bruteforce, {}, {}, None)
    assert result["mitre"][0]["id"] == "T1110.001"


def test_build_narrative_mentions_bruteforce_and_breach():
    bruteforce = {"1.1.1.1": {"count": 10, "window_start": "2026-01-01 00:00:00", "window_end": "2026-01-01 00:02:00"}}
    events = [
        make_event("2026-01-01 00:00:00", "Failed", "1.1.1.1"),
        make_event("2026-01-01 00:00:05", "Accepted", "1.1.1.1"),
    ]
    timeline = build_session_timeline(events, "1.1.1.1")

    narrative = build_narrative("1.1.1.1", "sshd", bruteforce, {}, {}, timeline)

    assert "1.1.1.1" in narrative
    assert "gained access" in narrative
    assert "across the full session" in narrative
    assert "The single densest window alone included 10 failed attempts." in narrative


def test_build_narrative_uses_sudo_specific_wording():
    bruteforce = {"alice": {"count": 6, "window_start": "x", "window_end": "y"}}
    narrative = build_narrative("alice", "sudo", bruteforce, {}, {}, None)
    assert "failed sudo attempts" in narrative


def test_build_narrative_handles_no_signals():
    narrative = build_narrative("3.3.3.3", "sshd", {}, {}, {}, None)
    assert "3.3.3.3" in narrative
    assert "did not meet any detection threshold" in narrative


def test_build_narrative_combines_bruteforce_and_enumeration_lead():
    bruteforce = {"1.1.1.1": {"count": 12, "window_start": "x", "window_end": "y"}}
    username_enum = {"1.1.1.1": {"distinct_usernames": 7, "usernames": ["a", "b", "c"], "window_start": "x", "window_end": "y"}}
    narrative = build_narrative("1.1.1.1", "sshd", bruteforce, username_enum, {}, None)
    assert "credential stuffing" in narrative
    assert "12-attempt" in narrative
    assert "7 usernames" in narrative


def test_build_narrative_malicious_only_no_local_pattern():
    malicious_ips = {"5.5.5.5": {"abuseConfidenceScore": 95, "totalReports": 20, "countryCode": "RU"}}
    narrative = build_narrative("5.5.5.5", "sshd", {}, {}, malicious_ips, None)
    assert "no local attack pattern" in narrative
    assert "95%" in narrative


def test_build_executive_summary_picks_highest_scoring_ip():
    ip_scores = {
        "1.1.1.1": score_ip("1.1.1.1", "sshd", {"1.1.1.1": {"count": 10, "window_start": "x", "window_end": "y"}}, {}, {}, None),
        "2.2.2.2": score_ip("2.2.2.2", "sshd", {}, {}, {"2.2.2.2": {"abuseConfidenceScore": 90, "totalReports": 5}}, None),
    }
    summary = build_executive_summary(ip_scores)

    assert summary["headline_ip"] == "2.2.2.2"
    assert summary["confidence"] == 40
    assert summary["mitre_techniques"]


def test_build_executive_summary_empty_when_nothing_flagged():
    summary = build_executive_summary({})
    assert summary["threat_level"] == "Informational"
    assert summary["headline_ip"] is None
    assert summary["mitre_techniques"] == []


def test_build_executive_summary_breaks_ties_deterministically_by_actor():
    ip_scores = {
        "9.9.9.9": score_ip("9.9.9.9", "sshd", {"9.9.9.9": {"count": 10, "window_start": "x", "window_end": "y"}}, {}, {"9.9.9.9": {"abuseConfidenceScore": 90, "totalReports": 5}}, None),
        "1.1.1.1": score_ip("1.1.1.1", "sshd", {"1.1.1.1": {"count": 10, "window_start": "x", "window_end": "y"}}, {}, {"1.1.1.1": {"abuseConfidenceScore": 90, "totalReports": 5}}, None),
        "5.5.5.5": score_ip("5.5.5.5", "sshd", {"5.5.5.5": {"count": 10, "window_start": "x", "window_end": "y"}}, {}, {"5.5.5.5": {"abuseConfidenceScore": 90, "totalReports": 5}}, None),
    }
    for _ in range(5):
        summary = build_executive_summary(ip_scores)
        assert summary["headline_ip"] == "1.1.1.1"
