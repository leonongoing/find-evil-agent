"""Tests for confidence scoring engine."""
import sys
sys.path.insert(0, '/home/taomi/projects/find-evil-agent')

from src.confidence import ConfidenceScorer, Finding, Evidence


def test_empty_evidence():
    scorer = ConfidenceScorer()
    score = scorer.score([])
    assert score == 0, f"Expected 0, got {score}"
    print("✅ test_empty_evidence passed")


def test_single_high_reliability_tool():
    scorer = ConfidenceScorer()
    ev = Evidence(tool="volatility3", command="vol -f mem.raw windows.pslist", raw_output="PID 1234 malware.exe")
    score = scorer.score([ev])
    assert score >= 50, f"Expected >= 50, got {score}"
    print(f"✅ test_single_high_reliability_tool passed (score={score})")


def test_failed_tool_penalized():
    scorer = ConfidenceScorer()
    ev = Evidence(tool="volatility3", command="vol -f mem.raw windows.pslist", raw_output="error", exit_code=1)
    score = scorer.score([ev])
    assert score < 30, f"Expected < 30 for failed tool, got {score}"
    print(f"✅ test_failed_tool_penalized passed (score={score})")


def test_corroboration_increases_score():
    scorer = ConfidenceScorer()
    ev1 = Evidence(tool="volatility3", command="vol pslist", raw_output="malware.exe")
    ev2 = Evidence(tool="tshark", command="tshark -r cap.pcap", raw_output="malware.exe -> C2")
    score_single = scorer.score([ev1])
    score_corroborated = scorer.score([ev1, ev2])
    assert score_corroborated > score_single, f"Corroboration should increase score: {score_single} -> {score_corroborated}"
    print(f"✅ test_corroboration_increases_score passed ({score_single} -> {score_corroborated})")


def test_hash_ioc_bonus():
    scorer = ConfidenceScorer()
    ev = Evidence(tool="yara", command="yara rules.yar file.exe", raw_output="match")
    sha256 = "a" * 64
    score_no_ioc = scorer.score([ev])
    score_with_hash = scorer.score([ev], iocs=[sha256])
    assert score_with_hash > score_no_ioc, f"Hash IOC should increase score"
    print(f"✅ test_hash_ioc_bonus passed ({score_no_ioc} -> {score_with_hash})")


def test_confidence_labels():
    f = Finding("F001", "test", "desc", 95, "high")
    assert f.confidence_label() == "CONFIRMED"
    f.confidence = 75
    assert f.confidence_label() == "HIGH"
    f.confidence = 55
    assert f.confidence_label() == "MEDIUM"
    f.confidence = 35
    assert f.confidence_label() == "LOW"
    f.confidence = 15
    assert f.confidence_label() == "SPECULATIVE"
    print("✅ test_confidence_labels passed")


if __name__ == "__main__":
    test_empty_evidence()
    test_single_high_reliability_tool()
    test_failed_tool_penalized()
    test_corroboration_increases_score()
    test_hash_ioc_bonus()
    test_confidence_labels()
    print("\n✅ All confidence tests passed!")
