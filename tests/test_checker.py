from beawake import checker


def test_floor_overrides_a_safe_model_verdict(monkeypatch):
    fake = {"verdict": "safe", "reason": "", "action": "", "raw": ""}
    monkeypatch.setattr(checker, "check_message", lambda text: fake.copy())
    r = checker.check("Hemen tikla: bit.ly/x")
    assert r["verdict"] == "scam" and r["model_verdict"] == "safe"
