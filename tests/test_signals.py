from beawake.signals import apply_floor, find_signals


def test_turkish_scam():
    s = find_signals("Hesabiniz bloke edildi, hemen su linke tiklayin: bit.ly/abc123")
    assert {"shortened_link", "urgency", "threat_or_prize"} <= set(s)


def test_arabic_scam():
    s = find_signals("تم إيقاف حسابك البنكي، اضغط على الرابط فورًا لتأكيد بياناتك: bit.ly/x9")
    assert {"shortened_link", "urgency", "threat_or_prize"} <= set(s)


def test_ip_link():
    assert "ip_link" in find_signals("Pay now: http://192.168.1.5/pay")


def test_clean_message_has_no_signals():
    assert find_signals("Yarin aksam yemege gelir misin?") == []


def test_normal_link_is_only_a_link():
    assert find_signals("Toplanti notlari: https://docs.example.com/a") == ["link"]


def test_floor_only_raises():
    assert apply_floor("safe", ["link", "urgency"]) == "suspicious"
    assert apply_floor("safe", []) == "safe"
    assert apply_floor("scam", []) == "scam"
