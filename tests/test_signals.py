from beawake.signals import apply_floor, find_signals, rules_verdict


def test_turkish_scam():
    s = find_signals("Hesabiniz bloke edildi, hemen su linke tiklayin: bit.ly/abc123")
    assert {"shortened_link", "urgency", "threat"} <= set(s)
    assert rules_verdict(s) == "scam"


def test_arabic_scam():
    s = find_signals("تم إيقاف حسابك البنكي، اضغط على الرابط فورًا لتأكيد بياناتك: bit.ly/x9")
    assert {"shortened_link", "urgency", "threat"} <= set(s)


def test_ip_link():
    assert "ip_link" in find_signals("Pay now: http://192.168.1.5/pay")


def test_lookalike_domain():
    assert "suspicious_domain" in find_signals("Verify: apple-id-verify.top/login")


def test_clean_message_has_no_signals():
    assert find_signals("Yarin aksam yemege gelir misin?") == []


def test_normal_link_is_only_a_link():
    assert find_signals("Notes: https://docs.example.com/a") == ["link"]
    assert rules_verdict(["link"]) == "safe"


def test_real_verification_codes_are_not_requests():
    assert "credential_request" not in find_signals("Your verification code is 904112. Don't share it with anyone.")
    assert "credential_request" not in find_signals("رمز التحقق الخاص بك هو 553821. لا تشاركه مع أحد.")
    assert "credential_request" not in find_signals("Dogrulama kodunuz: 482915. Bu kodu kimseyle paylasmayin.")


def test_asking_for_a_code_is_a_request():
    assert "credential_request" in find_signals("Please reply with your password to keep your account")
    assert "credential_request" in find_signals("أرسل رقم بطاقتك ورمز التحقق إلى هذا الرقم")


def test_new_number_needs_a_money_ask():
    assert "impersonation" in find_signals("Mom, this is my new number. Can you send $400?")
    assert "impersonation" not in find_signals("Hi, this is my new number, save it")


def test_floor_only_raises():
    assert apply_floor("safe", ["link", "urgency"]) == "suspicious"
    assert apply_floor("safe", ["shortened_link", "urgency"]) == "scam"
    assert apply_floor("safe", []) == "safe"
    assert apply_floor("scam", []) == "scam"
    assert apply_floor("suspicious", []) == "suspicious"
