"""Deterministic scam signals: plain code, no AI."""
import re
import unicodedata
from urllib.parse import urlparse

SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "goo.gl", "ow.ly")
TRAILING = ".,;:!?)\"'»،؟"


def _norm(s: str) -> str:
    """Lowercase and strip diacritics so 'tıklayın' == 'tiklayin' and Arabic tashkeel is ignored."""
    s = unicodedata.normalize("NFKD", s.replace("İ", "i").replace("ı", "i").casefold())
    s = "".join(c for c in s if not unicodedata.combining(c))
    return s.replace("ى", "ي").replace("ة", "ه")


_WORDS = {
    "urgency": ["hemen", "acil", "derhal", "son gun", "urgent", "immediately", "right away",
                "within 24", "فورا", "عاجل", "حالا", "خلال 24"],
    "credential_request": ["sifre", "cvv", "dogrulama kodu", "kart bilgi", "tc kimlik", "password",
                           "pin code", "verification code", "card number", "otp", "كلمة المرور",
                           "رمز التحقق", "الرقم السري", "رقم البطاقة", "تأكيد بيانات"],
    "threat_or_prize": ["hesabiniz bloke", "hesabiniz askiya", "kazandiniz", "odul", "account suspended",
                        "account blocked", "you won", "prize", "تم إيقاف", "تم تعليق", "ربحت", "جائزة"],
}
KEYWORDS = {
    k: re.compile(r"(?<!\w)(?:" + "|".join(re.escape(_norm(w)) for w in ws) + ")")
    for k, ws in _WORDS.items()
}
URL_RE = re.compile(
    r"(?:https?://|www\.)\S+|(?<![\w.-])(?:" + "|".join(map(re.escape, SHORTENERS)) + r")/\S*", re.I
)
IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def find_signals(text: str) -> list[str]:
    found = set()
    for url in (u.rstrip(TRAILING) for u in URL_RE.findall(text)):
        found.add("link")
        host = (urlparse(url if "//" in url else "//" + url).hostname or "").removeprefix("www.")
        if host in SHORTENERS:
            found.add("shortened_link")
        elif IP_RE.fullmatch(host):
            found.add("ip_link")
    norm = _norm(text)
    found.update(name for name, rx in KEYWORDS.items() if rx.search(norm))
    return sorted(found)


def apply_floor(verdict: str, signals: list[str]) -> str:
    """Never let a risky-looking message stay 'safe'. Only raises, never lowers."""
    s = set(signals)
    risky = bool(s & {"shortened_link", "ip_link"}) or ("link" in s and bool(s & {"urgency", "credential_request"}))
    return "suspicious" if verdict == "safe" and risky else verdict
