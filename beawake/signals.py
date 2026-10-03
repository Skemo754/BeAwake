"""Deterministic scam signals: plain code, no AI."""
import re
import unicodedata
from urllib.parse import urlparse

SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "goo.gl", "ow.ly")
RISKY_TLDS = {"top", "xyz", "click", "support", "icu", "buzz", "rest", "cfd", "sbs", "info", "online",
              "site", "live", "work", "vip", "cc", "tk", "ml", "ga", "cf", "gq"}
DOMAIN_WORDS = ("verify", "login", "pay", "fee", "billing", "secure", "update", "odeme", "itiraz", "giris", "toll")
TLDS = "|".join(["com", "net", "org", "io", "me", "ly", "co", "app", "link", "gov", "edu", "tr"] + sorted(RISKY_TLDS))
TRAILING = ".,;:!?)\"'»،؟"
ORDER = {"safe": 0, "suspicious": 1, "scam": 2}
STRONG = {"shortened_link", "ip_link", "suspicious_domain", "credential_request", "prize", "impersonation", "fee_demand"}


def _norm(s: str) -> str:
    """Lowercase, strip diacritics, unify Arabic letter variants (tıklayın == tiklayin, أ == ا)."""
    s = s.replace("’", "'").replace("İ", "i").replace("ı", "i")
    s = unicodedata.normalize("NFKD", s.casefold())
    s = "".join(c for c in s if not unicodedata.combining(c))
    return s.replace("ى", "ي").replace("ة", "ه")


def _rx(*parts: str) -> re.Pattern:
    # Not preceded by a Latin letter/digit; Arabic prefixes (و، ب، ل) are allowed on purpose.
    return re.compile(r"(?<![a-z0-9])(?:" + "|".join(parts) + ")")


URGENCY = _rx("hemen", "acil", "derhal", "son gun", "urgent", "immediately", "right away",
              r"\d+ ?(?:saat|hours?|ساع)", "فورا", "عاجل", "حالا")
THREAT = _rx("bloke", "askiya", "kapatilacak", "icra", "haciz", "suspended", "locked", "cancellation",
             r"account (?:is |has been )?(?:blocked|closed)", "ايقاف", "تعليق", "تعطيل")
PRIZE = _rx("kazandiniz", "cekilis", "odul", r"you(?:'ve| have)? won", "selected for", "gift card",
            "free iphone", "lottery", "prize", "claim your", "فزت", "ربحت", "جايزه")
NEW_NUMBER = _rx("yeni numara", "numaram", "new number", "lost my phone", "broke my phone", "telefonum bozuldu",
                 "رقمي الجديد", "رقم جديد", "جوالي انكسر", "جوالي خرب")
MONEY_ASK = re.compile(
    r"\d[\d.,]*\s?(?:tl|lira|usd|eur|euro|dollars?|dolar|دولار|ريال|درهم|جنيه|ليره)|[$€£]\s?\d"
    r"|تحويل|حواله|havale|\biban\b|\bwire\b|\btransfer\b|gonder|send (?:me )?\$")
SENSITIVE = _rx("sifre", "password", r"\bpin\b", r"\botp\b", r"\bcvv\b", "dogrulama kod", "kart bilgi",
                "kart numara", "tc kimlik", "kimlik no", r"\biban\b", "verification code", "security code",
                "card number", "bank account", "account number", "passport", "pasaport",
                r"كلمه (?:ال)?(?:مرور|سر)", "الرقم السري", "رقم سري", "رمز التحقق", "كود التحقق", "رقم بطاق",
                "رقم حساب", "جواز")
REQUEST = _rx("send", "reply", "share", "give", "provide", "enter", "submit", "confirm", "iletin", "gonder",
              "paylasin", "yanitla", "girin", "bildirin", "ارسل", "شارك", "اعط", "ادخل", "سجل", "ابعت", "اكتب")
NEGATION = re.compile(
    r"(?:do not|don't|dont|never|not) (?:share|tell|give|send|disclose)|kimseyle|paylasma|asla"
    r"|لا ?(?:تشار|تعط|تخبر|ترسل|تفصح)")
FEE = _rx("fee", "ucret", "rusum", "gumruk", "customs", "رسوم")
PAY_VERB = _rx(r"pay\b", "paying", "odeyin", "odeme yap", "ادفع", "دفع")
URL_RE = re.compile(
    r"(?:https?://|www\.)\S+|(?<![\w@.-])(?:[a-z0-9-]+\.)+(?:" + TLDS + r")\b(?:/\S*)?", re.I)
IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def _credential_request(norm: str) -> bool:
    """A sensitive item is being asked for: a request verb nearby and no 'do not share' next to it."""
    for m in SENSITIVE.finditer(norm):
        window = norm[max(0, m.start() - 45): m.end() + 45]
        if not NEGATION.search(window) and REQUEST.search(window):
            return True
    return False


def find_signals(text: str) -> list[str]:
    found = set()
    for url in (u.rstrip(TRAILING) for u in URL_RE.findall(text)):
        found.add("link")
        host = (urlparse(url if "//" in url else "//" + url).hostname or "").removeprefix("www.")
        if host in SHORTENERS:
            found.add("shortened_link")
        elif IP_RE.fullmatch(host):
            found.add("ip_link")
        elif host.rsplit(".", 1)[-1] in RISKY_TLDS or ("-" in host and any(w in host for w in DOMAIN_WORDS)):
            found.add("suspicious_domain")
    norm = _norm(text)
    checks = {
        "urgency": URGENCY.search(norm),
        "threat": THREAT.search(norm),
        "prize": PRIZE.search(norm),
        "impersonation": NEW_NUMBER.search(norm) and MONEY_ASK.search(norm),
        "credential_request": _credential_request(norm),
        "fee_demand": FEE.search(norm) and PAY_VERB.search(norm),
    }
    found.update(name for name, hit in checks.items() if hit)
    return sorted(found)


def rules_verdict(signals) -> str:
    """The rules' own opinion. Strong signals need no help; weak ones only count together."""
    s = set(signals)
    strong = s & STRONG
    if len(strong) >= 2 or (strong and s & {"urgency", "threat"}):
        return "scam"
    if strong or ("link" in s and s & {"urgency", "threat"}):
        return "suspicious"
    return "safe"


def apply_floor(verdict: str, signals) -> str:
    """Never let the model's verdict sit below the rules' verdict. Only raises, never lowers."""
    r = rules_verdict(signals)
    return r if ORDER[r] > ORDER[verdict] else verdict
