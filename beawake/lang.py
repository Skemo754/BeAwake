"""Pick the language the answer must be written in."""
import re

_ARABIC = re.compile(r"[\u0600-\u06FF]")
_ENGLISH = {"the", "you", "your", "and", "this", "please", "with", "can", "will", "have", "our", "from",
            "we", "are", "for", "my", "not", "it", "of", "to", "is", "in", "be", "by", "or", "if", "has",
            "was", "been", "reply", "time", "now", "meeting"}
OTHER = "the same language as the message (only Turkish or English, never Spanish)"


def reply_language(text: str) -> str:
    """Name Arabic and English explicitly (a model once answered an English message in Spanish);
    anything else (Turkish) falls back to the message's own language, with Spanish ruled out."""
    if _ARABIC.search(text):
        return "Arabic"
    text = re.sub(r"https?://\S+", " ", text.lower())
    return "English" if sum(w in _ENGLISH for w in re.findall(r"[a-z]+", text)) >= 2 else OTHER
