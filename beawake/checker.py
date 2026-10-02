"""The full pipeline: code signals -> Gemma -> safety floor."""
from .llm import check_message
from .signals import apply_floor, find_signals


def check(text: str) -> dict:
    signals = find_signals(text)
    result = check_message(text, signals)
    result["model_verdict"] = result["verdict"]
    result["verdict"] = apply_floor(result["verdict"], signals)
    result["signals"] = signals
    return result
