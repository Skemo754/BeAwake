"""BeAwake: paste a suspicious message, get a plain verdict. Runs fully locally."""
import gradio as gr

from beawake.checker import check

LABELS = {
    "safe": "🟢 Looks safe / Güvenli görünüyor / تبدو آمنة",
    "suspicious": "🟠 Suspicious / Şüpheli / مشبوهة",
    "scam": "🔴 Likely a scam / Büyük olasılıkla dolandırıcılık / احتيال على الأرجح",
}


def run(text: str):
    if not text.strip():
        return "", "", "", ""
    try:
        r = check(text)
    except RuntimeError as e:
        raise gr.Error(str(e))
    return LABELS[r["verdict"]], r["reason"], r["action"], ", ".join(r["signals"]) or "-"


demo = gr.Interface(
    fn=run,
    inputs=gr.Textbox(lines=6, label="Message / Mesaj / الرسالة"),
    outputs=[
        gr.Textbox(label="Verdict"),
        gr.Textbox(label="Why"),
        gr.Textbox(label="What to do"),
        gr.Textbox(label="Signals found by code"),
    ],
    title="BeAwake",
    description="Runs fully on this computer with a local Gemma model. Nothing is sent online. "
                "It is a second opinion, not a guarantee: when in doubt, call the sender using a number you already trust.",
    examples=[
        ["Hesabiniz bloke edildi, hemen su linke tiklayin: bit.ly/abc123"],
        ["تم إيقاف حسابك البنكي، اضغط على الرابط فورًا لتأكيد بياناتك: bit.ly/x9"],
        ["Yarin aksam yemege gelir misin?"],
    ],
)

if __name__ == "__main__":
    demo.launch(server_name="127.0.0.1")
