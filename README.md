# BeAwake

A second opinion on suspicious messages, running entirely on your own computer.

Paste an SMS, WhatsApp message or email. BeAwake tells you whether it looks **safe**, **suspicious** or like a **scam**, why, and what to do next, in the language of the message (tested in Turkish, Arabic and English). Nothing leaves the laptop: the model is a local Gemma served by `llama.cpp`.

Built for the DEV Hacktoberfest 2026 Weekend Challenge, *Build for a Friend*.

<!-- TODO: add screenshots, e.g. docs/screenshot-tr.png and docs/screenshot-ar.png -->

## Who it is for

My Turkish friend and my family. They receive messages that pretend to be a bank, a courier or a relative, in Turkish, Arabic and English. Pasting those messages (names, phone numbers, sometimes card details) into an online tool would mean sending private data to a server they don't control. So this runs locally.

## How it works

```
message -> Gemma (local llama-server) -> verdict + reason + action
message -> plain-code signals (links, lookalike domains, requests for codes, urgency...)
                          |
                          v
   safety floor: the final verdict is never lower than the rules' own verdict
```

- **Gemma does the judging.** It reads the message and explains in the message's language. The prompt defines each verdict: ordinary messages (appointments, deliveries, bills, shared files, one-time codes that say "don't share") are `safe`, and a link or phone number alone is not a reason for suspicion.
- **Plain code adds context-aware signals.** It checks for shortened and IP links, lookalike domains, prizes, fee demands, and "new number + money" impersonation. A request for a code only counts if a request verb is next to it and it is not negated, so a real "your code is 123456, don't share it" is not flagged.
- **The floor only raises, never lowers.** Calling a scam "safe" is the worst mistake.
- **Reply language is decided in code.** English and Arabic are named explicitly in the prompt. In an earlier version, English messages sometimes got Spanish answers.
- **Thinking mode is off** (`enable_thinking: false`): with it on, a short answer took about 17 seconds and could run out of tokens before giving a verdict. `temperature 0` caused repetition loops in Turkish, so I use `0.2` with a repeat penalty.
- The message is wrapped in `<message>` tags and the model is told it is untrusted data, a cheap guard against "ignore previous instructions".

## Run it

Requirements: Python 3.11, [llama.cpp](https://github.com/ggml-org/llama.cpp) with `llama-server`, and a Gemma GGUF model.

```bash
# 1. Start the local model (leave it running)
llama-server -m /path/to/gemma-model.gguf -ngl 999 -c 4096 --host 127.0.0.1 --port 8080

# 2. Install and start BeAwake
pip install -r requirements.txt
python app.py        # http://127.0.0.1:7860
```

I developed it with Gemma 4 12B (`Q3_K_M`, about 5.7 GB) on an RTX 5060 Laptop GPU with 8 GB VRAM. Evaluating 36 messages takes about 45 seconds.

Tests: `python -m pytest -q`. Evaluation: `PYTHONPATH=. python eval/run_eval.py eval/holdout.csv out.json`, then `python eval/metrics.py out.json`.

## Does it work? Evaluation

Two sets of 36 synthetic messages, written by me (fake names and domains), 6 scam and 6 legitimate per language in Turkish, Arabic and English. They include hard cases: real verification-code SMS, harmless links, and scams with no link at all ("mom, new number").

- **Dev set** (`eval/dataset.csv`): used while building. The first version scored 33/36 here.
- **Holdout set** (`eval/holdout.csv`): written after the first round with different wording. I ran the improved rules on it once and did not tune against it afterwards.

I measured the first version and the improved version (v2: context-aware rules, calibrated prompt, reply-language fix) on the holdout set. The raw results are in `eval/results_holdout_v1.json` and `eval/results_holdout_v2.json`.

| Holdout, 36 messages | rules v1 | rules v2 | BeAwake v1 | BeAwake v2 |
|---|---|---|---|---|
| Scams missed (of 18) | 12 | 5 | 0 | **0** |
| Legitimate flagged (of 18) | 2 | 0 | 6 | **1** |
| Accuracy | 61% | 86% | 83% | **97%** (35/36) |
| 95% interval (Wilson) | 45-75% | 71-94% | 68-92% | 86-100% |
| English messages answered in the wrong language | - | - | 7 of 12 | **0 of 12** |

What I take from this, and what I don't:

- **The model catches what plain rules cannot.** The five scams still missed by the v2 rules have no link or keyword: relatives asking for money without saying "new number", a job offer, a phone-call threat, an investment group. Gemma caught all five. Rules alone: 72% recall, 100% precision. BeAwake: 100% recall, 95% precision.
- **Most of the improvement came from the prompt and the language fix**, not the rules. The safety floor never changed a verdict in any run (0 of 36 on the dev set, 0 of 36 on the holdout, both versions), so **I have not shown that it adds value**. It stays as a safety net, and the signals are still shown in the UI.
- **0 missed scams in 18 does not mean the miss rate is 0.** With 18 scams, the true rate could still be as high as about 19%.
- The single remaining false alarm is a Turkish bank notice ("your statement is ready, log in to the app").
- **The holdout is not a clean test.** I wrote both sets, so both look like the scam templates I know. I redesigned the rules and prompt after seeing the dev errors, and the prompt's idea of "ordinary messages" came from my own picture of both sets. Treat the numbers as indicative, not proof.

### Known weaknesses

- **Turkish text quality.** With a Q3-quantized model the Turkish explanations sometimes had small mistakes or odd words (for example `tıklemeyin` instead of `tıklamayın`). Verdicts were right, but the wording was not perfect. I have not re-measured this after the prompt change.
- **Rules gaps.** Scams without a link or keyword are invisible to the rules by design.
- It is a second opinion, not a guarantee. When in doubt, call the sender on a number you already trust.

## What my friend and family said

I haven't been able to put BeAwake in their hands yet, so I have no feedback from them to share. I'd rather say that than make something up. The thing I most want to learn is whether the small Turkish mistakes matter to a real Turkish reader, and how it handles the real messages that reach them, which are probably messier than the ones I wrote.

## Why a local, open model

- **Privacy.** The messages people want checked are exactly the ones with private details. They never leave the machine.
- **Works offline, no per-message cost.** No account, no API key.
- **Multilingual in one model.** Gemma handled Turkish, Arabic and English with one prompt.
- **Inspectable.** I could see where it failed and tune the generation settings and prompt myself, which a closed API would not allow.

## Project structure

```
beawake/llm.py       client for the local llama-server (prompt + parsing)
beawake/lang.py      decides the reply language
beawake/signals.py   deterministic signals, rules verdict, safety floor
beawake/checker.py   the pipeline
app.py               Gradio UI
eval/                datasets, evaluation scripts, saved results
tests/               unit tests
```

## Honest note on prior work

This repository was created on 2 October 2026, during the challenge, and all code here was written for it. I had earlier built a personal local assistant called NEXUS, which taught me how to run Gemma with `llama.cpp` and structure a model client behind a small interface. No code was copied from it; the experience, not the files, carried over.

## Work after the deadline

The deadline was 5 October 2026, 06:59 UTC.

**Before the deadline:** all code, tests, evaluation scripts and the raw evaluation results were committed. The last commit with code is `a0aaab3` (3 October 2026, 13:28 UTC). The first commit, `8d9fb0a`, is from 2 October 2026, 09:00 UTC.

**After the deadline**, I made these changes only:

- An accidental commit (`fa49740`) of a Gradio flag-log file with four test messages. I removed it and added `.gradio/` to `.gitignore`.
- This README. It was committed after the deadline, and the numbers in it come from the result files committed before it.
