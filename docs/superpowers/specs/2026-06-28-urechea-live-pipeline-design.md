# SigurScan Urechea Live Pipeline Design

Date: 2026-06-28
Status: design contract for implementation
Scope: Android live-call Urechea, local ASR, redacted semantic review, UI feedback, cost guard

## Decision

Default production direction:

- No cloud ASR by default.
- Keep raw audio on-device.
- Keep Whisper local for the next implementation pass.
- Add VAD/RMS, model warm-up, coverage telemetry, bounded recency processing, and clearer live UI states.
- Use Mistral only through the backend on redacted transcript windows, escalate-only, capped per call.
- Do not lock Vosk/sherpa-onnx as the product engine until a Nokia C22 benchmark proves it beats the current path on latency, Romanian recall, memory, and APK impact.

This replaces the earlier "switch immediately to Vosk" recommendation. Vosk/sherpa-onnx remain P1 benchmark candidates, not P0 product direction.

## Ground Truth From Current Main

Current `origin/main` at `f7e62f7e` already has these pieces:

- `SpeakerGuardForegroundService` runs capture inside a microphone foreground service.
- `SpeakerGuardSession` uses a bounded `Channel` with `BufferOverflow.SUSPEND`, capacity `4`.
- Current main no longer has the old `DROP_OLDEST capacity=1` failure mode.
- `chunksDropped` currently always returns `0`, so the UI can still falsely imply no audio loss or backlog risk.
- Whisper JNI caches the model context globally (`g_ctx`), so the model is not reloaded per chunk.
- Whisper JNI already uses speed-biased settings: `n_threads=4`, `single_segment=true`, `max_tokens=32`, `audio_ctx=256`, `no_context=true`.
- Android already has `BackendAudioSemanticReviewer`.
- Backend already exposes `POST /v1/audio/semantic-review`.
- Backend semantic review accepts only redacted transcript, never raw audio.
- Android fusion is already escalate-only: Mistral can raise local evidence to `SUSPECT`/`DANGEROUS`, but cannot downgrade.

Measured Nokia C22 data from the live device:

- Romanian vishing fixture duration: about 2.9 seconds.
- First measured Whisper run: `elapsed_ms=13160`.
- Transcript was noisy: `Benerecere sa multibani intr-un consiguracum`.
- Despite noisy ASR, local evidence was actionable because fraud tokens still survived.

Interpretation:

- Whisper local is slow on C22, but not automatically disqualified for phone scams.
- The product target is not sub-second final verdict. The target is a useful warning before the user makes an irreversible move.
- Scam calls usually include setup, authority building, confusion, and repeated instructions. A useful result within 20-60 seconds can still protect the user.
- The critical failure to fix is coverage and feedback: the user must see that Urechea is alive, and the pipeline must not silently miss the decisive phrase.

## Non-Negotiables

- Raw audio never leaves the phone in the default path.
- Backend receives only redacted transcript snippets.
- Mistral is semantic escalate-only, not a safety downgrader.
- If Mistral fails, the user keeps the local verdict and sees a non-technical status.
- No silent audio loss. If speech was skipped, stale, blocked, or not processed, telemetry must show it.
- Cost must be bounded. No per-minute ASR provider in the default product.

## Architecture

### Band 0: Call Prompt And Consent

Already mostly present:

- Call screening detects unknown/suspect calls.
- User sees prompt to use speaker and let SigurScan analyze.
- User explicitly starts listening.

Required UX rule:

- The prompt must work when the phone is unlocked, locked, or behind the dialer overlay.
- If Android/dialer hides the custom prompt, a visible notification fallback must explain: "Deschide notificarea SigurScan ca sa pornesti Urechea."

### Band 1: Local Live Signal

Purpose: prove the app is listening immediately, even before ASR finishes.

Add:

- RMS/VAD frame monitor on the capture stream.
- UI states:
  - `Ascult...`
  - `Am prins voce`
  - `Analizez fragment audio`
  - `Verific semantic`
  - `Suspect` / `Periculos`
- Metrics:
  - `audio_capture_started_at`
  - `voice_detected_at`
  - `speech_ms_detected`
  - `speech_ms_queued`
  - `speech_ms_processed`
  - `speech_ms_skipped_stale`
  - `backlog_ms`
  - `asr_latency_ms`
  - `semantic_latency_ms`

This fixes the "30 seconds of dead UI" problem without needing a new ASR engine.

### Band 2: Local ASR With Coverage Control

Current issue:

- `SUSPEND` avoids explicit `DROP_OLDEST`, but when ASR is slower than capture, the recorder can block on `chunks.send`.
- `chunksDropped=0` is therefore misleading.
- The system lacks a policy for stale backlog versus fresh speech.

Replace the generic chunk channel with a `SpeechSegmentQueue`:

- VAD-gated: silence should not become ASR work.
- In-memory only: raw PCM is never persisted and never uploaded.
- Bounded by time, not just count.
- Tracks skipped/stale audio explicitly.
- Prefers fresh speech when backlog exceeds the configured latency budget.
- Never reports fake "0 dropped" when the system skipped or could not enqueue speech.

Target behavior:

- Process the first voiced segment as soon as possible.
- Keep enough recent speech to catch repeated fraud instructions.
- Avoid being several minutes behind the live conversation.
- If falling behind, show "analiza intarzie" and keep processing recent speech rather than old chit-chat.

Initial parameters to test on C22:

- VAD frame: 20-30 ms.
- Speech segment target: 2.5-3.5 seconds voiced audio.
- Queue freshness budget: 45-60 seconds.
- Max in-memory voiced backlog: 30-45 seconds.
- Whisper warm-up at session start using `nativeCanLoadModel(modelPath)`.
- Benchmark `n_threads=4`, `6`, and `8`; do not blindly ship `6` if it starves capture/UI.

### Band 3: Semantic Review With Mistral

Existing backend endpoint:

- `POST /v1/audio/semantic-review`
- Input: redacted transcript only.
- Output: semantic review, not raw transcript echo.
- Fusion on Android is escalate-only.

Required fixes before relying on it:

- `SpeakerGuardForegroundService` must use the same complete API client as normal scans:
  - API key.
  - client instance id.
  - Play Integrity token when available.
- `BackendAudioSemanticReviewer` must not swallow all errors as `null`.
  - Log and expose privacy-safe reason codes such as `http_403`, `timeout`, `network_error`, `mistral_fallback`.
  - Do not log transcript text.
- Cap Mistral calls per call session:
  - Max 4 semantic reviews per call by default.
  - Minimum cooldown 20-30 seconds.
  - Trigger early if local evidence becomes `SUSPECT` or transcript contains high-risk action terms.
  - Otherwise review accumulated transcript after enough content exists.

Suggested request shape:

- `channel = "call_live"`
- `transcript_redacted`
- `local_verdict`
- `local_reason_codes`
- `claimed_identity`
- `arc_family`
- `session_age_seconds`
- `window_index`
- `previous_semantic_risk`

Fusion remains:

```text
final = max(local_audio_evidence, mistral_semantic_review)
```

Mistral may raise:

- `UNVERIFIED -> SUSPECT`
- `UNVERIFIED -> DANGEROUS`
- `SUSPECT -> DANGEROUS`

Mistral may not lower:

- `DANGEROUS -> SUSPECT`
- `SUSPECT -> UNVERIFIED`
- anything -> `SAFE`

### Band 4: UI Product Contract

The user must understand what is happening without technical language.

States:

- Prompt visible: "Te suna un numar necunoscut. Vrei sa-l pui pe difuzor si sa ascult impreuna cu tine?"
- After consent: "Urechea asculta. Pune apelul pe difuzor."
- Voice detected: "Am prins voce. Analizez."
- ASR processing: "Analizez ultimul fragment."
- Semantic processing: "Verific intentia conversatiei."
- Local warning: "Semnale suspecte. Nu da coduri, bani sau acces remote."
- Dangerous: "Opreste-te. Pare frauda."
- Backend unavailable: "Analiza avansata nu a raspuns. Continui local."

Never show a blank wait state for 30 seconds.

## Cost Guard

Default path cost:

- ASR local: 0 marginal cost.
- Mistral: capped per call.
- No cloud streaming ASR.

Hard caps:

- Per-call semantic review cap: 4.
- Per-device daily semantic review cap configurable.
- Backend timeout short enough to avoid Cloud Run burn.
- If backend rejects/fails, stay local and do not retry aggressively.

## Implementation Order

### P0-A: Observability Truth

Goal: stop lying to ourselves.

- Replace fake `chunksDropped=0` with real coverage metrics.
- Log privacy-safe metrics per session.
- Add tests for queue accounting.
- UI shows if analysis is delayed.

Acceptance:

- A slow-ASR test proves skipped/stale/backlog metrics are non-zero when the processor cannot keep up.
- No raw transcript or audio appears in logs.

### P0-B: Model Warm-Up And Voice Feedback

Goal: remove model load from first user-visible verdict and prove the app hears voice.

- Call model warm-up at session start.
- Add RMS/VAD state.
- UI transitions to "Am prins voce" within 1 second of speech energy.

Acceptance on Nokia C22:

- User sees "Am prins voce" during the call, before ASR result.
- First ASR result is measured after warm-up separately from model-load time.

### P0-C: VAD-Gated Recency Queue

Goal: process useful recent speech, not silence or stale backlog.

- Replace raw fixed chunk channel with VAD-gated speech segment queue.
- Use bounded in-memory voiced backlog.
- Prefer recent speech when overloaded.
- Explicitly count stale/skipped speech.

Acceptance:

- Simulated slow ASR does not block capture indefinitely.
- Recent voiced segments are still processed under backlog.
- Metrics show coverage honestly.

### P0-D: Complete Semantic Reviewer Client And Error Reasons

Goal: make Mistral usable and debuggable.

- Use the normal API client/interceptors in `SpeakerGuardForegroundService`.
- Add Play Integrity/client instance support.
- Add privacy-safe failure reason taxonomy.
- Add per-call cap/cooldown.

Acceptance:

- Test proves audio semantic client sends the same auth/integrity headers as normal scan client.
- Live log can distinguish `received=false` causes.
- Mistral can escalate but not downgrade.

### P0-E: Live UI Card Polish

Goal: make the live call experience understandable.

- Add the state language above.
- Keep user actions simple:
  - start listening;
  - stop listening;
  - call action guidance.

Acceptance:

- On unlocked phone, locked phone, and dialer overlay, user can understand how to start Urechea.
- During a 60-second test call, the card never looks dead.

### P1: Engine Benchmark, Not Engine Swap

Only after P0:

- Benchmark current Whisper warm/cold.
- Benchmark `n_threads=4/6/8`.
- Benchmark sherpa-onnx if a Romanian-capable model is practical.
- Benchmark Vosk only if a Romanian model with acceptable license and quality is found.

Promotion rule:

- Replace Whisper only if another local engine beats it on:
  - first useful transcript latency;
  - Romanian scam token recall;
  - memory on C22;
  - APK/model size;
  - maintenance risk.

## Manual Test Script

Device: Nokia C22, Android 13.

1. Install ASR-enabled build.
2. Grant call screening role and microphone permission.
3. Call Nokia from an unknown number.
4. Accept the call and put it on speaker.
5. Start Urechea.
6. Play a realistic social-engineering script:
   - authority claim;
   - account compromised;
   - do not tell anyone;
   - safe account / transfer / code / remote access.
7. Verify:
   - prompt visible or notification fallback visible;
   - "Am prins voce" appears quickly;
   - first local result arrives;
   - Mistral request is attempted only with redacted transcript;
   - no more than cap number of semantic requests;
   - verdict escalates if transcript carries fraud signals;
   - stop releases microphone.

Required log fields:

- session id
- capture start
- voice detected
- speech detected ms
- segments queued
- segments processed
- stale/skipped ms
- ASR latency
- semantic requested
- semantic result/failure reason
- final fused verdict

## Out Of Scope

- Cloud ASR default path.
- Uploading raw audio.
- Replacing Whisper before benchmark evidence.
- Letting Mistral return `SAFE`.
- Reworking the generic scan verdict gate.

## Final Product Principle

For live phone scams, SigurScan does not need perfect transcription of every word. It needs:

- immediate proof it is listening;
- enough local transcript to catch dangerous instructions;
- a semantic reviewer that can reason about social engineering;
- honest coverage metrics;
- a warning before the user sends money, gives a code, installs remote access, or takes credit.

This spec optimizes for that outcome under the real constraints: Nokia C22, offline-first audio, no cloud ASR default, and a 30 lei/month consumer product.
