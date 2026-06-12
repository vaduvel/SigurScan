# Share Intent QA - 2026-06-11

## Scope

This report covers the Android Share Intent intake contract used by SigurScan for
shared text, HTML, URLs, images, PDFs, email attachments, and mixed multi-share
payloads.

## Automated Evidence

- Full JVM unit suite: passed.
- Full Android instrumented suite: 22/22 passed on `Medium_Phone_API_36.1`.
- Release APK assembly: passed.
- Android lint: passed.

The instrumented Share Intent coverage verifies:

- `ACTION_SEND` text, browser URL, HTML, image, and PDF streams.
- `ACTION_SEND_MULTIPLE` HTML plus attachments and mixed attachments.
- `EXTRA_HTML_TEXT`, HTML `ClipData`, and HTML MIME preservation.
- Android `Spanned`/`URLSpan` conversion to HTML so hidden links survive.
- URI collection from both extras and `ClipData`, with deduplication.
- Subject-only email fallback.
- Atomic intake ordering: text and all attachments are staged before scanning.
- Deep-link nested URL preservation.

## Emulator Runtime Evidence

Device: `Medium_Phone_API_36.1` (`emulator-5554`)

- Cold-start `ACTION_SEND`: activity launched successfully.
- Warm `ACTION_SEND` with `FLAG_ACTIVITY_SINGLE_TOP`: Android reported that the
  intent was delivered to the currently running top-most activity.
- The running process remained alive after the second share.
- Android crash buffer remained empty.
- The UI displayed the newly shared URL and its shared-content fidelity notice.

Screenshot evidence generated locally:

- `/tmp/sigurscan-share-warm.png`

## Source-App Matrix

| Source | Available on QA emulator | Contract covered | Real source-app share executed |
| --- | --- | --- | --- |
| Chrome | Yes | URL/text | Pending share-sheet walkthrough |
| Google Messages | Yes | Text/link/image | Pending account-free walkthrough |
| Google Photos | Yes | Image | Pending seeded-gallery walkthrough |
| Android Files | Yes | Image/PDF/multi-share | Pending seeded-file walkthrough |
| Gmail | No | Text/HTML/PDF | Not executable on current emulator |
| Outlook | No | Text/HTML/PDF | Not executable on current emulator |
| Notion Mail/native mail | No | Text/HTML/PDF | Not executable on current emulator |
| WhatsApp | No | Text/link/image | Not executable on current emulator |
| Telegram | No | Text/link/image | Not executable on current emulator |
| Signal | No | Text/link/image | Not executable on current emulator |
| Messenger | No | Text/link/image | Not executable on current emulator |

## Honest Completion Boundary

The shared intake implementation and Android contract are verified. Real
share-sheet walkthroughs from third-party apps that are not installed or
authenticated on the QA emulator remain a release-candidate manual QA item.

Mixed email HTML plus attachments are staged atomically, but the current product
still scans the HTML/text path first and leaves attachments available for
individual scans. A single combined verdict across the email body and every
attachment is a separate pipeline capability.
