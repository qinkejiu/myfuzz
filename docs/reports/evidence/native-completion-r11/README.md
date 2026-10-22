# R11 local preparation evidence

Current Stage 1 manifest: `a944ef09f414642541854d36955a81b906f213b4705b2e09cc96372de7f84059`.

- `reviews/stage1-review-a.json` and `stage1-review-b.json`: independent accepted exact-digest decisions, eight typed readback rows each. Operator evidence, not cryptographic signatures.
- `software-20261022-attempt2/`: final nine-file local software run, 266 passed / 3 native opt-in skips / 32 subtests passed; exact command, process terminal, log SHA, unchanged input hashes, and input byte copies.
- `software-20261022-attempt1/`: prior 195-pass software run of the subsequently rejected intermediate candidate; not the final acceptance evidence.
- `stage1-history/3d22a101eee49e27036796bc159fa36e5dcedaef805050eb223214c7d3171feb/`: prior static-only accepted package and its original review receipts.
- `stage1-history/de66e59556fb1f6ec782baac0f83a543da210fa4248b21a9666f9fa860740b9f/`: intermediate package plus Important review rejection for loose nested identity equality.

Local software fixtures use disposable Python processes and offline receipts. No complete Stage 2 package/admission, remote upload, or native three-branch gate has been performed. See the [current report](../../native-exact-source-completion-r11-preparation-20261022.md).
