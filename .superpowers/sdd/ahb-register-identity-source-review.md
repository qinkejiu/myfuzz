# Generated AHB register target identity independent review

2026-10-17. Reviewed frozen998c89c, `contracts.py` SHA256 `9b4338123df915cedfc065d433e0d7beacc44512c927cfff356dae24e2d8b915` and target tests SHA256 `08985a744ed1330d36df9bd11e815f52c3450c68f0a468f3ad979f084a846847`; both independently matched actual frozen bytes. Also inspected the real AHB/APB session identity implementations, report and saved software evidence. No metadata operation, remote, DUT build, model, elaboration or native occurred.

Verdict: **no high/medium source blocker** found for this strict identity registration increment.

The runtime-kind map is explicit and closed: APB3 and AHB-Lite choose distinct service keys and exact schema strings. Common scenario fields keep their original16-item limits, list/pair shapes, aligned/window-bound offsets,32-bit values and known initial policies. Early permitted field sets do not grant a downgrade: after exact artifact regeneration the selected kind's exact field set rejects bare identity, missing/mixed/foreign protocol keys and unknown fields. This follows runtime protocol kind, not a component-name or new CPU factory branch.

AHB register artifacts use the existing v2 request path, so strict JSON runtime identity reconstruction retains bool/int distinctions; build identity now explicitly includes AHB register kind in strict JSON comparison. The APB closed set and checks are mathematically identical to the prior branch apart from shared local variable names/error wording. Other service branches, CPU startup observation contract and source admission are unchanged. The existing Runner class registry already contains the actual AHB target class; no broad class allowlist or source authority was added.

The actual Caliptra profile/request/renderer/driver/Python target constructor/strict reconstruction and Runner manifest run in software controls. Saved ABI/physical/frontend facts and build-tool identity are explicitly substituted; all external Popen except source-authentication git is forbidden. Old target artifact provenance does not establish new CPU startup or native target execution. Scenario setup/probe values remain explicitly supplied, rather than hidden defaults or fabricated results.

Independent software receipts:

- `PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q tests/local_harness/test_ahb_register_identity.py` —actual pytest process exit0, **21 passed in12.38s**.
- `PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q tests/local_harness/test_generic_apb_identity.py` —actual exit0, **38 passed in5.78s**, confirming existing APB behavior after shared-branch refactor.

Owner's RED2/combined162pass receipts were read, not independently rerun in full here. These software results grant no storage-version/reset/source/native-reset/retirement authority. Actual newly generated CVW13-role startup→Caliptra continuous/fresh gate remains separately pending, and no P7 acceptance follows from this review.
