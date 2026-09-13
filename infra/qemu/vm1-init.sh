#!/bin/bash
# Baked into the VM1 image; runs at every boot BEFORE the harness (pre-adversarial). Prints the
# guest's own kernel physical ranges (for scoped VMI from below), starts a virtual display, then
# runs the harness. Output goes to the serial console the supervisor reads.
exec > /dev/ttyAMA0 2>&1
set +e
iomem_range() { awk -v pat="$1" '$0 ~ pat {n=split($1,a,"-"); printf "\"0x%s\",\"0x%s\"", a[1], a[2]; exit}' /proc/iomem; }
code=$(iomem_range "Kernel code")
rod=$(iomem_range "Kernel rodata"); [ -z "$rod" ] && rod=$(iomem_range "Kernel data")
IFS=',' read -r cs ce <<<"$code"; IFS=',' read -r rs re <<<"$rod"
echo "KMEM {\"code_start\":${cs:-\"0x0\"},\"code_end\":${ce:-\"0x0\"},\"rodata_start\":${rs:-\"0x0\"},\"rodata_end\":${re:-\"0x0\"}}"
# virtual display for headed browsers (Xvfb); harness also supports headless
export DISPLAY=:99
export PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp >/var/log/xvfb.log 2>&1 &
sleep 1
# Consume the verified immutable deps image (attached read-only as /dev/vdb): the trusted side built
# and digest-verified this exact snapshot at attach (Codex end-of-P1 #7). VM1 runs the PRESTAGED
# harness + interpreter FROM the image — never a baked default — and there is NO fallback: a missing
# image, missing config, or missing prestaged interpreter aborts the run as inconclusive rather than
# silently executing an unverified path (which could be reported as "contained" without a real test).
mkdir -p /deps
abort() { echo "VM1_READY $(uname -r)"; echo "HARNESS_DONE {\"error\":\"$1\"}"; exit 0; }
mount -o ro /dev/vdb /deps 2>/dev/null || abort "deps image /dev/vdb not mountable"
[ -f /deps/run-config.json ] || abort "run-config.json missing from deps image"
RC_MODEL=$(python3 -c "import json;print(json.load(open('/deps/run-config.json'))['model'])" 2>/dev/null)
RC_MANIFEST=$(python3 -c "import json;print(json.load(open('/deps/run-config.json')).get('manifest_digest',''))" 2>/dev/null)
[ -n "$RC_MODEL" ] || abort "model missing from run-config.json"
# Mount + config parse succeeded — emit the mount marker now (qualification asserts THIS to prove the
# mandatory deps-image consumption path, distinct from VM1_READY which the missing-image abort also
# emits) (Codex end-of-P1 #6).
echo "DEPS_IMAGE mounted ro; model=$RC_MODEL manifest=$RC_MANIFEST"
[ -x /deps/venv/bin/python ] || abort "prestaged interpreter /deps/venv/bin/python missing"
# The interpreter must actually RUN, and the harness + its deps must IMPORT from the image, before we
# declare readiness — a broken venv relocation or a missing wheel aborts as inconclusive rather than
# silently running an unverified path (Codex end-of-P1 #4).
/deps/venv/bin/python -c 'import sys' 2>/dev/null || abort "prestaged interpreter not runnable in VM1"
PYTHONPATH=/deps /deps/venv/bin/python -c 'import deadswitch_harness, playwright' 2>/dev/null || abort "harness or playwright import failed from deps image"
echo "VM1_READY $(uname -r)"
# Execute the harness from the immutable image (code + interpreter both from /deps). PYTHONPATH=/deps
# imports the package from the verified snapshot regardless of the relocatable venv's build path.
# set -o pipefail so a python crash (not tee's success) is what the `||` sees.
cd /deps || exit 1
set -o pipefail
# Bounded smoke run: cap the agentic loop (DS_MAX_STEPS) and its wall budget (DS_MAX_S) so it always
# completes and emits HARNESS_DONE within the window even under slow local inference. `timeout -k`
# force-SIGKILLs a wedged python (a plain SIGTERM can be ignored mid-socket-read, leaving `tee` with
# no EOF so the fallback never fires); on kill, tee sees EOF and the fallback HARNESS_DONE is emitted.
DS_GATEWAY="http://172.16.0.1:3128" DS_MODEL="$RC_MODEL" DS_MODE="${DS_MODE:-agentic}" DS_DEPS="/deps" \
  DS_MAX_S="${DS_MAX_S:-200}" DS_MAX_STEPS="${DS_MAX_STEPS:-5}" \
  PYTHONPATH="/deps" PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
  timeout -k 15 300 /deps/venv/bin/python -u -m deadswitch_harness 2>&1 | tee /var/log/harness.log || echo "HARNESS_DONE {\"error\":\"harness crashed or timed out\"}"
