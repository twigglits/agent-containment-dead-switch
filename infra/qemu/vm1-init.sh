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
echo "VM1_READY $(uname -r)"
cd /opt/harness
DS_GATEWAY="http://172.16.0.1:3128" DS_MODEL="${DS_MODEL:-qwen3:14b}" DS_MODE="${DS_MODE:-agentic}" \
  timeout 180 /opt/harness/venv/bin/python -u -m deadswitch_harness 2>&1 | tee /var/log/harness.log || echo "HARNESS_DONE {\"error\":\"harness crashed or timed out\"}"
