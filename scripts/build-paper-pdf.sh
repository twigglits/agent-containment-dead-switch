#!/usr/bin/env bash
# Build docs/dead-switch-paper.pdf from docs/dead-switch-paper.md.
#
# Pipeline: Markdown -> HTML (python-markdown, stdlib-only otherwise) -> PDF (headless Chrome, which
# also renders the ```mermaid diagram via mermaid.js from a CDN, so a network connection is needed
# for that one figure). Relative repo links are rewritten to GitHub URLs so they work from the PDF.
#
# Prereqs: python3 with the `markdown` package (pip install markdown), Google Chrome or Chromium.
# Usage:   scripts/build-paper-pdf.sh [input.md] [output.pdf]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IN="${1:-$ROOT/docs/dead-switch-paper.md}"
OUT="${2:-${IN%.md}.pdf}"
REPO_URL="${REPO_URL:-https://github.com/twigglits/agent-containment-dead-switch/blob/main}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CHROME="${CHROME:-}"
if [ -z "$CHROME" ]; then
  for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
           "/Applications/Chromium.app/Contents/MacOS/Chromium" \
           google-chrome google-chrome-stable chromium chromium-browser; do
    if [ -x "$c" ] || command -v "$c" >/dev/null 2>&1; then CHROME="$c"; break; fi
  done
fi
[ -n "$CHROME" ] || { echo "build-paper-pdf: no Chrome/Chromium found (set CHROME=/path)" >&2; exit 1; }
python3 -c 'import markdown' 2>/dev/null || { echo "build-paper-pdf: python3 'markdown' package missing (pip install markdown)" >&2; exit 1; }

IN="$IN" OUT_HTML="$WORK/paper.html" REPO_URL="$REPO_URL" ROOT="$ROOT" python3 - <<'PY'
import html, os, pathlib, re
import markdown

src = pathlib.Path(os.environ["IN"])
root = pathlib.Path(os.environ["ROOT"])
repo = os.environ["REPO_URL"].rstrip("/")
text = src.read_text(encoding="utf-8")

# --- Markdown preprocessing -------------------------------------------------------------------
# 1. The title block uses single newlines: make them hard breaks.
text = re.sub(r"^(\*\*(?:Author|Project|Draft):\*\*.*)$", r"\1  ", text, flags=re.M)
# 2. References: one paragraph per [n] entry; un-indent wrapped continuation lines.
def fix_refs(m):
    body = m.group(2)
    out = []
    for line in body.split("\n"):
        if re.match(r"^\[\d+\]", line):
            out.append("")          # blank line starts a new paragraph
            out.append(line)
        elif line.startswith("    "):
            out.append(line.strip())
        else:
            out.append(line)
    return m.group(1) + "\n".join(out)
text = re.sub(r"(## References\n)(.*?)(?=\n---)", fix_refs, text, count=1, flags=re.S)

body = markdown.markdown(
    text,
    extensions=["tables", "fenced_code", "toc", "sane_lists", "smarty"],
    extension_configs={"toc": {"toc_depth": "2-3"}},
    output_format="html5",
)

# --- HTML post-processing ---------------------------------------------------------------------
# 3. ```mermaid fences -> <pre class="mermaid"> that mermaid.js renders in the browser.
def mermaid(m):
    return '<pre class="mermaid">' + html.unescape(m.group(1)) + "</pre>"
body = re.sub(r'<pre><code class="language-mermaid">(.*?)</code></pre>', mermaid, body, flags=re.S)

# 4. Relative links -> GitHub URLs (blob for files, tree for directories), resolved from docs/.
def link(m):
    href = m.group(1)
    if re.match(r"^(https?:|mailto:|#)", href):
        return m.group(0)
    target = (src.parent / href).resolve()
    try:
        rel = target.relative_to(root)
    except ValueError:
        return m.group(0)
    kind = "tree" if target.is_dir() else "blob"
    return 'href="%s/%s"' % (repo.replace("/blob/main", "/" + kind + "/main"), rel.as_posix())
body = re.sub(r'href="([^"]+)"', link, body)

title = re.search(r"^# (.+)$", text, flags=re.M).group(1)
css = """
@page { size: A4; margin: 18mm 17mm 20mm 17mm; }
html { font-size: 10.5pt; }
body { font-family: "Charter", "Georgia", "Times New Roman", serif; line-height: 1.42; color: #111;
       max-width: 100%; margin: 0; }
h1 { font-size: 20pt; line-height: 1.2; margin: 0 0 6pt; }
h1 + h3 { font-size: 12.5pt; font-weight: normal; font-style: italic; color: #333; margin: 0 0 12pt; }
h2 { font-size: 14pt; margin: 20pt 0 6pt; border-bottom: 1px solid #bbb; padding-bottom: 2pt; break-after: avoid; }
h3 { font-size: 11.5pt; margin: 14pt 0 4pt; break-after: avoid; }
p { margin: 0 0 7pt; text-align: justify; hyphens: auto; orphans: 3; widows: 3; }
ul, ol { margin: 0 0 7pt; padding-left: 18pt; }
li { margin-bottom: 3pt; }
blockquote { margin: 6pt 0 8pt; padding: 4pt 10pt; border-left: 3px solid #999; background: #f4f4f4; }
code, pre { font-family: "SF Mono", Menlo, Consolas, "Liberation Mono", monospace; font-size: 8.6pt; }
code { background: #f2f2f2; padding: 0 2px; border-radius: 2px; }
pre { background: #f6f6f6; border: 1px solid #ddd; padding: 6pt 8pt; white-space: pre-wrap; word-break: break-word; break-inside: avoid; }
pre code { background: none; padding: 0; }
pre.mermaid { background: none; border: none; text-align: center; }
pre.mermaid svg { max-width: 100%; height: auto; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0 10pt; font-size: 9pt; break-inside: avoid; }
th, td { border: 1px solid #bbb; padding: 3pt 5pt; vertical-align: top; text-align: left; }
th { background: #eee; }
hr { border: 0; border-top: 1px solid #ccc; margin: 14pt 0; }
a { color: #0b4f9c; text-decoration: none; }
strong { font-weight: 700; }
.toc { display: none; }
"""
page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>{css}</style>
<script type="module">
import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
mermaid.initialize({{ startOnLoad: true, theme: "neutral", flowchart: {{ useMaxWidth: true }} }});
</script></head><body>{body}</body></html>"""
pathlib.Path(os.environ["OUT_HTML"]).write_text(page, encoding="utf-8")
PY

"$CHROME" --headless=new --disable-gpu --hide-scrollbars --no-pdf-header-footer \
  --run-all-compositor-stages-before-draw --virtual-time-budget=15000 \
  --print-to-pdf="$OUT" "file://$WORK/paper.html" >/dev/null 2>&1

[ -s "$OUT" ] || { echo "build-paper-pdf: Chrome produced no output" >&2; exit 1; }
echo "wrote $OUT ($(du -h "$OUT" | cut -f1))"
