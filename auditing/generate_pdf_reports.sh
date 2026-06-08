#!/bin/bash
# =============================================================================
# generate_pdf_reports.sh — Convert Audit HTML Reports to PDF
#
# Description:
#   Converts all HTML audit reports in ~/audit_reports/ to PDF format.
#   Uses macOS built-in tools (cupsfilter + osascript/Safari fallback).
#   Can also be called with a specific HTML file as an argument.
#
#   PDF reports are saved alongside the HTML files with the same name.
#
# Usage:
#   ./generate_pdf_reports.sh                    # convert all HTML reports
#   ./generate_pdf_reports.sh report.html        # convert specific file
#
# =============================================================================

set -uo pipefail

REPORT_DIR="$HOME/audit_reports"

log()   { echo "  $*"; }
ok()    { echo "  [OK]    $*"; }
err()   { echo "  [ERROR] $*"; }

# ─── PDF Generation Function ──────────────────────────────────────────────────

generate_pdf() {
    local HTML_FILE="$1"
    local PDF_FILE="${HTML_FILE%.html}.pdf"
    local BASENAME=$(basename "$HTML_FILE")

    log "Converting: $BASENAME"

    # Method 1: cupsfilter (built-in macOS)
    if /usr/sbin/cupsfilter -m application/pdf "$HTML_FILE" > "$PDF_FILE" 2>/dev/null; then
        local SIZE=$(du -h "$PDF_FILE" 2>/dev/null | awk '{print $1}')
        ok "PDF created: $(basename $PDF_FILE) ($SIZE)"
        return 0
    fi

    # Method 2: osascript via Safari print-to-PDF
    log "cupsfilter failed — using Safari print-to-PDF..."
    local ABS_HTML=$(realpath "$HTML_FILE")
    local ABS_PDF=$(realpath "$(dirname "$HTML_FILE")")/$(basename "${HTML_FILE%.html}.pdf")

    osascript << APPLESCRIPT 2>/dev/null
        set htmlFile to POSIX file "$ABS_HTML"
        set pdfFile to "$ABS_PDF"
        tell application "Safari"
            activate
            open htmlFile
            delay 3
            tell application "System Events"
                tell process "Safari"
                    keystroke "p" using command down
                    delay 2
                    -- Click the PDF dropdown
                    click button "PDF" of sheet 1 of window 1
                    delay 1
                    click menu item "Save as PDF…" of menu 1 of button "PDF" of sheet 1 of window 1
                    delay 1
                    keystroke "a" using command down
                    keystroke pdfFile
                    delay 0.5
                    keystroke return
                    delay 2
                end tell
            end tell
            close front document
        end tell
APPLESCRIPT

    if [[ -f "$PDF_FILE" ]]; then
        local SIZE=$(du -h "$PDF_FILE" 2>/dev/null | awk '{print $1}')
        ok "PDF created via Safari: $(basename $PDF_FILE) ($SIZE)"
        return 0
    fi

    # Method 3: Python + weasyprint (if available)
    if python3 -c "import weasyprint" 2>/dev/null; then
        python3 -c "
import weasyprint
weasyprint.HTML(filename='$HTML_FILE').write_pdf('$PDF_FILE')
print('PDF generated via weasyprint')
" 2>/dev/null && ok "PDF created via weasyprint: $(basename $PDF_FILE)" && return 0
    fi

    err "Could not generate PDF for $BASENAME — install wkhtmltopdf for reliable conversion"
    err "  brew install wkhtmltopdf  OR  use Safari: File → Export as PDF"
    return 1
}

# ─── Main ─────────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Audit Report PDF Generator"
echo "  Date   : $(date)"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Single file mode
if [[ $# -gt 0 && -f "$1" ]]; then
    generate_pdf "$1"
    echo ""
    exit 0
fi

# Batch mode — convert all HTML reports
HTML_FILES=$(find "$REPORT_DIR" -name "*.html" 2>/dev/null | sort)

if [[ -z "$HTML_FILES" ]]; then
    echo "  No HTML reports found in $REPORT_DIR"
    echo ""
    exit 0
fi

TOTAL=0
SUCCESS=0
while IFS= read -r f; do
    PDF="${f%.html}.pdf"
    if [[ -f "$PDF" ]]; then
        log "Skipping (PDF exists): $(basename $f)"
        continue
    fi
    ((TOTAL++))
    generate_pdf "$f" && ((SUCCESS++)) || true
done <<< "$HTML_FILES"

echo ""
echo "  Converted: $SUCCESS / $TOTAL reports"
echo "  Location : $REPORT_DIR"
echo ""
echo "════════════════════════════════════════════════════════════════"
