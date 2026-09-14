"""Show the most recent local update comparison report without fetching or writing."""
from routing import ROOT

if __name__ == "__main__":
    report=ROOT/'work'/'update-report.md'
    if not report.exists():
        raise SystemExit('No comparison report yet; run scripts/pipeline.py update first.')
    print(report.read_text())
