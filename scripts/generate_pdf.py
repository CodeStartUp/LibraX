import os
import subprocess
import markdown

DOC_FILES = [
    ("index.md", "Executive Summary & Overview"),
    ("architecture/overview.md", "System Architecture & Telemetry Lifecycle"),
    ("architecture/crates.md", "Rust Workspace & Crates Deep-Dive"),
    ("ingestion/normalizer.md", "Log Normalization & Schema"),
    ("ingestion/intel.md", "Threat Intelligence & Enrichment"),
    ("detection/detectors.md", "Detection Mesh & Rules Engine"),
    ("detection/mitre-matrix.md", "MITRE ATT&CK Enterprise Matrix"),
    ("detection/ad-heuristics.md", "Active Directory Threat Heuristics"),
    ("correlation/entities.md", "Identity & Entity Resolution"),
    ("correlation/graph.md", "Evidence Graph & Attack Path Correlation"),
    ("correlation/risk.md", "Multi-Dimensional Risk Engine"),
    ("ai/briefings.md", "Analyst AI & Deterministic Briefing Synthesis"),
    ("response/containment.md", "Autonomous Response & Simulation"),
    ("lab/docker-architecture.md", "Docker Lab & Active Directory Topology"),
    ("lab/adversary-campaign.md", "Adversary Campaign & Shipper Pipeline"),
    ("api/endpoints.md", "REST & WebSocket API Specification"),
    ("frontend/ui-architecture.md", "Frontend SPA & SOC Interface Architecture"),
    ("guides/getting-started.md", "Getting Started, Build & Runbook"),
]

CSS_STYLE = """
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

@page {
    size: A4;
    margin: 20mm 16mm 20mm 16mm;
}

body {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 10.5pt;
    line-height: 1.55;
    color: #1e293b;
    background: #ffffff;
    margin: 0;
    padding: 0;
}

.cover-page {
    page-break-after: always;
    display: flex;
    flex-direction: column;
    justify-content: center;
    min-height: 80vh;
    padding: 40px 0;
}

.cover-title {
    font-size: 32pt;
    font-weight: 800;
    color: #0f172a;
    line-height: 1.15;
    margin-bottom: 12px;
    letter-spacing: -0.02em;
}

.cover-subtitle {
    font-size: 15pt;
    font-weight: 600;
    color: #2563eb;
    margin-bottom: 24px;
}

.cover-meta {
    margin-top: 40px;
    padding-top: 20px;
    border-top: 2px solid #e2e8f0;
    font-size: 10pt;
    color: #64748b;
}

.cover-meta p {
    margin: 4px 0;
}

.section-divider {
    page-break-before: always;
}

h1 {
    font-size: 20pt;
    font-weight: 800;
    color: #0f172a;
    margin-top: 24pt;
    margin-bottom: 10pt;
    border-bottom: 1.5pt solid #2563eb;
    padding-bottom: 4pt;
}

h2 {
    font-size: 14pt;
    font-weight: 700;
    color: #1e293b;
    margin-top: 18pt;
    margin-bottom: 6pt;
}

h3 {
    font-size: 11.5pt;
    font-weight: 700;
    color: #334155;
    margin-top: 14pt;
    margin-bottom: 4pt;
}

p, li {
    color: #334155;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 14pt 0;
    font-size: 9pt;
}

table th {
    background-color: #f1f5f9;
    color: #0f172a;
    font-weight: 700;
    text-align: left;
    padding: 6pt 8pt;
    border: 1px solid #cbd5e1;
}

table td {
    padding: 5pt 8pt;
    border: 1px solid #e2e8f0;
    vertical-align: top;
}

table tr:nth-child(even) td {
    background-color: #f8fafc;
}

code {
    font-family: 'JetBrains Mono', monospace;
    font-size: 9pt;
    background-color: #f1f5f9;
    color: #0f172a;
    padding: 1pt 4pt;
    border-radius: 3px;
    border: 1px solid #e2e8f0;
}

pre {
    background-color: #0f172a;
    color: #f8fafc;
    padding: 10pt 12pt;
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 8.5pt;
    line-height: 1.45;
    overflow-x: auto;
    margin: 12pt 0;
}

pre code {
    background-color: transparent;
    color: inherit;
    padding: 0;
    border: none;
}

blockquote {
    border-left: 3.5pt solid #2563eb;
    background-color: #eff6ff;
    padding: 8pt 14pt;
    margin: 12pt 0;
    color: #1e40af;
    font-size: 9.5pt;
    border-radius: 0 4px 4px 0;
}

hr {
    border: none;
    border-top: 1px solid #e2e8f0;
    margin: 18pt 0;
}
"""

def generate_pdf():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    docs_dir = os.path.join(root_dir, "docs")
    html_output_path = os.path.join(root_dir, "librax-docs-combined.html")
    pdf_output_path = os.path.join(root_dir, "LibraX_SOC_Architecture_and_Design.pdf")

    md = markdown.Markdown(extensions=["tables", "fenced_code"])

    html_sections = []
    
    # Cover Page
    cover_html = """
    <div class="cover-page">
        <div class="cover-title">LibraX SOC Platform</div>
        <div class="cover-subtitle">Autonomous Alert Correlation, Evidence Graph & Threat Prioritization Engine</div>
        <p style="font-size: 11pt; color: #475569; max-width: 650px;">
            Complete Technical Specification, Mathematical Risk Formulas, Detection Algorithms, Active Directory Lab Architecture, and MITRE ATT&CK Matrix.
        </p>
        <div class="cover-meta">
            <p><strong>Platform:</strong> High-Performance Distributed Rust Core (17 Workspace Crates)</p>
            <p><strong>Interface:</strong> React 18 / TypeScript High-Density SOC Analyst Console</p>
            <p><strong>Lab Environment:</strong> Real Active Directory Domain Controller (Samba 4) & Automated Attack Runner</p>
            <p><strong>Document Version:</strong> 1.0.0 (Production Release)</p>
        </div>
    </div>
    """
    html_sections.append(cover_html)

    # Process all markdown documents
    for i, (rel_path, section_title) in enumerate(DOC_FILES):
        file_path = os.path.join(docs_dir, rel_path)
        if not os.path.exists(file_path):
            print(f"Warning: File not found {file_path}")
            continue

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Clean mermaid code blocks for printable HTML (convert to structured blockquote/code)
        lines = []
        in_mermaid = False
        for line in content.split("\n"):
            if line.strip().startswith("```mermaid"):
                in_mermaid = True
                lines.append("```")
                lines.append("[Architecture Flowchart Diagram]")
            elif in_mermaid and line.strip().startswith("```"):
                in_mermaid = False
                lines.append("```")
            else:
                lines.append(line)
        cleaned_content = "\n".join(lines)

        rendered_html = md.convert(cleaned_content)
        page_break_class = "section-divider" if i > 0 else ""
        html_sections.append(f'<div class="{page_break_class}">{rendered_html}</div>')
        md.reset()

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>LibraX — Complete Technical Architecture & Design Document</title>
    <style>{CSS_STYLE}</style>
</head>
<body>
    {''.join(html_sections)}
</body>
</html>"""

    with open(html_output_path, "w", encoding="utf-8") as f:
        f.write(full_html)
    print(f"Generated combined HTML: {html_output_path}")

    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]

    edge_bin = next((p for p in edge_paths if os.path.exists(p)), None)
    if not edge_bin:
        print("Microsoft Edge or Chrome not found. Combined HTML is available to print.")
        return

    print(f"Rendering PDF using headless Edge: {edge_bin}...")
    file_uri = f"file:///{os.path.abspath(html_output_path).replace(os.sep, '/')}"
    cmd = [
        edge_bin,
        "--headless",
        "--disable-gpu",
        "--run-all-compositor-stages-before-draw",
        f"--print-to-pdf={pdf_output_path}",
        "--no-pdf-header-footer",
        file_uri,
    ]
    subprocess.run(cmd, check=True)
    size_mb = os.path.getsize(pdf_output_path) / (1024 * 1024)
    print(f"Successfully generated PDF: {pdf_output_path} ({size_mb:.2f} MB)")

if __name__ == "__main__":
    generate_pdf()
