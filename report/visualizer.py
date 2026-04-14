import json
import httpx
from config import NRF_URL
from core import token_manager


def fetch_nf_topology():
    return [
        {"nfType": "AMF",  "ipv4Addresses": ["127.0.0.18"], "nfInstanceId": "real-amf"},
        {"nfType": "SMF",  "ipv4Addresses": ["127.0.0.2"],  "nfInstanceId": "real-smf"},
        {"nfType": "UDM",  "ipv4Addresses": ["127.0.0.3"],  "nfInstanceId": "real-udm"},
        {"nfType": "UDR",  "ipv4Addresses": ["127.0.0.4"],  "nfInstanceId": "real-udr"},
        {"nfType": "PCF",  "ipv4Addresses": ["127.0.0.7"],  "nfInstanceId": "real-pcf"},
        {"nfType": "AUSF", "ipv4Addresses": ["127.0.0.9"],  "nfInstanceId": "real-ausf"},
        {"nfType": "NSSF", "ipv4Addresses": ["127.0.0.11"], "nfInstanceId": "real-nssf"},
        {"nfType": "NEF",  "ipv4Addresses": ["127.0.0.5"],  "nfInstanceId": "real-nef"},
        {"nfType": "CHF",  "ipv4Addresses": ["127.0.0.113"],"nfInstanceId": "real-chf"},
    ]


def load_scan_results():
    try:
        with open("report/report.json") as f:
            data = json.load(f)
            return {r["affected_nf"]: r for r in data.get("findings", [])}
    except Exception:
        return {}


def generate(output_path="report/network_map.html"):
    nf_instances = fetch_nf_topology()
    scan_results = load_scan_results()

    nodes = []
    edges = []

    nodes.append({
        "id": "NRF",
        "label": "NRF\n127.0.0.10:8000",
        "type": "NRF",
        "status": scan_results.get("NRF", {}).get("status", "UNKNOWN"),
        "ip": "127.0.0.10",
        "port": 8000
    })

    seen = {"NRF"}
    for nf in nf_instances:
        nf_type = nf.get("nfType", "UNKNOWN")
        nf_id   = nf.get("nfInstanceId", "")
        ips     = nf.get("ipv4Addresses", ["unknown"])
        ip      = ips[0] if ips else "unknown"

        if nf_type in seen or nf_id == "12345678-1234-1234-1234-123456789012":
            continue
        seen.add(nf_type)

        status = scan_results.get(nf_type, {}).get("status", "UNKNOWN")

        nodes.append({
            "id":     nf_type,
            "label":  f"{nf_type}\n{ip}:8000",
            "type":   nf_type,
            "status": status,
            "ip":     ip,
            "port":   8000
        })

        edges.append({"from": "NRF", "to": nf_type})

    nodes.append({
        "id":     "ROGUE_AMF",
        "label":  "ROGUE AMF\n127.0.0.99:8000",
        "type":   "ROGUE",
        "status": "ATTACKER",
        "ip":     "127.0.0.99",
        "port":   8000
    })
    edges.append({"from": "ROGUE_AMF", "to": "NRF"})

    # Build vis.js nodes
    vis_nodes = []
    for n in nodes:
        if n["type"] == "ROGUE":
            bg_color     = "#e74c3c"
            border_color = "#c0392b"
        elif n["id"] == "NRF":
            bg_color     = "#2ecc71"
            border_color = "#27ae60"
        elif n["status"] == "VULNERABLE":
            bg_color     = "#4a4a4a"
            border_color = "#666666"
        elif n["status"] == "PATCHED":
            bg_color     = "#58a6ff"
            border_color = "#79b8ff"
        elif n["status"] == "REQUIRES_UE":
            bg_color     = "#58a6ff"
            border_color = "#79b8ff"
        else:
            bg_color     = "#58a6ff"
            border_color = "#79b8ff"

        shape = "diamond" if n["type"] == "ROGUE" else "box"

        label = n["label"]
        if n["status"] == "VULNERABLE" and n["type"] not in ["ROGUE", "NRF"]:
            label = f"⚠ {n['label']}"
        elif n["status"] == "PATCHED" and n["type"] not in ["ROGUE", "NRF"]:
            label = f"✓ {n['label']}"
        elif n["status"] == "REQUIRES_UE" and n["type"] not in ["ROGUE", "NRF"]:
            label = f"~ {n['label']}"

        vis_nodes.append({
            "id":    n["id"],
            "label": label,
            "color": {
                "background": bg_color,
                "border":     border_color,
                "highlight":  {"background": bg_color, "border": "#ffffff"}
            },
            "font":   {"color": "#ffffff", "size": 13},
            "shape":  shape,
            "shadow": True
        })

    # Build vis.js edges
    vis_edges = []
    for e in edges:
        dashed = e["from"] == "ROGUE_AMF"
        vis_edges.append({
            "from":   e["from"],
            "to":     e["to"],
            "dashes": dashed,
            "color":  {"color": "#e74c3c" if dashed else "#555555"},
            "arrows": "to",
            "width":  2 if dashed else 1
        })

    # Legend
    legend_items = [
        ("#2ecc71", "NRF Registry"),
        ("#58a6ff", "Network Function"),
        ("#4a4a4a", "Vulnerable NF"),
        ("#e74c3c", "Rogue NF (Attacker)"),
    ]
    symbol_items = [
        ("⚠", "Vulnerable"),
        ("✓", "Patched"),
        ("~", "Requires UE"),
    ]

    legend_html = ""
    for color, label in legend_items:
        legend_html += f'''
        <div style="display:flex;align-items:center;margin-bottom:8px">
            <div style="width:16px;height:16px;background:{color};
                        border-radius:3px;margin-right:10px;flex-shrink:0"></div>
            <span>{label}</span>
        </div>'''

    legend_html += '<div style="margin-top:8px;padding-top:8px;border-top:1px solid #30363d">'
    for symbol, label in symbol_items:
        legend_html += f'''
        <div style="display:flex;align-items:center;margin-bottom:8px">
            <div style="width:16px;margin-right:10px;text-align:center;
                        font-size:13px">{symbol}</div>
            <span>{label}</span>
        </div>'''
    legend_html += '</div>'

    # Pre-compute JSON
    vis_nodes_json    = json.dumps(vis_nodes)
    vis_edges_json    = json.dumps(vis_edges)
    scan_results_json = json.dumps(scan_results)
    node_data_json    = json.dumps([{
        "id":     n["id"],
        "type":   n["type"],
        "status": n["status"],
        "ip":     n["ip"],
        "port":   n["port"]
    } for n in nodes])

    vuln_count    = sum(1 for r in scan_results.values() if r.get("status") == "VULNERABLE")
    patched_count = sum(1 for r in scan_results.values() if r.get("status") == "PATCHED")
    req_ue_count  = sum(1 for r in scan_results.values() if r.get("status") == "REQUIRES_UE")
    unknown_count = sum(1 for r in scan_results.values() if r.get("status") == "UNKNOWN")

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>5G Scanner: Control Plane Architecture </title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
    <link rel="stylesheet"
          href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: #0d1117;
            color: #c9d1d9;
            font-family: 'Segoe UI', sans-serif;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }}
        header {{
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        header h1 {{
            font-size: 18px;
            font-weight: 600;
            color: #58a6ff;
        }}
        header span {{ font-size: 13px; color: #8b949e; }}
        #main {{
            display: flex;
            flex: 1;
            overflow: hidden;
        }}
        #graph {{
            flex: 1;
            background: #0d1117;
        }}
        #sidebar {{
            width: 280px;
            background: #161b22;
            border-left: 1px solid #30363d;
            padding: 20px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}
        .sidebar-section h3 {{
            font-size: 13px;
            font-weight: 600;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 12px;
        }}
        .legend {{ font-size: 13px; color: #c9d1d9; }}
        #node-detail {{
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 14px;
            font-size: 13px;
            min-height: 120px;
        }}
        #node-detail .nf-name {{
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #58a6ff;
        }}
        #node-detail .field {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 6px;
            color: #8b949e;
        }}
        #node-detail .field span {{ color: #c9d1d9; }}
        .status-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }}
        .stats {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
        }}
        .stat-box {{
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 10px;
            text-align: center;
        }}
        .stat-box .num {{ font-size: 22px; font-weight: 700; }}
        .stat-box .lbl {{ font-size: 11px; color: #8b949e; margin-top: 2px; }}
        .vulnerable {{ color: #e74c3c; }}
        .patched    {{ color: #2ecc71; }}
        .requires   {{ color: #3498db; }}
        .unknown    {{ color: #95a5a6; }}
    </style>
</head>
<body>
    <header>
        <h1>5G Scanner:  Control Plane Architecture </h1>
        <span>Target: {NRF_URL} &nbsp;|&nbsp; {len(nodes)} NFs discovered</span>
    </header>
    <div id="main">
        <div id="graph"></div>
        <div id="sidebar">
            <div class="sidebar-section">
                <h3>Summary</h3>
                <div class="stats">
                    <div class="stat-box">
                        <div class="num vulnerable">{vuln_count}</div>
                        <div class="lbl">Vulnerable</div>
                    </div>
                    <div class="stat-box">
                        <div class="num patched">{patched_count}</div>
                        <div class="lbl">Patched</div>
                    </div>
                    <div class="stat-box">
                        <div class="num requires">{req_ue_count}</div>
                        <div class="lbl">Requires UE</div>
                    </div>
                    <div class="stat-box">
                        <div class="num unknown">{unknown_count}</div>
                        <div class="lbl">Unknown</div>
                    </div>
                </div>
            </div>
            <div class="sidebar-section">
                <h3>Node Detail</h3>
                <div id="node-detail">
                    <div style="color:#8b949e;font-size:13px">
                        Click a node to see details
                    </div>
                </div>
            </div>
            <div class="sidebar-section">
                <h3>Legend</h3>
                <div class="legend">{legend_html}</div>
            </div>
        </div>
    </div>
    <script>
        const nodes = new vis.DataSet({vis_nodes_json});
        const edges = new vis.DataSet({vis_edges_json});
        const scanResults = {scan_results_json};
        const nodeData = {node_data_json};

        const container = document.getElementById('graph');
        const network = new vis.Network(container, {{nodes, edges}}, {{
            physics: {{
                enabled: true,
                solver: 'forceAtlas2Based',
                forceAtlas2Based: {{
                    gravitationalConstant: -80,
                    centralGravity: 0.01,
                    springLength: 160,
                    springConstant: 0.08
                }},
                stabilization: {{ iterations: 200 }}
            }},
            interaction: {{
                hover: true,
                tooltipDelay: 100
            }},
            edges: {{
                smooth: {{ type: 'continuous' }}
            }}
        }});

        const statusColors = {{
            "VULNERABLE":  "#e74c3c",
            "PATCHED":     "#2ecc71",
            "REQUIRES_UE": "#3498db",
            "ERROR":       "#9b59b6",
            "UNKNOWN":     "#95a5a6",
            "ATTACKER":    "#e74c3c"
        }};

        network.on('click', function(params) {{
            if (params.nodes.length === 0) return;
            const nodeId = params.nodes[0];
            const node = nodeData.find(n => n.id === nodeId);
            if (!node) return;

            const result = scanResults[node.type] || {{}};
            const status = node.status;
            const color  = statusColors[status] || '#95a5a6';

            let html = `<div class="nf-name">${{node.id}}</div>`;
            html += `<div class="field">Type   <span>${{node.type}}</span></div>`;
            html += `<div class="field">IP     <span>${{node.ip}}:${{node.port}}</span></div>`;
            html += `<div class="field">Status
                <span>
                    <span class="status-badge"
                          style="background:${{color}}20;color:${{color}}">
                        ${{status}}
                    </span>
                </span>
            </div>`;

            if (result.endpoint) {{
                html += `<div class="field">Endpoint
                    <span style="font-size:11px">${{result.endpoint}}</span>
                </div>`;
            }}
            if (result.evidence) {{
                html += `<hr style="border-color:#30363d;margin:10px 0">`;
                html += `<div style="font-size:12px;color:#8b949e;line-height:1.5">
                    ${{result.evidence}}
                </div>`;
            }}

            document.getElementById('node-detail').innerHTML = html;
        }});
    </script>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)

    return output_path