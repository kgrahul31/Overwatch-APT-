import plotly.graph_objects as go
import networkx as nx

"""
Mapping our simple string threat alerts to MITRE ATT&CK Tactics/Techniques.
T1110 -> Brute Force
T1078 -> Valid Accounts
T1059 -> Command and Scripting Interpreter
T1548 -> Abuse Elevation Control Mechanism
T1486 -> Data Encrypted for Impact
T1083 -> File and Directory Discovery
T1136 -> Create Account
T1046 -> Network Service Scanning
T1112 -> Modify Registry
T1562 -> Impair Defenses
T1053 -> Scheduled Task/Job
"""

MITRE_MAP = {
    "Failed login attempts": ("Initial Access", "T1110 Brute Force"),
    "Account lockout events": ("Initial Access", "T1110 Brute Force"),
    "Suspicious process execution": ("Execution", "T1059 Command & Scripting"),
    "Privilege escalation": ("Privilege Escalation", "T1548 Elevation Control"),
    "Potential malware or ransomware": ("Impact", "T1486 Data Encrypted"),
    "Unauthorized access to critical files": ("Discovery", "T1083 File Discovery"),
    "New user account creation": ("Persistence", "T1136 Create Account"),
    "Suspicious network activity (possible port scanning)": ("Discovery", "T1046 Network Scanning"),
    "Suspicious registry changes": ("Defense Evasion", "T1112 Modify Registry"),
    "Firewall or anti-virus disabled": ("Defense Evasion", "T1562 Impair Defenses"),
    "Suspicious scheduled task": ("Execution", "T1053 Scheduled Task"),
}

def generate_attack_graph(detected_alerts):
    """
    Takes a list of string alerts, looks up their MITRE tactic & technique,
    and returns a Plotly figure representing the Attack Chain.
    """
    if not detected_alerts:
        fig = go.Figure()
        fig.update_layout(title="No Threats Detected to Graph", paper_bgcolor="#0f172a", plot_bgcolor="#0f172a", font=dict(color="#94a3b8"))
        return fig

    # Build graph
    G = nx.DiGraph()
    root = "Compromised System"
    G.add_node(root, group="root")

    for alert in set(detected_alerts):
        # Strip emojis for looking up in the map cleanly
        clean_alert = alert.split(" ", 1)[-1] if alert.startswith(('⚠️','🔒','⚙️','🔺','🦠','🚫','👤','🌐','📝','🛑','📅')) else alert
        
        # Use fallback if exact string isn't found
        mapping = MITRE_MAP.get(clean_alert)
        if mapping:
            tactic, technique = mapping
            G.add_edge(root, tactic)
            G.add_edge(tactic, technique)
            G.nodes[tactic]['group'] = "tactic"
            G.nodes[technique]['group'] = "technique"
        else:
            # Unmapped alert
            G.add_edge(root, "Unknown Tactic")
            G.add_edge("Unknown Tactic", clean_alert)
            G.nodes["Unknown Tactic"]['group'] = "tactic"
            G.nodes[clean_alert]['group'] = "technique"

    # Positioning
    try:
        pos = nx.spring_layout(G, seed=42)
    except:
        pos = nx.random_layout(G)

    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    node_x = []
    node_y = []
    text = []
    colors = []
    
    color_map = {"root": "#ef4444", "tactic": "#eab308", "technique": "#3b82f6"}

    for node in G.nodes():
        node_group = G.nodes[node].get('group', 'technique')
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        text.append(node)
        colors.append(color_map.get(node_group, "#94a3b8"))

    fig = go.Figure()
    
    # Add Edges
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color='#475569'),
        hoverinfo='none',
        mode='lines'
    ))

    # Add Nodes
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        text=text,
        textposition="top center",
        hoverinfo='text',
        marker=dict(
            showscale=False,
            color=colors,
            size=14,
            line_width=2
        )
    ))

    fig.update_layout(
        title="MITRE ATT&CK Graph",
        title_font_color="#e0e6ed",
        title_x=0.5,
        plot_bgcolor='#0f172a',
        paper_bgcolor='#0f172a',
        font=dict(color="#94a3b8"),
        showlegend=False,
        margin=dict(b=20, l=5, r=5, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )

    return fig
