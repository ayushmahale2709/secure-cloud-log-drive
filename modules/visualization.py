import graphviz


# -------------------------------------------------
# BLOCKCHAIN VISUALIZATION
# -------------------------------------------------

def draw_blockchain(chain):
    """
    Create a visual representation of the blockchain.
    Each block connects to the next block.
    """

    graph = graphviz.Digraph()

    graph.attr(rankdir="LR")

    for block in chain:

        label = f"""
Block {block.index}

Owner: {block.owner}

Hash:
{block.hash[:10]}...
"""

        graph.node(
            str(block.index),
            label,
            shape="box",
            style="filled",
            fillcolor="#1e293b",
            fontcolor="white"
        )

    for i in range(len(chain) - 1):
        graph.edge(str(chain[i].index), str(chain[i + 1].index))

    return graph


# -------------------------------------------------
# SYSTEM ARCHITECTURE DIAGRAM
# -------------------------------------------------

def draw_architecture():

    graph = graphviz.Digraph()

    graph.attr(rankdir="TB")

    graph.node(
        "User",
        "User",
        shape="circle",
        style="filled",
        fillcolor="#2563eb",
        fontcolor="white"
    )

    graph.node(
        "App",
        "Streamlit Application",
        shape="box",
        style="filled",
        fillcolor="#1e293b",
        fontcolor="white"
    )

    graph.node(
        "Auth",
        "Authentication System",
        shape="box"
    )

    graph.node(
        "Blockchain",
        "Blockchain Log Storage",
        shape="box"
    )

    graph.node(
        "Search",
        "Search Index",
        shape="box"
    )

    graph.node(
        "AI",
        "Anomaly Detection",
        shape="box"
    )

    graph.edge("User", "App")
    graph.edge("App", "Auth")
    graph.edge("App", "Blockchain")
    graph.edge("Blockchain", "Search")
    graph.edge("App", "AI")

    return graph


# -------------------------------------------------
# THREAT FLOW VISUALIZATION
# -------------------------------------------------

def draw_threat_flow(threat_level):

    graph = graphviz.Digraph()

    graph.node(
        "User",
        "User Activity",
        shape="circle"
    )

    if threat_level == "LOW":

        graph.node(
            "Normal",
            "Normal Behavior",
            style="filled",
            fillcolor="lightgreen"
        )

        graph.edge("User", "Normal")

    elif threat_level == "MEDIUM":

        graph.node(
            "Anomaly",
            "Suspicious Activity",
            style="filled",
            fillcolor="orange"
        )

        graph.edge("User", "Anomaly")

    else:

        graph.node(
            "Anomaly",
            "Suspicious Activity",
            style="filled",
            fillcolor="orange"
        )

        graph.node(
            "Threat",
            "Security Threat",
            style="filled",
            fillcolor="red"
        )

        graph.edge("User", "Anomaly")
        graph.edge("Anomaly", "Threat")

    return graph
