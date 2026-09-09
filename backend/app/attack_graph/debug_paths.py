import networkx as nx
from app.database import SessionLocal
from app.attack_graph.graph_engine import build_graph

db = SessionLocal()
graph = build_graph(db)

high_value_targets = [
    n for n, data in graph.nodes(data=True)
    if data.get("risk_score", 0) >= 50 or data.get("asset_type") in ("server", "router")
]
print("high_value_targets:", high_value_targets)

print("\nChemins directs 1 -> 2 :")
try:
    paths = list(nx.all_simple_paths(graph, 1, 2, cutoff=4))
    print(paths)
except Exception as e:
    print("Erreur:", e)

db.close()
