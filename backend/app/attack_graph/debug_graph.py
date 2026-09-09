from app.database import SessionLocal
from app.attack_graph.graph_engine import build_graph

db = SessionLocal()
graph = build_graph(db)

print("=== NODES ===")
for n, data in graph.nodes(data=True):
    print(f"  {n}: {data}")

print("\n=== EDGES ===")
for u, v, data in graph.edges(data=True):
    print(f"  {u} -> {v}: {data}")

db.close()
