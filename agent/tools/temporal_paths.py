
from collections import deque
import networkx as nx

from langchain_core.tools import tool

from agent.tools.data_utils import GRAPH_PATH


@tool
def find_temporal_paths(
    event_id: str,
    max_hops: int = 3,
    max_nodes: int = 30
) -> str:
    """
    Explore multi-hop relationships between attack event nodes
    in the NetworkX attack graph.

    Returns predecessor and successor event chains around
    the selected event.

    Use this when investigating possible sequences of related events.
    """

    try:
        if not GRAPH_PATH.exists():
            return f"Error: Attack graph not found at {GRAPH_PATH}."

        graph = nx.read_gexf(GRAPH_PATH)

        root = f"event:{event_id}"

        if root not in graph:
            return f"Event node {root} was not found in the graph."

        # Build a graph containing only event nodes.
        # This avoids treating shared host/category nodes as
        # chronological event-to-event transitions.
        event_nodes = [
            node for node in graph.nodes
            if str(node).startswith("event:")
        ]

        event_graph = nx.DiGraph()
        event_graph.add_nodes_from(event_nodes)

        for source, destination, attributes in graph.edges(data=True):
            if (
                str(source).startswith("event:") and
                str(destination).startswith("event:")
            ):
                event_graph.add_edge(
                    source,
                    destination,
                    **attributes
                )

        def explore(start, direction):
            queue = deque([(start, [start], 0)])
            results = []
            visited = {start}

            while queue and len(results) < max_nodes:
                current, path, depth = queue.popleft()

                if depth >= max_hops:
                    continue

                neighbours = (
                    list(event_graph.successors(current))
                    if direction == "forward"
                    else list(event_graph.predecessors(current))
                )

                for neighbour in neighbours:

                    if neighbour in visited:
                        continue

                    visited.add(neighbour)

                    new_path = (
                        path + [neighbour]
                        if direction == "forward"
                        else [neighbour] + path
                    )

                    results.append({
                        "direction": direction,
                        "path": new_path,
                        "hops": depth + 1
                    })

                    queue.append(
                        (neighbour, new_path, depth + 1)
                    )

                    if len(results) >= max_nodes:
                        break

            return results

        predecessors = explore(root, "backward")
        successors = explore(root, "forward")

        result = {
            "event_id": event_id,
            "max_hops": max_hops,
            "predecessor_paths": predecessors,
            "successor_paths": successors,
            "graph_event_nodes": event_graph.number_of_nodes(),
            "graph_event_edges": event_graph.number_of_edges()
        }

        import json

        return json.dumps(result, indent=2, default=str)

    except Exception as e:
        return f"Error exploring temporal paths: {str(e)}"
