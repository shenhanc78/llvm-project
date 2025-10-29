from collections import defaultdict, deque

class GraphAlgorithm:
    @staticmethod
    def tarjan_scc(nodes, successors):
        """
        Tarjan's algorithm.
        Args:
            nodes: iterable of node ids (e.g., function names)
            successors: dict[node] -> set[node] (caller -> callees)
        Returns:
            sccs: list[list[node]] where each inner list is one SCC (arbitrary order)
            comp_id: dict[node] -> int  component index for each node
        """
        index = 0
        idx = {}
        low = {}
        onstack = set()
        stack = []
        sccs = []

        def strongconnect(v):
            nonlocal index
            idx[v] = index
            low[v] = index
            index += 1
            stack.append(v)
            onstack.add(v)

            for w in successors.get(v, ()):
                if w not in idx:
                    strongconnect(w)
                    low[v] = min(low[v], low[w])
                elif w in onstack:
                    low[v] = min(low[v], idx[w])

            # root of an SCC
            if low[v] == idx[v]:
                component = []
                while True:
                    w = stack.pop()
                    onstack.remove(w)
                    component.append(w)
                    if w == v:
                        break
                sccs.append(component)

        for v in nodes:
            if v not in idx:
                strongconnect(v)

        # component id map
        comp_id = {}
        for cid, comp in enumerate(sccs):
            for v in comp:
                comp_id[v] = cid
        return sccs, comp_id

    @staticmethod
    def build_condensed_dag(nodes, successors, predecessors):
        """
        Collapse nodes into SCC super-nodes and build the condensed DAG.
        Returns:
            sccs: list[list[node]]  original nodes per component id
            comp_id: dict[node]->int
            dag_succ: dict[cid] -> set[cid]
            dag_pred: dict[cid] -> set[cid]
        """
        sccs, comp_id = GraphAlgorithm.tarjan_scc(nodes, successors)

        dag_succ = defaultdict(set)
        dag_pred = defaultdict(set)

        for u in nodes:
            cu = comp_id[u]
            for v in successors.get(u, ()):
                cv = comp_id[v]
                if cu != cv:
                    dag_succ[cu].add(cv)
                    dag_pred[cv].add(cu)

        # ensure every component appears in maps
        C = len(sccs)
        for c in range(C):
            _ = dag_succ[c]
            _ = dag_pred[c]

        return sccs, comp_id, dag_succ, dag_pred

    @staticmethod
    def scc_order_bottom_up(dag_succ, dag_pred):
        """
        Bottom-up order on the SCC DAG: sinks first (no outgoing edges).
        Uses a Kahn-style peel from sinks upward.
        Returns:
            order: list[int] of component ids in bottom-up order.
        """
        all_cids = set(dag_succ) | set(dag_pred)
        outdeg = {c: len(dag_succ.get(c, ())) for c in all_cids}
        q = deque([c for c in all_cids if outdeg[c] == 0])
        order = []

        while q:
            u = q.popleft()
            order.append(u)
            for p in dag_pred.get(u, ()):
                outdeg[p] -= 1
                if outdeg[p] == 0:
                    q.append(p)

        # If cycles existed here, something's wrong—condensation must be a DAG.
        if len(order) != len(all_cids):
            remaining = [c for c in all_cids if c not in set(order)]
            if not remaining:
                raise ValueError("Something is wrong when generating call graph.")
            # But to be safe, append any unprocessed nodes (should be none).
            # order.extend(remaining)
        return order

    @staticmethod
    def function_order_bottom_up(nodes, successors, predecessors):
        """
        Convenience wrapper: returns
        - sccs (list of lists of original nodes),
        - bottom-up SCC id order,
        - a flattened bottom-up function order (each SCC kept as a group).
        """
        sccs, comp_id, dag_succ, dag_pred = GraphAlgorithm.build_condensed_dag(nodes, successors, predecessors)
        scc_bottom_up = GraphAlgorithm.scc_order_bottom_up(dag_succ, dag_pred)

        # Flatten functions in bottom-up SCC order.
        # For multi-node SCCs (recursion), return them as a list to process as a unit.
        grouped = [list(sccs[cid]) for cid in scc_bottom_up]
        flat = [f for group in grouped for f in group]  # if you really need a flat list

        return {
            "sccs": sccs,
            "scc_bottom_up_order": scc_bottom_up,
            "grouped_functions_bottom_up": grouped,
            "flat_functions_bottom_up": flat,
            "comp_id": comp_id,
            "condensed_successors": dag_succ,
            "condensed_predecessors": dag_pred,
        }
