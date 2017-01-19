import networkx as nx

def join(network, exclude, T, v):
    """Implementation of the greedy approximation algorithm for constructing DSTs.
    
    See algorithm 3 in 'Resilient SDN-based multicast'.
    
    Arguments:
    network: network graph
    exclude: all links that should be excluded from the trees
    T: current trees
    v: node to be added to T
    """
    
    if v in T:
        return []
        
    def weight(x, y, edata):
        if not edata['live']:
            return None
        if (x,y) in exclude:
            return None
        if not T.has_edge(x,y) and y in T:
            return None #Resulting trees should actually be trees
        return 1
    try:
        length, paths = nx.multi_source_dijkstra(G=network, sources=set(T.nodes()), target=v, weight=weight)
        if v not in paths:
            return []
        path = paths[v]

        w = path[0]

        
        pre = []

        cur = w
        root = T.graph['root']
        while cur != root:
            cur = list(T.predecessors(cur))[0]
            pre.append(cur)

        pre.reverse()
        
        return pre + path
    except (nx.NetworkXNoPath, nx.NetworkXError):
        return []
