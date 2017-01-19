import networkx as nx

def join(network, exclude, T, v):
    """Used to construct SPTs.
    
    See algorithm 2 in 'Resilient SDN-based multicast'.
    
    Arguments:
    network: network graph
    exclude: all links that should be excluded from the trees
    T: current trees
    v: node to be added to T
    """
    
    if v in T:
        return []
        
    epsilon = 1.0/(T.size() + 1) #1/(num_edges + 1)
        
    def weight(x, y, edata):
        if not edata['live']:
            return None
        if (x,y) in exclude:
            return None
        if T.has_edge(x,y):
            return 1.0 - epsilon
        if y in T:
            return None #Resulting trees should actually be trees
        return 1.0

    try:
        return nx.dijkstra_path(network, T.graph['root'], v, weight)
    except (nx.NetworkXNoPath, nx.NetworkXError):
        return []
