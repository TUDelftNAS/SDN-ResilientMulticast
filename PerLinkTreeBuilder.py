import networkx as nx

import AbstractTreeBuilder
from collections import deque

class PerLinkTreeBuilder(AbstractTreeBuilder.AbstractTreeBuilder):
    """Protects against F link failures by installing backup trees for all protected links"""

    def _process_request(self, T, v, r, F, ip_group, ip_source):
        """Implementation of algorithm 4 from 'Resilient SDN-based multicast'"""
    
        if not r:
            return self._leave(T, v, ip_group, ip_source)
            
        network = self.controller.get_network()
        path = self.join(network, [], T, v)
        
        if len(path) == 0:
            self.controller.log('no path from ' + str(T.graph['root']) + ' to ' + str(v))
            return False
            
        self._add_path(ip_group, ip_source, T, path, F > 0)
        
        queue = deque()
        if F > 0:
            queue.append((path, T, []))
        
        while len(queue) > 0:
            path, T, down = queue.popleft()
            
            for i in range(1, len(path)):
                x = path[i-1]
                y = path[i]
                predecessor = path[i-2] if i >= 2 else T.graph['predecessor_switch']
                
                backup = T[x][y]['backup']

                if backup is None:
                    backup = self._create_tree(x, T, predecessor)
                    T[x][y]['backup'] = backup
                    
                L = set(down)
                L.add((x,y))
                L.add((y,x))
                
                b_path = self.join(network, L, backup , v)
                
                if len(b_path) > 0:
                    not_done = len(L)/2 < F

                    if b_path[1] not in backup[x]:                        
                        self.controller.add_backup(predecessor, x, ip_group, y, b_path[1], 
                        ip_source, backup.graph['tag'], T.graph['tag'], not_done)
                        backup.add_edge(x, b_path[1], backup = None)

                    self._add_path(ip_group, ip_source, backup, b_path[1:], not_done)
                    
                    if not_done:
                        queue.append((b_path, backup, L))
                else:
                    self.controller.log('no backup path from ' + str(x) + ' to ' + str(v))

                    if backup.number_of_edges() == 0:
                        T[x][y]['backup'] = None
                        self._undo_tree(backup)
        return True

    def _add_path(self, ip_group, ip_source, tree, path, needs_backup=False):
        """Add path to tree and install the necessary flow entries."""
    
        tag = tree.graph['tag']

        for i in range(len(path) - 1, 0, -1):
            prev = path[i - 1]
            cur = path[i]

            if prev not in tree or cur not in tree[prev]:
                self.controller.add_flow(prev, ip_group, [cur], True, ip_source, tag)
                tree.add_edge(prev, cur, backup=None)
            else:
                break

    def _remove_flow(self, src, dst, ip_group, ip_source, tree):
        self.controller.remove_flow(src, ip_group, [dst], True, ip_source, tree.graph['tag'])

    def _remove_backup(self, predecessor, src, orig_dst, dst, ip_group, ip_source, tag):
        self.controller.remove_backup(predecessor, src, ip_group, orig_dst, dst, ip_source, tag)
