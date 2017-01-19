import networkx as nx

from abc import ABCMeta, abstractmethod 
from collections import deque

class AbstractTreeBuilder:
    """Treebuilders keep track and maintain the trees of all multicast groups."""
    
    __metaclass__ = ABCMeta
    
    #Maximum VLAN tag number
    max_vid = 4094

    def __init__(self, F, controller, join):
        self.F = F
        self.groups = {}
        self.controller = controller
        self.join = join

    def create_group(self, ip_group, ip_source, switch_id):
        """Create a new multicast group/tree rooted at switch_id.
        
        No new group gets created if a group with ip_group and ip_source already exists.
        
        Arguments:
        ip_group: IP address of the group
        ip_source: IP address of the source
        switch_id: id of the root switch
        
        Each multicast group is uniquely identiefied by their group address and source address
        """
        
        key = (ip_group, ip_source)

        if key in self.groups:
            self.controller.log('group ' + str(key) + ' already created')
        else:
            self.groups[key] = self._create_tree(switch_id)
            self.controller.log('created new group: ' + str(key))

    def _create_tree(self, switch_id, parent = None, predecessor_switch = None):
        """Create a new tree rooted at switch_id. Automatically assigns correct tag.
        
        Arguments:
        switch_id: id of the root switch
        parent: parent tree, or None if the new tree is a primary tree
        predecessor_switch: id of previous switch on current packet path, or None if it does not exist
        """
        
        tree = nx.DiGraph(root = switch_id, parent = parent)
        tree.add_node(switch_id)
        
        tree.graph['predecessor_switch'] = predecessor_switch

        if parent == None:
            tree.graph['tag_index'] = 1
            tree.graph['tag'] = None
            tree.graph['primary'] = tree
        else:
            primary = parent.graph['primary']
            tree.graph['primary'] = primary

            tag = primary.graph['tag_index']
            tree.graph['tag'] = tag

            tag = tag + 1
            if tag > self.max_vid:
                tag = 1 #Assuming we can cycle through tags
            primary.graph['tag_index'] = tag
            
        return tree

    def _undo_tree(self, tree):
        """Undoes creating tree. DOES NOT WORK PROPERLY IF tree WAS NOT THE LAST TREE CREATED."""
        
        if tree.graph['parent'] != None:
            primary = tree.graph['primary']
            tag = primary.graph['tag_index']

            tag = tag - 1
            if tag < 1:
                tag = self.max_vid

            primary.graph['tag_index'] = tag
            
    @abstractmethod   
    def _process_request(self, T, v, r, F, ip_group, ip_source):
        """Add or remove v from tree T
        
        Arguments:
        T: (primary) tree
        v: subscriber to be added to THE
        r: true if v should be added to T, false otherwise
        F: amount of (link) fault tolerance required
        ip_group: IP address of multicast group of T
        ip_source: IP address of source of T
        """
        
        pass
        
    def add_subscriber(self, ip_group, ip_source, subscriber):
        """Add subscriber to the multicast group identified by ip_group and ip_source.
        
        Arguments:
        ip_group: IP address of the group
        ip_source: IP address of the source
        subscriber: id of new subscriber        
        """
    
        key = (ip_group, ip_source)
        if key not in self.groups:
            self.controller.log('group ' + str(key) + ' does not exist')
            return

        tree = self.groups[key]
        if subscriber in tree:
            self.controller.log(str(subscriber) + ' already added to ' + str(key))
            return

        if self._process_request(tree, subscriber, True, self.F, ip_group, ip_source):
            self.controller.log(str(subscriber) + ' added to group ' + str(key))

    def remove_group(self, ip_group, ip_source):
        """Remove/Destroy multicast group/tree identified by ip_group and ip_source.
        
        Arguments:
        ip_group: IP address of the group
        ip_source: IP address of the source
        """
    
        key = (ip_group, ip_source)
        if key not in self.groups:
            self.controller.log('group ' + str(key) + ' does not exist')
            return
        
        tree = self.groups[key]
        
        self._remove_all_flows(ip_group, ip_source, tree)
            
        del self.groups[key]

        self.controller.log('Group ' + str(key) + ' removed')

    def _remove_all_flows(self, ip_group, ip_source, tree):
        tag = tree.graph['tag']

        for node in tree:            
            dsts = list(tree.successors(node))
            if len(dsts) > 0:
                self.controller.remove_flow(node, ip_group, 'all', True, ip_source, tag)
                
                for dst in dsts:
                    backup = tree[node][dst]['backup']
                    if backup != None:
                        self._remove_all_flows(ip_group, ip_source, backup)

    def remove_subscriber(self, ip_group, ip_source, subscriber):
        """Remove subscriber from the multicast group identified by ip_group and ip_source.
        
        Arguments:
        ip_group: IP address of the group
        ip_source: IP address of the source
        subscriber: id of subscriber        
        """
        
        key = (ip_group, ip_source)
        if key not in self.groups:
            self.controller.log('group ' + str(key) + ' does not exist')
            return
            
        tree = self.groups[key]
        
        if subscriber not in tree:
            self.controller.log(str(subscriber) + ' not subscribed to ' + str(key))
            return
        
        if self._process_request(tree, subscriber, False, self.F, ip_group, ip_source):
            self.controller.log(str(subscriber) + ' removed from group ' + str(key))

    @abstractmethod
    def _remove_flow(self, src, dst, ip_group, ip_source, tree):
        """Remove flow from src to dst in tree."""
        pass

    @abstractmethod
    def _remove_backup(self, predecessor, src, orig_dst, dst, ip_group, ip_source, tag):
        """Remove backup entry for flow from src to orig_dst"""
        pass

    def _leave(self, T, v, ip_group, ip_source, origin_dst=None):
        """Remove v from tree T.
        
        Arguments:
        T: tree
        v: subscriber to remove from T
        ip_group: IP address of multicast group of T
        ip_source: IP address of source of T
        origin_dst: only used by _leave itself, should be ignored when calling _leave
        """
        
        root = T.graph['root']

        if v not in T or v == root:
            return

        tag = T.graph['tag']

        cur = v
        while T.out_degree(cur) <= 1 and cur != root:
            pre = list(T.predecessors(cur))[0]

            if pre != root or T.graph['parent'] == None:                
                self._remove_flow(pre, cur, ip_group, ip_source, T)
            else:
                self._remove_backup(T.graph['predecessor_switch'], pre, origin_dst, 
                cur, ip_group, ip_source, tag)

            cur = pre

        cur = v
        while cur != root:
            pre = list(T.predecessors(cur))[0]

            backup = T[pre][cur]['backup']
            if backup != None:
                self._leave(backup, v, ip_group, ip_source, cur)

            cur = pre

        cur = v
        while T.out_degree(cur) == 0 and cur != root:
            pre = list(T.predecessors(cur))[0]

            T.remove_node(cur)

            cur = pre
    
    def repair(self, broken_links):
        """Repair all trees for failures broken_links. Currently calls to this function are ignored, 
        because this should be done in a more sophisticated way."""
        
        return
        self.controller.log('Starting repairs')

        for key in self.groups:
            tree = self.groups[key]
            self._repair(set(broken_links), tree, key[0], key[1])

        self.controller.log('Repairs finished')

    def _repair(self, broken_links, tree, ip_group, ip_source):
        affected = set()
        for link in broken_links:
            if tree.has_edge(link[0], link[1]):
                affected.update(self._get_subscribers(tree, link[1]))

        for subscriber in affected:
            self.remove_subscriber(ip_group, ip_source, subscriber)

        for subscriber in affected:
            self.add_subscriber(ip_group, ip_source, subscriber)

    def _get_subscribers(self, tree, root):
        subscribers = []

        for suc in tree.successors(root):
            if tree.out_degree(suc) == 0:
                subscribers.append(suc)
            else:
                subscribers.extend(self._get_subscribers(tree, suc))

        return subscribers
