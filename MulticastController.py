from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import in_proto
from ryu.lib.packet import igmp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host

import networkx as nx
import itertools as it

import PerLinkTreeBuilder
from SPT import join as SPT_join
from DST import join as DST_join

class MulticastController(app_manager.RyuApp):
    """The Multicast Controller is responsible for installing flow and group entries, 
    adding and removing hosts to and from groups 
    and generally facilitating all communication with the OpenFlow switches."""
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    LOWPRIO = 1
    MEDPRIO = 2
    HIGHPRIO = 3
    HIGHESTPRIO = 4

    FLOOD_TABLE = 4

    def __init__(self, *args, **kwargs):
        super(MulticastController, self).__init__(*args, **kwargs)

        self.network = nx.DiGraph()
        self.span_tree = None
        self.builder = PerLinkTreeBuilder.PerLinkTreeBuilder(3, self, SPT_join) #F,.,join function
        self.groups = {} #ip_group -> [ip_sources]

        self.ip_2_mac = {}

    def log(self, message):
        self.logger.info(message)
        return

    def get_network(self):
        """Returns network graph."""
        return self.network

    def get_source_node(self, ip_source):
        """Returns id of node with IP address ip_source."""
        
        return self.ip_2_mac[ip_source]

    def _add_FF_group(self, switch_id, g_key, port, tag):
        """Add a new FF group table to switch switch_id.
        
        Creates an FF group with a single bucket with watch and output port 'port'.
        
        Arguments:
        switch_id: id of switch to add group table to
        g_key: key used to store this group in the FF_groups map
        port: port to output to in bucket 1
        tag: packet VLAN tag
        """
        dp = self.network.node[switch_id]['switch'].dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        actions = [parser.OFPActionOutput(port)]
        buckets = [parser.OFPBucket(0, port, 0, actions)]

        g_id = self._add_group(switch_id, buckets)

        groups = self.network.node[switch_id]['FF_groups']
        groups[g_key] = [(g_id, 0)]

        buckets_map = self.network.node[switch_id]['buckets']
        buckets_map[g_id] = [(port, tag, False)]

    def _add_group(self, switch_id, buckets):
        """Add a new FF group table to switch switch_id with buckets 'buckets'."""
        
        dp = self.network.node[switch_id]['switch'].dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        g_id = self.network.node[switch_id]['group_id_index']
        g_type = ofp.OFPGT_FF

        cmd = parser.OFPGroupMod(dp, ofp.OFPGC_ADD, g_type, g_id, buckets)
        dp.send_msg(cmd)        

        self.log('Added group ' + str(g_id) + ' to switch ' + str(switch_id))

        #TODO: Use buckets map to check for free g_id's
        g_index = g_id + 1
        if g_index < 1: #TODO: Can we replace this with a maximum value gotten from the switch itself?
            g_index = 1 #Here we assume that by this time group id 1 is available again
        self.network.node[switch_id]['group_id_index'] = g_index

        return g_id

    def _remove_FF_group(self, switch_id, g_id, dst_address, src_address, prev_switch_id):
        """Remove group with id g_id from switch switch_id.
        
        Arguments:
        switch_id: id of switch to remove group table from
        g_id: group id
        dst_address: ip or mac address of destination
        src_address: ip or mac address of source
        prev_switch_id: id of previous switch in packet path
        """
    
        dp = self.network.node[switch_id]['switch'].dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        cmd = parser.OFPGroupMod(dp, ofp.OFPGC_DELETE, ofp.OFPGT_FF, g_id)
        dp.send_msg(cmd)

        FF_groups = self.network.node[switch_id]['FF_groups']
        buckets_map = self.network.node[switch_id]['buckets']

        g_buckets = buckets_map[g_id]

        #Remove group from FF_groups
        for i in range(len(g_buckets)-1,0,-1):
            port,tag,drop = g_buckets[i]

            if not drop:
                del FF_groups[self._get_FF_key(port, 
                    self._get_key(True, dst_address, src_address, tag, prev_switch_id))]
            else:
                break

        #Get list of all copies of FF groups for the same primary link
        first_bucket = g_buckets[0]
        f_port = first_bucket[0]
        f_tag = first_bucket[1]
        f_g_key = self._get_FF_key(f_port, 
            self._get_key(True, dst_address, src_address, f_tag, prev_switch_id))
        first_groups = FF_groups[f_g_key]

        #Remove this group from the list
        for i in range(0,len(first_groups)):
            if first_groups[i][0] == g_id:
                first_groups.pop(i)

        if len(first_groups) == 0:
            del FF_groups[f_g_key]

        del buckets_map[g_id]

        self.log('removed group ' + str(g_id) + 'from switch ' + str(switch_id))        

    #Solely meant for Fast Tree Switching
    def set_tagged_flow(self, switch_id, dst_address, dsts, src_address, tag, origin_tag):
        """Function solely created for testing Fast Tree Switching.
        Adds or modifies a flow entry to output to all dsts and add VLAN tag 'tag'
        
        Arguments:
        switch_id: id of switch to add flow entry to
        dst_address: IP address of destination of packet
        dsts: switch (or host) ids to send packet to
        src_address: IP address of source of packet
        tag: VLAN tag to tag packet with
        origin_tag: previous tag of packet, or None if tagged is not tagged yet
        """
    
        dp = self.network.node[switch_id]['switch'].dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        key = self._get_key(True, dst_address, src_address, origin_tag, None)

        ports_s, ports_h = self._get_ports(switch_id, dsts)
        FF_groups = {}

        flows = self.network.node[switch_id]['flows']
        if key in flows:
            current_s, current_h, current_tables = flows[key]
        else:
            current_tables = 0

        match = self._get_match(parser, ofp, dst_address, src_address, True, origin_tag, None)

        prio = self._get_priority(origin_tag, None)

        actions = []

        if tag is None:
            action_list = []

            for port in ports_s:
                action_list.append(parser.OFPActionOutput(port))
            for port in ports_h:
                action_list.append(parser.OFPActionOutput(port))

            actions.append(action_list)

        else:
            if len(ports_s) > 0:
                action_list = [parser.OFPActionPushVlan()] if origin_tag is None else []
                action_list.append(parser.OFPActionSetField(vlan_vid = (0x1000 | tag)))

                for port in ports_s:
                    action_list.append(parser.OFPActionOutput(port))

                actions.append(action_list)

            if len(ports_h) > 0:
                action_list = [parser.OFPActionOutput(port) for port in ports_h]
                actions.append(action_list)

        self._install_actions(dp, parser, ofp, prio, current_tables, match, actions)

        flows[key] = (ports_s, ports_h, len(actions))

        self.log('ADDED/MODDIFIED FLOW FROM SWITCH ' + str(switch_id) 
                + ' TO PORTS ' + str(ports_s) + ' AND ' + str(ports_h))

        self.log('DESTINATION = ' + str(dst_address))
        if tag is not None:
            self.log('TAG = ' + str(tag))

    def add_flow(self, switch_id, dst_address, dsts, multicast = False, 
                src_address = None, tag = None, forced = False, prev_switch_id = None):
        """Add a flow to switch switch_id to output to dsts.
        
        If a flow entry to dst_address (from src_address) already exists, 
        this entry gets modified to also output to dsts.
        
        Arguments:
        switch_id: id of switch to add flow to
        dst_address: if multicast: IP address of the destination (i.e. the group address)
                     else: MAC address of the destination
        dsts: switch or host ids to output packet to
        multicast: True if the packet is multicast, False otherwise
        src_address: IP address of packet source. Only required when multicast == True
        tag: VLAN tag to match packet to, None if packet should not be matched to a tag.
        forced: force the flow entry to be re-installed, even if a flow to dsts already exists
        prev_switch_id: id of the previous switch on the packet path, None if this should not be matched to
        """
        
        dp = self.network.node[switch_id]['switch'].dp
        key = self._get_key(multicast, dst_address, src_address, tag, prev_switch_id)
        
        ports_s,ports_h = self._get_ports(switch_id, dsts)

        FF_groups = self.network.node[switch_id]['FF_groups']

        in_port = None if prev_switch_id is None else self.network[prev_switch_id][switch_id]['dst_port']

        ofp = dp.ofproto
        parser = dp.ofproto_parser

        install = False
        current_tables = 0
        flows = self.network.node[switch_id]['flows']
        #Check if a flow already exists
        if key in flows and (len(flows[key][0]) > 0 or len(flows[key][1]) > 0):
            current_s,current_h,current_tables = flows[key]
            
            if forced:
                ports_s.update(current_s)
                ports_h.update(current_h)
                install = True
            else:
                #Check if this flow already contains these ports
                for port in ports_s:
                    if port not in current_s:
                        ports_s.update(current_s)
                        ports_h.update(current_h)
                        install = True
                        break
                if not install:
                    for port in ports_h:
                        if port not in current_h:
                            ports_s.update(current_s)
                            ports_h.update(current_h)
                            install = True
                            break
        else:
            install = True

        if install:
            match = self._get_match(parser, ofp, dst_address, src_address, multicast, tag, in_port)

            prio =  self._get_priority(tag, in_port)
                
            actions = self._get_actions(parser, FF_groups, key, tag, ports_s, ports_h)

            self._install_actions(dp, parser, ofp, prio, current_tables, match, actions)

            flows[key] = (ports_s,ports_h,len(actions))

            self.log('ADDED/MODDIFIED FLOW FROM SWITCH ' + str(switch_id) + ' TO PORTS ' 
                    + str(ports_s) + ' AND ' + str(ports_h))
            self.log('DESTINATION = ' + str(dst_address))
            if tag is not None:
                self.log('TAG = ' + str(tag))

    def _get_key(self, multicast, dst_address, src_address, tag, prev_switch_id):
        """Returns unique key for flow entry."""
    
        if multicast:
            return (dst_address, src_address, tag, prev_switch_id)
        else:
            return dst_address

    def _get_FF_key(self, port, key):
        """Returns FF_groups key."""
        
        return (port, key)

    def _get_priority(self, tag, in_port):
        ret = self.MEDPRIO if tag is None else self.HIGHPRIO
        return ret if in_port is None else ret+1

    def _get_ports(self, switch_id, dsts):
        """Returns (ports_s, ports_h). 
        Where ports_s is a set of ports corresponding to dsts to switches.
        And where ports_h is a set of ports corresponding to dsts to hosts.
        """
    
        ports_s = set()
        ports_h = set()
        for dst in dsts:
            port = self.network[switch_id][dst]['src_port']
            if self.network.node[dst]['host']:
                ports_h.add(port)
            else:
                ports_s.add(port)

        return (ports_s, ports_h)

    def _get_match(self , parser, ofp, dst_address, src_address, multicast, tag, in_port):
        if multicast:
            match = parser.OFPMatch(eth_dst=self.ip_2_mac[dst_address], eth_src=self.ip_2_mac[src_address])
        else:
            match = parser.OFPMatch(eth_dst=dst_address)

        if tag is not None:
            match = parser.OFPMatch(vlan_vid=(0x1000 | tag), **dict(match.items()))

        if in_port is not None:
            match = parser.OFPMatch(in_port=in_port, **dict(match.items()))

        return match

    def _get_actions(self, parser, FF_groups, key, tag, ports_s, ports_h):
        """Returns a list of action-lists.
        
        List 0 should be added to flow table 0, list 1 to flow table 1, etc.
        Returns a maximum of 3 action-lists
        """
    
        actions = []

        actions_groups = []
        actions_outputs = []
        actions_remove_tag = []
        actions_remove_tag.append(parser.OFPActionPopVlan())

        for port in ports_s:
            if self._get_FF_key(port, key) in FF_groups:
                for g_id,index in FF_groups[(port, key)]:
                    actions_groups.append(parser.OFPActionGroup(g_id))
            else:
                actions_outputs.append(parser.OFPActionOutput(port))

        for port in ports_h:
            if tag is None:
                actions_outputs.append(parser.OFPActionOutput(port))
            else:
                actions_remove_tag.append(parser.OFPActionOutput(port))

        if len(actions_groups) > 0:
            actions.append(actions_groups)
        if len(actions_outputs) > 0:
            actions.append(actions_outputs)
        if len(actions_remove_tag) > 1:
            actions.append(actions_remove_tag)

        return actions            

    def _install_actions(self, dp, parser, ofp, prio, current_tables, match, actions):
        for i in range(0, len(actions)):
            instr = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions[i])]

            if len(actions) - 1 > i:
                instr.append(parser.OFPInstructionGotoTable(i + 1))

            if i < current_tables:
                command = ofp.OFPFC_MODIFY_STRICT
            else:
                command = ofp.OFPFC_ADD

            cmd = parser.OFPFlowMod(
                datapath=dp, table_id=i, command=command, priority=prio, match=match,
                instructions=instr, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY)
            dp.send_msg(cmd)

        for i in range(len(actions), current_tables):
            cmd = parser.OFPFlowMod(dp, table_id=i, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                    command=ofp.OFPFC_DELETE_STRICT, match=match, priority=prio)
            dp.send_msg(cmd)

    def remove_flow(self, switch_id, dst_address, dsts, multicast = False, 
                    src_address = None, tag = None, prev_switch_id = None):
        """Remove flow in switch_id to dsts.
        
        If the corresponding flow entry outputs to other dsts too, it gets modified insteaf of removed.
        
        Arguments:
        switch_id: id of switch to remove flow from
        dst_address: if multicast: IP address of the destination (i.e. the group address)
                     else: MAC address of the destination
        dsts: switch or host ids to stop outputting packet to
        multicast: True if the packet is multicast, False otherwise
        src_address: IP address of packet source. Only required when multicast == True
        tag: VLAN tag used to match packet to, None if packet was not be matched to a tag.
        prev_switch_id: id of the previous switch on the packet path, None if this was not matched to
        """
                    
        dp = self.network.node[switch_id]['switch'].dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        key = self._get_key(multicast, dst_address, src_address, tag, prev_switch_id)

        in_port = None if prev_switch_id is None else self.network[prev_switch_id][switch_id]['dst_port']

        flows = self.network.node[switch_id]['flows']
        if key not in flows:
            self.log('Tried to remove flows from ' + str(switch_id) + ' to ' + 
                    str(dsts) + ' , but these do not exist')
            if tag is not None:
                self.log('Tag = ' + str(tag))
            return

        current_s,current_h,current_tables = flows[key]

        prio =  self._get_priority(tag, in_port)

        FF_groups = self.network.node[switch_id]['FF_groups']

        if dsts == 'all':
            other_s = []
            other_h = []
        else:
            #Find all ports that should remain
            ports_s,ports_h = self._get_ports(switch_id, dsts)
            other_s = [port for port in current_s if port not in ports_s]
            other_h = [port for port in current_h if port not in ports_h]

        match = self._get_match(parser, ofp, dst_address, src_address, multicast, tag, in_port)

        if len(other_s) == 0 and len(other_h) == 0:
            for i in range(0,current_tables):
                cmd = parser.OFPFlowMod(dp, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, 
                                        command=ofp.OFPFC_DELETE_STRICT, match=match, priority = prio)
                dp.send_msg(cmd)
        else:
            actions = self._get_actions(parser, FF_groups, key, tag, other_s, other_h)

            self._install_actions(dp, parser, ofp, prio, current_tables, match, actions)

        if other_s or other_h:
           flows[key] = (other_s,other_h,len(actions))
        else:
            del flows[key]

        #Remove all relevant groups
        if dsts == 'all':
            for port in current_s:
                g_key = self._get_FF_key(port, key)
                if g_key in FF_groups:
                    for g_id,index in FF_groups[g_key]:
                        self._remove_FF_group(switch_id, g_id, dst_address, src_address, prev_switch_id)
       
        else:
            for port in filter(lambda p: p in current_s, ports_s):
                g_key = self._get_FF_key(port, key)
                if g_key in FF_groups:
                    for g_id,index in FF_groups[g_key]:
                        self._remove_FF_group(switch_id, g_id, dst_address, src_address, prev_switch_id)

        self.log('REMOVED FLOW FROM SWITCH ' + str(switch_id) + ' TO PORTS ' + 
                str(ports_s) + 'AND ' + str(ports_h))
        self.log('DESTINATION = ' + str(dst_address))
        if tag is not None:
            self.log('TAG = ' + str(tag))

    def _parse_buckets_list(self, in_port, buckets, dp):
        if len(buckets) == 0:
            return []
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        parsed = []

        tagged = buckets[0][1] is not None

        for port,tag,drop in buckets:
            actions = []

            if not drop:
                if tag is not None and len(parsed) > 0:
                    if not tagged:
                        actions.append(parser.OFPActionPushVlan())
                    actions.append(parser.OFPActionSetField(vlan_vid = (0x1000 | tag)))

                if isinstance(port ,list):
                    for p in port:
                        actions.append(parser.OFPActionOutput(p if p != in_port else ofp.OFPP_IN_PORT))
                    port = in_port
                else:
                    actions.append(parser.OFPActionOutput(port if port != in_port else ofp.OFPP_IN_PORT))
        
            parsed.append(parser.OFPBucket(0, port, 0, actions))

        return parsed

    #Only for ipv4 multicast trees
    def add_backup(self, prev_switch_id, switch_id, dst_address, dst, backup_dst, 
                src_address, tag, tag_origin = None, needs_backup = False, in_port_flow = False):
        """Add backup in switch switch_id for link to dst. Only use this for IPV4 multicast.
        
        Arguments:
        prev_switch_id: if of previous switch on packet path
        switch_id: id of switch to add backup to
        dst_address: IP group address
        dst: dst to add backup for
        backup_dst: backup output destination
        src_address: IP address of packet source
        tag: new tag
        tag_origin: current tag
        needs_backup: True if backup could also be added for backup_dst itself, False otherwise
        in_port_flow: True if in_port was matched to, False otherwise
        """
                
        dp = self.network.node[switch_id]['switch'].dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        if prev_switch_id is None:
            in_port = 0
        else:
            in_port = self.network[prev_switch_id][switch_id]['dst_port']

        if not in_port_flow:
            prev_switch_id = None

        key_origin = self._get_key (True, dst_address, src_address, tag_origin, prev_switch_id)
        key_backup = self._get_key(True, dst_address, src_address, tag, prev_switch_id)
        port = self.network[switch_id][dst]['src_port']

        backup_port = self.network[switch_id][backup_dst]['src_port']

        FF_groups = self.network.node[switch_id]['FF_groups']

        log_message = 'Adding backup ' + str(backup_dst) + ' for ' + str(dst) + ' in switch ' + str(switch_id)
        if prev_switch_id is not None:
            log_message = log_message + ' (traffic coming from ' + str(prev_switch_id) + ')'
        self.log(log_message)

        b_g_key = self._get_FF_key(backup_port, key_backup)

        if b_g_key in FF_groups:
            self.log('FAILED: backup already installed')
            return

        g_key = self._get_FF_key(port, key_origin)

        if g_key not in FF_groups:
            self._add_FF_group(switch_id, g_key, port, tag_origin)
            self.add_flow(switch_id, dst_address, [], True, src_address, tag_origin, True, prev_switch_id)
        
        buckets = self.network.node[switch_id]['buckets']

        groups = FF_groups[g_key]
        base_id, index = groups[0]
        base_group = buckets[base_id]

        #Case with no existing backup
        if len(base_group) == index+1:
            base_group.append((backup_port, tag, False))

            cmd = parser.OFPGroupMod(dp, ofp.OFPGC_MODIFY, ofp.OFPGT_FF, base_id, 
                                    self._parse_buckets_list(in_port, base_group, dp))
            dp.send_msg(cmd)

            FF_groups[b_g_key] = [(base_id, index+1)]

        #Can just output to multiple ports in last bucket
        #Here we assume tag is the same for both outputs (should be the case normally)
        elif not needs_backup:
            port_list = base_group[index+1][0]
            if not isinstance(port_list, list):
                port_list = [port_list]
                base_group[index+1] = (port_list, tag, False)
            port_list.append(backup_port)

            cmd = parser.OFPGroupMod(dp, ofp.OFPGC_MODIFY, ofp.OFPGT_FF, base_id, 
                                    self._parse_buckets_list(in_port, base_group, dp))
            dp.send_msg(cmd)

            FF_groups[b_g_key] = [(base_id, index)]

        #Case with already existing backup
        #Need to add a new FF group to the switch
        else:
            b_group = []

            for i in range(0, index+1):
                p,t,drop = base_group[i]
                b_group.append((p,t,True))            
            
            b_group.append((backup_port, tag, False))

            g_id = self._add_group(switch_id, self._parse_buckets_list(in_port, b_group, dp))

            buckets[g_id] = b_group

            first_bucket = b_group[0]
            f_port = first_bucket[0]
            f_tag = first_bucket[1]
            f_g_key = self._get_FF_key(f_port, 
                        self._get_key(True, dst_address, src_address, f_tag, prev_switch_id))

            FF_groups[f_g_key].append((g_id, 0))
            FF_groups[b_g_key] = [(g_id, index+1)]

            self.add_flow(switch_id, dst_address, [], True, src_address, f_tag, True, prev_switch_id)

        self.log('Added backup for ' + str(dst) + ' to switch ' + str(switch_id))
        self.log('From tag ' + str(tag_origin) + ' to tag ' + str(tag))
        
    def remove_backup(self, prev_switch_id, switch_id, dst_address, dst, backup_dst, src_address, 
                    tag, in_port_flow = False):
        """Remove backup for dst in switch_id.
        
        Arguments:
        prev_switch_id: if of previous switch on packet path
        switch_id: id of switch to remove backup from
        dst_address: IP group address
        dst: dst to remove backup for
        backup_dst: backup output destination
        src_address: IP address of packet source
        tag: backup tag
        in_port_flow: True if in_port (previous switch) was matched to, False otherwise"""
                    
        dp = self.network.node[switch_id]['switch'].dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        if prev_switch_id is None:
            in_port = 0
        else:
            in_port = self.network[prev_switch_id][switch_id]['dst_port']

        if not in_port_flow:
            prev_switch_id = None

        key_backup = self._get_key(True, dst_address, src_address, tag, prev_switch_id)
        port = self.network[switch_id][dst]['src_port']

        backup_port = self.network[switch_id][backup_dst]['src_port']

        FF_groups = self.network.node[switch_id]['FF_groups']

        self.log('Removing backup ' + str(backup_dst) + ' for ' + str(dst) + ' in switch ' + str(switch_id))

        b_g_key = self._get_FF_key(backup_port, key_backup)

        if b_g_key not in FF_groups:
            self.log('FAILED: backup not installed')
            return

        buckets = self.network.node[switch_id]['buckets']

        base_id,index = FF_groups[b_g_key][0]
        base_group = buckets[base_id]

        first_bucket = base_group[0]
        f_port = first_bucket[0]
        f_tag = first_bucket[1]

        rem_groups = []

        #Case with no existing backup for backup
        #So no copies exist
        if len(base_group) == index+1:
            rem_groups.append(base_id)

        #Add all copies to removal list
        else:
            f_g_key = self._get_FF_key(f_port, self._get_key(True, dst_address, src_address, 
                                    f_tag, prev_switch_id))

            for g_id,index in FF_groups[f_g_key]:
                bucket = buckets[g_id][index]
                if (bucket[0] == backup_port or (isinstance(bucket[0], list) and backup_port in bucket[0])) and bucket[1] == tag:
                    rem_groups.append(g_id)

        removed_group = False
        for g_id in rem_groups:
            group = buckets[g_id]
            if index == 0 or group[index-1][2]:
                #can just be removed
                self._remove_FF_group(switch_id, g_id, dst_address, src_address, prev_switch_id)
                removed_group = True
            else:
                if isinstance(group[index], list):
                    group[index].remove(backup_port)
                    cmd = parser.OFPGroupMod(dp, ofp.OFPGC_MODIFY, ofp.OFPGT_FF, g_id, 
                                            self._parse_buckets_list(in_port, group, dp))
                    dp.send_msg(cmd)
                else:
                    for i in range(index,len(group)):
                        p,t,d = group[i]
                        if not d:
                            g_k = self._get_FF_key(p, 
                                    self._get_key(True, dst_address, src_address, t, prev_switch_id))
                            del FF_groups[g_k]
                    buckets[g_id] = group[0:index]
                    cmd = parser.OFPGroupMod(dp, ofp.OFPGC_MODIFY, ofp.OFPGT_FF, g_id, self._parse_buckets_list(in_port, buckets[g_id], dp))
                    dp.send_msg(cmd)

        if removed_group:
            self.add_flow(switch_id, dst_address, [], True, src_address, f_tag, True, prev_switch_id)

        self.log('Removed backup ' + str(backup_dst) + ' for ' + str(dst) + ' in switch ' + str(switch_id))

    #This function gets triggered before the topology controller flows are added
    #But late enough to be able to remove flows 
    @set_ev_cls(ofp_event.EventOFPStateChange, [CONFIG_DISPATCHER])
    def state_change_handler(self, ev):        
        dp = ev.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser        
        
        #Delete any possible currently existing flows.
        del_flows = parser.OFPFlowMod(dp, table_id=ofp.OFPTT_ALL, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, command=ofp.OFPFC_DELETE) 
        dp.send_msg(del_flows)
        
        #Delete any possible currently exising groups
        del_groups = parser.OFPGroupMod(datapath=dp, command=ofp.OFPGC_DELETE, group_id=ofp.OFPG_ALL)
        dp.send_msg(del_groups)
        
        #Make sure deletion is finished using a barrier before additional flows are added
        barrier_req = parser.OFPBarrierRequest(dp)
        dp.send_msg(barrier_req)

    #Switch connected
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        #Add default flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        instr = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        cmd = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=instr)
        dp.send_msg(cmd)

    #Topology Events
    @set_ev_cls(event.EventSwitchEnter)
    def switchEnter(self,ev):
        switch = ev.switch

        self.network.add_node(switch.dp.id, switch = switch, flows= {}, FF_groups = {}, buckets = {}, group_id_index = 1, host = False)
        self.log('Added switch ' + str(switch.dp.id))

    @set_ev_cls(event.EventSwitchLeave)
    def switchLeave(self,ev):
        switch = ev.switch
        sid = switch.dp.id

        if sid in self.network:
            for node in self.network.predecessors(sid):
                self.network[node][sid]['live'] = False
            for node in self.network.successors(sid):
                self.network[sid][node]['live'] = False
            
            self.builder.repair(self.network.edges(sid))
                
            self.log('Removed switch ' + str(sid))

    @set_ev_cls(event.EventLinkAdd)
    def linkAdd(self,ev):
        link = ev.link
        src = link.src.dpid
        dst = link.dst.dpid

        self.network.add_edge(src, dst, src_port = link.src.port_no, dst_port = link.dst.port_no, live = True)
        self.log('Added link from ' + str(src) + ' to ' + str(dst))

    @set_ev_cls(event.EventLinkDelete)
    def linkDelete(self,ev):
        link = ev.link
        src = link.src.dpid
        dst = link.dst.dpid

        if (src,dst) in self.network.edges():
            self.network[src][dst]['live'] = False

            self.builder.repair([(src, dst)])

            self.log('Removed link from ' + str(src) + ' to ' + str(dst))

    @set_ev_cls(event.EventHostAdd)
    def hostFound(self,ev):
        host = ev.host
        switch = host.port.dpid
        mac = host.mac

        self._hostFound(switch, host.port.port_no, mac)

    def _hostFound(self, switch_id, port, mac):
        if mac not in self.network:
            self.network.add_node(mac, host = True)
            self.network.add_edge(mac, switch_id, src_port = -1, dst_port = port, live = True)
            self.network.add_edge(switch_id, mac, src_port = port, dst_port = -1, live = True)
            self.log('Added host ' + mac + ' at switch ' + str(switch_id))

    #Packet received
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        pkt = packet.Packet(msg.data)        
        eth = pkt[0]
        
        if eth.protocol_name != 'ethernet':
            #Ignore non-ethernet packets
            self.processOther(dp,msg,pkt)
            return
        
        #Don't do anything with LLDP, not even logging
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.log('Received ethernet packet')
        src = eth.src
        dst = eth.dst
        self.log('From ' + src + ' to ' + dst)

        if src not in self.network:
            self._hostFound(dp.id, msg.match['in_port'], src)

        if (self.isMulticast(dst)):
            self.processMulticast(dp,msg,pkt)
            
        #Do not process unicast packets
        else:
            return

    def processMulticast(self,dp,msg,pkt):
        """Process multicast and broadcast messages"""
        eth = pkt[0]
        dst = eth.dst

        #We only support IPV4 multicast
        if (eth.ethertype == ether_types.ETH_TYPE_IP and dst != 'ff:ff:ff:ff:ff:ff'):
            self.processIPMulticast(dp,msg,pkt)
        
        #Only process IPV4 multicast packets
        else:
            return

    def processIPMulticast(self,dp,msg,pkt):
        self.log('IPV4 Multicast Message')
        eth = pkt[0]
        ip = pkt[1]      

        if ip.protocol_name != 'ipv4':
            self.log('Expected ipv4, but got ' + ip.protocol_name)
            return

        #IGMP message
        if ip.proto == in_proto.IPPROTO_IGMP:
            igmp_msg = pkt[2]
            self.processIGMP(eth.src, ip.src, igmp_msg)
            return
            
        #TODO:Check if this really is a multicast IP packet before creating a new group
        #Create new group   
        if ip.dst not in self.groups:
            self.groups[ip.dst] = set()

            self.ip_2_mac[ip.dst] = eth.dst
        
        if ip.src not in self.groups[ip.dst]:
            self.builder.create_group(ip.dst, ip.src, dp.id)
            self.groups[ip.dst].add(ip.src)

            self.ip_2_mac[ip.src] = eth.src

            #Setup a flow to destroy all mesages from this group + src
            ofp = dp.ofproto
            parser = dp.ofproto_parser
            actions = []
            match = parser.OFPMatch(eth_dst=eth.dst, eth_src=eth.src)
            instr = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            cmd = parser.OFPFlowMod(
                datapath=dp, priority=self.LOWPRIO, match=match, instructions=instr)
            dp.send_msg(cmd)

    #TODO: Support all types of IGMPV3 messages,
    #instead of just INCLUDE and EXCLUDE messages
    def processIGMP(self, eth_src, ip_src, igmp_msg):
        #Only support IGMPV3
        if igmp_msg.protocol_name == 'igmpv3_report':
            records = igmp_msg.records
            for record in records:
                address = record.address
                self.log('Record change for group ' + address)
                if address in self.groups:
                    group = self.groups[address]
                    if record.type_ == igmp.CHANGE_TO_INCLUDE_MODE:
                        for src_ip in it.ifilter(lambda ip: ip != ip_src, group):
                            if src_ip in record.srcs:
                                self.builder.add_subscriber(address, src_ip, eth_src)
                            else:                       
                                self.builder.remove_subscriber(address, src_ip, eth_src)
                    elif record.type_ == igmp.CHANGE_TO_EXCLUDE_MODE:
                        for src_ip in it.ifilter(lambda ip: ip != ip_src, group):
                            if src_ip in record.srcs:
                                self.builder.remove_subscriber(address, src_ip, eth_src)
                            else:                       
                                self.builder.add_subscriber(address, src_ip, eth_src)
                else:
                    self.log('Group does not exit (yet)')
                    

        else:
            self.log('Only supporting IGMPV3')
    

    def isMulticast(self, dst):
        return (dst[0:2] == '01' or dst[0:5] == '33:33' or dst == 'ff:ff:ff:ff:ff:ff')

    def processOther(self,dp,msg,pkt):
        self.log('Ignoring the following packet: ')
        for p in pkt.protocols:
            self.log(str(p))    

