"""
    A Node_list is responsible for inserting new nodes, bookkeeping for the visited links (for the crawler),
    and retrieving the most favorable node.

    A node should be retrieved and added here
    only through its methods (get_next_request(), add) in order to preserve the ordering
"""

import heapq

from typing         import Dict, List, Set, Optional, Callable, Iterator, Any,  Tuple
from enum import Enum
import random
import json

from multiprocessing import Value, Lock

Label = int
class ExtendedEnum(Enum):
    def __str__(self):
        return str(self.name)
    def __repr__(self):
        return self.__str__()
    def __lt__(self, obj):
        return self.value < obj.value
    
class Policy(ExtendedEnum):
    NODE = 0
    EDGE = 1
    NODE_EDGE = 2

class webFuzzCoverage:
    """
        Constructs a heap tree of nodes plus a bunch of other data structures
        The heap tree (self._node_list) is semi-ordered in descending order of 
        favorableness. self._node_list[0] is the currently most favorable node

        :param crawler_unseen: links that have never been called yet
        :type crawler_unseen: Set of Nodes
        :return: The NodeList object
        :rtype: NodeList
    """
    def __init__(self, meta_file):
        self.lock = Lock()
        meta_json = json.loads(open(meta_file).read())
        self.basic_blocks = int(meta_json['basic-block-count'])

        self.policy = Policy.NODE
        self.node_list: List[Node] = []
        self._total_cfg_xor: Dict[Label, List[Optional[Node]]] = {}
        self._total_cfg_single: Dict[Label, List[Optional[Node]]] = {}

    def parse_headers(self,raw_headers) -> Iterator[Tuple[Label, str]]:
        relevant_headers = filter(lambda h: h[0].startswith("I-"), raw_headers.items())
        header_dict = {}
        for name, value in relevant_headers:
            header_dict[int(name[2:])]=value
        return header_dict

    @property
    def total_cover_score(self):
        
        total_cfg = self._total_cfg_single
        total_count = self.basic_blocks

        return 100*len(total_cfg) / total_count

    
    """
        Add node to the total cfg map

        A new node is accepted only if any of the conditions hold:
            1) has visited a label-bucket that we have not seen before
            2) it visited a label-bucket in which we have seen the past,
               but the node that visited that label is heavier than this
               new node (in terms of response time and size, see Node.isLighterThan)
        
        :param new_node: the node to add
        :type new_node: Node
        :param local_cfg: the xor-CFG of the node
        :type local_cfg: CFG
    """
    def _add_node_to_total_cfg(self, local_cfg):
        # similar to AFL, the global map (self._total_cfg) 
        # stores for each bucket in each label we have seen
        # the lightest node that can reach it
        
        # strictly all nodes in the heap tree (self._node_list) exist
        # also in the global map. If a node loses its references
        # in the global map, then it gets removed from the heap too.
        #self.lock.acquire()
        if self.policy == Policy.NODE:
            total_cfg = self._total_cfg_single
        else:
            total_cfg = self._total_cfg_xor
        
        
        for label, bucket in local_cfg.items():
            
            if label not in total_cfg:
                
                
                total_cfg[label] = ""
                
                continue
            #print(len(total_cfg))

        #self.lock.release()
            

            

        

    """
        Add new node to the heap tree and to the global CFG map.

        :param new_node: the node to add
        :type new_node: Node
        :param node_cfg: the CFGs observed for this node
        :type node_cfg: CFGTuple
        :return: if the node has been accepted
        :rtype: bool
    """
    def add(self, headers):
        #print(headers)
        cfg = self.parse_headers(headers)
        #print(cfg)
        
        if self.policy == Policy.NODE:
            self._add_node_to_total_cfg(cfg)
        else:
            self._add_node_to_total_cfg(cfg)

        

 