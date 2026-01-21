# -*- coding: utf-8 -*- 
import multiprocessing 
from src.priority_queue import MaxHeap
from multiprocessing.managers import SyncManager, BaseManager
from multiprocessing import Lock
from copy import deepcopy
from math import sqrt, log2
import random
    
class Seed:
    def __init__(self, initial_input, coverage, distance, mode, detected):
        # Value is WebInput class
        self.current_value = initial_input
        self.mutated_value = None
        self.num_detected = detected
        self.num_selected = 0
        self.energy = 2
        self.score = 0
        self.mode = mode
        self.max_coverage = coverage
        self.min_distance = distance
        self.CalculateEnergy()
        
        self.hash_value = hash(self.current_value.Decode(self.current_value._input_bytes))

    def __gt__(self, seed):
        return self.score > seed.score

    def CalculateScore(self, total_num, max_distance, min_distance):
        #TODO
        
        # hyperparameter for exploration
        ucb_e = 3
         
    
        
        exploration = ucb_e * sqrt(log2(total_num)/(self.num_selected + 1))  
        exploitation  = 0
        
        self.score = exploration 
        
        #self.score = exploration + exploitation
        
    
    def CalculateEnergy(self):
        #TODO  
        if self.energy == 0:
            self.energy = 2
        else:
            self.energy = 2 ** self.num_selected

class SeedPool:
    def __init__(self, initial_input, initial_coverage, initial_distance, mode):
        self.mode = mode
        self.lock = Lock()
        self._shared_queue = MaxHeap()
        self.total_try = 1
        self.max_coverage = initial_coverage
        self.min_distance = 100
        self.max_distance = 0
        self.target_detected = False
        # Add initial seed
        self.lock.acquire()
        seed = Seed(initial_input, initial_coverage, initial_distance, self.mode, False)
        seed.CalculateScore(self.total_try, self.max_distance, self.min_distance)
        # push to prioirty queue
        # heap queue is min-priority queue, we use -score
        self._shared_queue.insert(seed)
        self.lock.release()

    def TargetDetected(self):
        return self.target_detected

    def AddNewSeed(self, input, coverage, distance, detected):
        self.lock.acquire()
        # Create new seed
        new_input = deepcopy(input)
        if distance > self.max_distance:
            self.max_distance = distance
        seed = Seed(input, coverage, distance, self.mode, detected)
        seed.CalculateScore(self.total_try, self.max_distance, self.min_distance)
        # push to prioirty queue
        # heap queue is min-priority queue, we use -score
        self._shared_queue.insert(seed)
        self.lock.release()

    def AddInitialSeeds(self, initial_input):
        # first seed is added when seed pool is created
        initial_coverage = 0
        initial_distance = -1 
        #length = len(initial_input._input_dict)

        for i in range(9):
            new_input = deepcopy(initial_input)
            new_input_list_1 = new_input.DecodeAsList() 
            new_input_list = [x.replace('\00', '') for x in  new_input_list_1 ]
            param_names = list(initial_input._input_dict.keys())
            #print(param_names)
            for j in range(len(initial_input._input_dict)):
                if param_names[j] not in ["ownurl", "ownreferer", "owncookie", "ownuseragent"]:
                    if new_input_list[j] == "" and random.random() < 0.5:
                        #print (j)
                        #new_input.Mutation(j)
                        new_input.CreateFlag(j)
                #elif random.random() > 0.5:
                #    new_input.CreateFlag(j)
            #print( [x.replace('\00', '') for x in  new_input.DecodeAsList()])
            #print("\n")
            self.lock.acquire()
            seed = Seed(new_input, initial_coverage, initial_distance, self.mode, False)
            seed.CalculateScore(self.total_try, self.max_distance, self.min_distance)
            # push to prioirty queue
            # heap queue is min-priority queue, we use -score
            self._shared_queue.insert(seed)
            self.lock.release()

    def Reset(self, initial_input):
        # Clear all seeds
        self._shared_list = MaxHeap()
        # Append initial seed
        initial_seed = Seed(initial_input,0,-1,self.mode)
        self._shared_list.insert(initial_seed)
    

    def ReturnMaxScoreSeed(self):
        # Seed Pool is already sorted 
        self.total_try += 1
        
        if self.mode == "random" :
            random_idx = random.randrange(0,self._shared_queue.length())
            max_seed =  deepcopy(self._shared_queue.get(random_idx))
            self._shared_queue.get(random_idx).CalculateScore(self.total_try, self.max_distance, self.min_distance)
        else:
            self._shared_queue.Max().num_selected += 1
            max_seed = deepcopy(self._shared_queue.Max())

            self._shared_queue.Max().CalculateScore(self.total_try, self.max_distance, self.min_distance)
        self._shared_queue.Max().CalculateEnergy()

        # sort the heap
        self.lock.acquire()
        self.UpdateQueue()
        self._shared_queue.maxHeapify(0)
        self.lock.release()
        return max_seed
    
    def UpdateQueue(self):
        for i in range(0, self._shared_queue.length()):
            self._shared_queue.get(i).CalculateScore(self.total_try, self.max_distance, self.min_distance)
            
            
    def CheckUpdate(self, new_coverage, new_distance, detected):
        update = False
        self.lock.acquire()
        if detected:
            self.target_detected = True
            update = True
        if self.max_coverage < new_coverage:
            self.max_coverage = new_coverage
            update = True
        elif self.min_distance > new_distance and new_distance != -1:
            self.min_distance = new_distance 
            update = True
        self.lock.release()
        return update

        



