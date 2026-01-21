from multiprocessing import Lock
from math import sqrt, log2
from configparser import ConfigParser 
config = ConfigParser() 
config.read('../config.ini')

class ParameterHistory():
    def __init__(self, importance, mode):

        self.mode = mode
        self.selection = 0 
        self.updates = 0 
        self.importance = importance
        self.changes = 0
        self.score = 0
        self.UpdateScore(0)
    
    def UpdateScore(self, total_selection):

        if self.mode == "final":
            ucb_1 = 1
            ucb_2 = 0.6
            ucb_3 = 0.1
        
        ucb_1 = float(config['fuzzer']['exploration'])
        ucb_2 = float(config['fuzzer']['importance'])
        ucb_3 = float(config['fuzzer']['content_change'])
        
        #print(sqrt(log2(total_selection + 1)/(self.selection + 1)))
        exploration = ucb_1 * sqrt(log2(total_selection + 1)/(self.selection + 1))
        #exploration = (1 / (self.selection + 1)) 
        exploitation = ucb_2 * self.importance + ucb_3 * self.changes 
        self.score = exploration + exploitation
    
    def __gt__(self, param):
        return self.score > param.score

class ParameterHistoryList():
    def __init__(self, length, initial_response, initial_headers, params, mode):
        self.mode = mode
        self.param_names = [x.replace("GET-", "") for x in list(params.keys())]
        self.detected_list = []
        self.history_list = []
        self.lock = Lock()
        #print(list(params.keys()))
        self.importances = self.CalculateImportance(initial_response, self.param_names )
        #print(self.importances)
        for i in range(length):
            #print(i)
            self.AddHistory(self.importances[i])
        self.number_of_total_selection = 0
    
    def CalculateImportance(self, response, param_names):
        # count the number of existence 
        initial_importance = []
        print(param_names)
        for param in param_names:
            if param == "ownurl":
                param = "url"
            if param == "ownreferer":
                param = "referer"
            if param == "owncookie":
                param = "cookie"
            if param == "ownuseragent":
                param = "useragent"
            initial_importance.append(response.count(param))
        print(initial_importance)
        max_count = max(initial_importance)
        min_count = min(initial_importance)

        importances = []
        if max_count - min_count != 0:
            importances = [ ((x - min_count) / (max_count - min_count)) for x in initial_importance]
        else:
            importances = [0 for x in initial_importance]
        return importances

    def NumberOfDetected(self):
        return len(self.detected_list)

    def UpdateDetectedList(self, new_list):
        self.lock.acquire() 
        for elem in new_list:
            if not elem in self.detected_list:
                self.detected_list.append(elem)
        self.lock.release() 

    def AddHistory(self, importance):
        self.lock.acquire()
        self.history_list.append(ParameterHistory(importance, self.mode))
        self.lock.release()
        
    def PrintScore(self):
        lengths = []
        for param in self.history_list:
            lengths.append(param.selection)
        print(lengths)

    def ReturnMaxParamter(self):
  
        idx = 0
        max_param = 0
        self.lock.acquire()
        for param in self.history_list:
         
            if self.history_list[max_param] < param and not idx in self.detected_list:
                max_param = idx
            idx += 1
        self.lock.release()
  
        return max_param
    
    def UpdateParameter(self, idx, updated, changes):
    
        self.lock.acquire()
 
        self.history_list[idx].selection += 1
        #print(self.history_list[idx].selection)
        self.number_of_total_selection += 1
        if updated:
            self.history_list[idx].updates += 1 
        if changes > self.history_list[idx].changes:
            self.history_list[idx].changes = changes 

        for i in range(0, len(self.history_list)):
            self.history_list[i].UpdateScore(self.number_of_total_selection)
            #print(self.history_list[i].score)
        self.lock.release()
    
    def ReturnRandomParam(self):
        import random
        history_len = len(self.history_list)
        #print(history_len)
        return random.randint(0, history_len - 1)