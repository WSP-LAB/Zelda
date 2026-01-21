from multiprocessing import Lock

class Target:
    def __init__(self, input, idx, method):
        self.web_input = input 
        self.detected_idx = idx
        self.method = method


class TargetPool:
    def __init__(self, root_url):
        self.root_url = root_url 
        self.target_list_xss = []
        self.target_list_sqli = []
        self.target_list_cmdi = []
        self.target_list_blind = []
        self.detected_idx_list_xss = []
        self.detected_idx_list_sqli = []
        self.detected_idx_list_cmdi = []
        self.detected_idx_list_blind = []
        self.vul_sqli = []
        self.vul_cmdi = []
        self.lock = Lock()

    def AddTarget(self, input, detected_idx, method, vul_type):
        #print("Try to add")
        #print(detected_idx)
        #print(vul_type)
        # reduce duplicates
        if "xss" in vul_type:
            for idx in detected_idx["xss"]:
                if idx not in self.detected_idx_list_xss:
                    print("Add Target xss: " + str(detected_idx["xss"])) 
                    new_target = Target(input, detected_idx["xss"], method)
                    self.lock.acquire()
                    self.target_list_xss.append(new_target)
                    self.detected_idx_list_xss += detected_idx["xss"]
                    self.lock.release()
        if "sqli" in vul_type:
            for idx in detected_idx["sqli"]:
                if idx not in self.detected_idx_list_sqli:
                    #print("Add Target sqli: " + str(detected_idx["sqli"])) 
                    new_target = Target(input, detected_idx["sqli"], method)
                    self.lock.acquire()
                    self.target_list_sqli.append(new_target)
                    self.detected_idx_list_sqli += detected_idx["sqli"]
                    self.lock.release()
        if "cmdi" in vul_type:
            for idx in detected_idx["cmdi"]:
                if idx not in self.detected_idx_list_cmdi:
                    #print("Add Target cmdi: " + str(detected_idx["cmdi"])) 
                    new_target = Target(input, detected_idx["cmdi"], method)
                    self.lock.acquire()
                    self.target_list_cmdi.append(new_target)
                    self.detected_idx_list_cmdi += detected_idx["cmdi"]
                    self.lock.release()

        if "blind" in vul_type:
            for idx in detected_idx["blind"]:
                if idx not in self.detected_idx_list_blind:
                    #print("Add Target blind: " + str(detected_idx["blind"])) 
                    new_target = Target(input, detected_idx["blind"], method)
                    self.lock.acquire()
                    self.target_list_blind.append(new_target)
                    self.detected_idx_list_blind += detected_idx["blind"]
                    self.lock.release()
    def GetRootURL(self):
        return self.root_url
        
    def GetListXSS(self):
        return self.target_list_xss
    
    def GetListSQLI(self):
        return self.target_list_sqli

    def GetListCMDI(self):
        return self.target_list_cmdi
    
    def GetListBlind(self):
        return self.target_list_blind
    
    def GetVulSQLi(self):
        return self.vul_sqli

    def GetVulCMDi(self):
        return self.vul_cmdi

    def appendCMDI(self, idx):
        self.vul_cmdi.append(idx)
    
    def appendSQLI(self, idx):
        self.vul_sqli.append(idx)