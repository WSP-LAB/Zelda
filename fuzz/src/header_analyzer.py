class HeaderAnalyzer():
    def __init__(self):
        self.target_id = []
        self.covered_blocks = []
        self.max_coverage = 0

    def NewNodeCovered(self, headers):
        new_node = False
        for key in headers.keys():
            if "I-" in key:
                if not (key.replace("I-","") in self.covered_blocks): 
                    #print(key)
                    new_node = True 
                    break
        return new_node
                

    def CoverageCalcuation(self,headers):
        covered_block = 0

        total_blocks = 0
       
        for key in headers.keys():
            
            if "numBlock" in key:
                total_blocks += int(headers[key])
            if "I-" in key: 
                covered_block += 1
                self.covered_blocks.append(key.replace("I-",""))
        #print(covered_block)
        
        if total_blocks != 0:
            coverage = covered_block / total_blocks
        else: 
            coverage = -1
        
        if coverage > self.max_coverage:
            self.max_coverage = coverage
        
        #print(coverage)
        return coverage
    
    def DistanceCalculation(self, headers):
        min_distance = 100000000000000
  
        for block in self.covered_blocks:
            try:
                distance = float(headers["D-" + block])
                if distance != -1 and distance < min_distance:
                    min_distance = distance 
            except:
                pass
        

        return min_distance
    
    def CheckTarget(self, headers):
        self.target_id = []
        vul_info = ""
        for key in headers.keys(): 
            if "targetID" in key: 
                
                self.target_id += headers[key].replace("[","").replace("]","").replace('"',"").split(",")
        
        if "" in self.target_id:
            self.target_id.remove("")

        detected = False
        for id in self.target_id:
            #print(headers.keys())
            #print(("I-" + id.replace("xss", "").replace("sql", "")) + "111")
            # I-155264837325
            if  ("I-" + id.replace("xss", "").replace("sql", "")) in headers.keys():
                
                detected = True
                if "sql" in id:
                    vul_info += "sql"
                elif "xss" in id:
                    vul_info += "xss"
            #print(detected)
        #print(vul_info)
        return detected, vul_info

