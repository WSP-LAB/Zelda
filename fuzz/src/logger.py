from fileinput import filename
from multiprocessing import Value
import os 
import platform
import datetime
import csv 
import time 

class VunerabilityLogger():
    def __init__(self, root_url, mode, start_time, crawl_time):
        print("Init vul logger")
        if platform.system() == "Windows":
            print("windows")
            file_name_vul = "logs\'" +root_url.replace("http://","").split("/")[1] + "-vul-" + mode  
        else:
            if ":4000" in  root_url:
                file_name_vul = "logs/" + "nodegoat" + "-vul-" + mode  
                file_name_cov = "logs/" + "nodegoat" + "-vul-" + mode  
            elif ":1004" in root_url:
                file_name_vul = "logs/" + "dvna" + "-vul-" + mode  
                file_name_cov = "logs/" + "dvna" + "-vul-" + mode  
            elif ":1005" in root_url:
                file_name_vul = "logs/" + "juice" + "-vul-" + mode  
                file_name_cov = "logs/" + "juice" + "-vul-" + mode  
            elif ":1001" in root_url:
                file_name_vul = "logs/" + "wackopicko" + "-vul-" + mode  
                file_name_cov = "logs/" + "wackopicko" + "-vul-" + mode  
            elif ":1235" in root_url:
                file_name_vul = "logs/" + root_url.replace("http://","").split("/")[1] +"_inj" + "-vul-" + mode  
                file_name_cov = "logs/" + root_url.replace("http://","").split("/")[1] +"_inj" + "-vul-" + mode  
            else:
                file_name_vul = "logs/" + root_url.replace("http://","").split("/")[1] + "-vul-" + mode  
                file_name_cov = "logs/" + root_url.replace("http://","").split("/")[1] + "-vul-" + mode  
        file_ext = ".log"
        cov_ext = ".csv"
        uniq = 1
        output_path = file_name_vul + "-1" + file_ext
        cov_output_path = file_name_cov +  "-1" + cov_ext
        
        while os.path.exists(output_path):
            uniq += 1 
            output_path = "%s-%d%s" % (file_name_vul, uniq, file_ext)
            
        file_name_vul = "%s-%d%s" % (file_name_vul, uniq, file_ext)
        file_name_cov = "%s-%d%s" % (file_name_cov, uniq, cov_ext)

        self.log_vul = open(file_name_vul, "w")
        #self.log_cov = open(file_name_cov, "w")

        #self.log_cov_writer = csv.writer(self.log_cov)

        self.log_vul.write("target url: " + root_url + "\n")
        self.log_vul.flush()
        #self.lock = Lock() 
        self.num_req = Value('i', 0)
        self.start_time = start_time
        self.crawl_time = crawl_time

    def LogVul(self, vul_type, vul_info, url, parameter, payload):
        self.log_vul.write(str(int(time.time()- self.start_time)) + " " + vul_type + " " + vul_info + " " + url + " " + parameter + " " + payload + "\n")
        self.log_vul.flush()

    def LogTime(self, time):
        self.log_vul.write("Total time sec: " + str(time) +"\n")
        self.log_vul.write("Total time: " + str(datetime.timedelta(seconds=time)) +"\n")
        self.log_vul.flush()

    def CountRequest(self):
        with self.num_req.get_lock():
            self.num_req.value += 1
            #print(self.num_req.value)
            
    def LogRequest(self):
        self.log_vul.write("Total Request: " + str(self.num_req.value))
        self.log_vul.flush()

    def LogCoverage(self, current_time, coverage):
        self.log_cov_writer.writerow([int(time.time()- self.start_time), coverage])
        self.log_cov.flush() 

class Logger():
    def __init__(self, root_url, mode):
        if platform.system() == "Windows":
            print("windows")
            file_name_coverage = "logs\'" + root_url.split("/")[-1] + "-coverage-" + mode 
            file_name_block = "logs\'" + root_url.split("/")[-1] + "-block-" + mode 
            file_name_requests = "logs\'" + root_url.split("/")[-1] + "-request-" + mode 
        else:
            file_name_coverage = "logs/" + root_url.split("/")[-1] + "-coverage-" + mode 
            file_name_block = "logs/" + root_url.split("/")[-1] + "-block-" + mode 
            file_name_requests = "logs/" + root_url.split("/")[-1] + "-request-" + mode 
        file_ext = ".log"
        uniq = 1
        output_path = file_name_coverage + "-1" + file_ext

        while os.path.exists(output_path):
            uniq += 1 
            output_path = "%s-%d%s" % (file_name_coverage, uniq, file_ext)
            

        file_name_coverage = "%s-%d%s" % (file_name_coverage, uniq, file_ext)
        file_name_block = "%s-%d%s" % (file_name_block, uniq, file_ext)
        file_name_requests = "%s-%d%s" % (file_name_requests, uniq, file_ext)

        self.log_coverage = open(file_name_coverage, "w")
        self.log_block = open(file_name_block,"w")
        self.log_requests = open(file_name_requests, "w")

    def LogCoverage(self, time, coverage):
        self.log_coverage.write(str(time) + " " + str(coverage) + "\n")
        self.log_coverage.flush()

    def LogBasicBlock(self, time, covered_blocks):
        self.log_block.write(str(time) + " " + str(covered_blocks)  + "\n")
        self.log_block.flush()

    def LogRequests(self, time, num_req):
        self.log_requests.write(str(time) + " " + str(num_req)  + "\n")
        self.log_requests.flush()
