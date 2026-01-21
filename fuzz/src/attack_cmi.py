from os.path import join as path_join
import src.attack_utils as autil


from src.web_input import WebInput
from configparser import ConfigParser
from bs4 import BeautifulSoup as bs
from src.attack_utils import Mutator, PayloadReader

import random

PAYLOADS_FILE_1 = path_join("../fuzz/data", "cmdi_normal.txt")
PAYLOADS_FILE_2 = path_join("../fuzz/data", "cmdi_time.txt")

def _find_pattern_in_response_exec(data, warned: bool):
    vuln_info = ""
    executed = 0
    if "eval()'d code</b> on line <b>" in data and not warned:
        vuln_info = "Warning eval()"
        warned = True
    if "PATH=" in data and "PWD=" in data:
        vuln_info = "Command execution"
        executed = True
    if "COMPUTERNAME=" in data and "Program" in data:
        vuln_info = "Command execution"
        executed = True
    if "w4p1t1_eval" in data or "1d97830e30da7214d3e121859cfa695f" in data:
        vuln_info = "PHP evaluation"
        executed = True
    if "Cannot execute a blank command in" in data and not warned:
        vuln_info = "Warning exec"
        warned = True
    if "sh: command substitution:" in data and not warned:
        vuln_info = "Warning exec"
        warned = True
    if "Fatal error</b>:  preg_replace" in data and not warned:
        vuln_info = "preg_replace injection"
        warned = True
    if "Warning: usort()" in data and not warned:
        vuln_info = "Warning usort()"
        warned = True
    if "Warning: preg_replace():" in data and not warned:
        vuln_info = "preg_replace injection"
        warned = True
    if "Warning: assert():" in data and not warned:
        vuln_info = "Warning assert"
        warned = True
    if "Failure evaluating code:" in data and not warned:
        vuln_info = "Evaluation warning"
        warned = True
    if "/bin/sh: 1: Syntax error:" in data and not warned:
        vuln_info = "Command execution"
        warned = True
    return vuln_info, executed, warned

class AttackEXEC():
    def __init__(self, target_pool, session, vul_logger, http_executor):
        self.target_pool = target_pool
        self.session = session
        self.vul_logger = vul_logger
        self.payload_reader = PayloadReader() 
        self.http_executor = http_executor

    def Run(self):
        print("Command Execution / Injection Attack starts")
        vul_detected = False
        try_parameters = []
        self.payloads = self.payload_reader.read_payloads(PAYLOADS_FILE_1)
        for target in self.target_pool.GetListCMDI():
            
            #z get the first attempt result
            #if vul_detected:
            #    break
            #print(target.web_input.DecodeAsSessionParams(self.target_pool.GetRootURL()))
            
            original_params = target.web_input.DecodeAsSessionParams()
            print("Attack Params:"+ str(original_params) + str(target.detected_idx))
            #headers, response = ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session, original_params, target.method)

            # injected taint 
            for target_index in target.detected_idx:
                if not target_index in try_parameters:
                    try_parameters.append(target_index)

                    for (payload, flag) in self.payloads:
                        attack_params = autil.injectPayload(original_params, payload, target_index)
                        
                        result_headers, result_response = self.http_executor.ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session, attack_params, target.method, target_index)
                        
                        vul_detection, vul_info = self.OracleEXEC(self.target_pool.GetRootURL(), result_response)
                        
                        if vul_detection:
                            self.vul_logger.LogVul("CMDI", vul_info, self.target_pool.GetRootURL(), str(list(original_params)[target_index]), str(payload))
                            print("vulnerability detected cmdi: " + str(list(original_params)[target_index]) + ", payload: " + str(payload))
                            vul_detected = True
                            self.target_pool.appendCMDI(target_index)
                            break

        return vul_detected

    def Blind(self):
        payloads = self.payload_reader.read_payloads(PAYLOADS_FILE_2)
        #print(payloads)
        for target in self.target_pool.GetListBlind():
            original_params = target.web_input.DecodeAsSessionParams()
            for target_index in target.detected_idx:
                if target_index not in self.target_pool.GetVulCMDi():
                    result_headers, result_response = self.http_executor.ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session,original_params, target.method, target_index,self.vul_logger)
                    if result_response == "Read timed out":
                        #print("here")
                        pass
                    else:
                        for (payload, flag) in payloads:
                            attack_params =autil.injectPayload(original_params, payload, target_index) 
                            #print(attack_params)
                            result_headers, result_response = self.http_executor.ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session,attack_params, target.method, target_index,self.vul_logger)
                            if flag.payload_type ==  autil.PayloadType.time:
                                if result_response == "Read timed out":
                                    result_headers, result_response = self.http_executor.ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session,attack_params, target.method, target_index,self.vul_logger)
                                    if result_response == "Read timed out":
                                        vul_info = "CMDI Injection"
                                        self.vul_logger.LogVul("Blind-CMDI", vul_info, self.target_pool.GetRootURL(), str(list(original_params)[target_index]), str(payload) + " " +  str (attack_params))
                                        print("vulnerability detected time cmdi: " + self.target_pool.GetRootURL() + str(attack_params))
                                        break
                            else: 
                                vul_detection, vul_info = self.OracleEXEC(self.target_pool.GetRootURL(), result_response)
                                if vul_detection:
                                    self.vul_logger.LogVul("CMDI", vul_info, self.target_pool.GetRootURL(), str(list(original_params)[target_index]), str(payload))
                                    print("vulnerability detected cmdi: " + str(list(original_params)[target_index]) + ", payload: " + str(payload))
                                    vul_detected = True
                                    self.target_pool.appendCMDI(target_index)
                                    break

    def OracleEXEC(self, page, response):
        warned = False
        saw_internal_error = False
        vuln_info, executed, warned = _find_pattern_in_response_exec(response, warned)
        if vuln_info:
            # An error message implies that a vulnerability may exists
            return True, vuln_info
        else:
            return False, ""
       

            
