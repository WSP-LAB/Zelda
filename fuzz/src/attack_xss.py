from os.path import join as path_join
import src.attack_utils as autil

# from src.http_executor import ExecutePUTbyRequest
from src.web_input import WebInput
from configparser import ConfigParser
from bs4 import BeautifulSoup as bs
import random
PAYLOADS_FILE = path_join("../fuzz/data", "xssPayloads.ini")

class AttackXSS():
    def __init__(self, target_pool, session, vul_logger, http_executor):
        self.target_pool = target_pool
        self.session = session
        self.vul_logger = vul_logger
        self.http_executor = http_executor

    def Run(self):
        print("XSS Attack starts")
        vul_detected = False
        try_parameters = []
        for target in self.target_pool.GetListXSS():
            
            # get the first attempt result
            #if vul_detected:
            #    break
            #print(target.web_input.DecodeAsSessionParams(self.target_pool.GetRootURL()))
            
            original_params = target.web_input.DecodeAsSessionParams()
            print("Attack Params:"+ str(original_params) + str(target.detected_idx))
            #headers, response = ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session, original_params, target.method)

            # injected taint 
            
            for target_index in target.detected_idx:
                #print(target_index)
                if not target_index in try_parameters:
                    
                    number_flag = str(random.randint(5000, 10000))
                    taint = list(original_params.values())[target_index]
                    taint_params = autil.injectPayload(original_params, taint, target_index, number_flag)
                    
                    result_headers, taint_response = self.http_executor.ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session, taint_params,target.method, target_index, self.vul_logger)
                    
                    #print(result_headers)
                    
                    # generate new list of xss payloads
                    generated_payloads = autil.generate_payloads(taint_response, taint, PAYLOADS_FILE)
                    #print(generated_payloads)
                    for (payload, flag) in generated_payloads:
                        attack_params = autil.injectPayload(original_params, payload, target_index, number_flag)
                        #print(attack_params)
                        result_headers, result_response = self.http_executor.ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session, attack_params, target.method, target_index, self.vul_logger)
                        
                        vul_detection = self.OracleXSS(result_response, flag, taint, number_flag)
                        #print(result_response)
                        if vul_detection:
                            try_parameters.append(target_index)
                            self.vul_logger.LogVul("xss", "reflected", self.target_pool.GetRootURL(), str(list(original_params)[target_index]), str(payload) + " " +  str (attack_params))
                            print("vulnerability detected: " + str(list(original_params)[target_index]) + ", payload: " + str(payload))
                            vul_detected = True
                            break

        return vul_detected

    def OracleXSS(self, response, flags, taint, number_flag):
        config_reader = ConfigParser(interpolation=None)
        with open(path_join("../fuzz/data", "xssPayloads.ini"), encoding='utf-8') as payload_file:
            config_reader.read_file(payload_file)

        for section in config_reader.sections():
            
            if section == flags.section:
                #print(section)
                #print(flags.section)
                expected_value = config_reader[section]["value"].replace('[EXTERNAL_ENDPOINT]', "http://wapiti3.ovh/")
                expected_value = expected_value.replace("[PROTO_ENDPOINT]", "wapiti3.ovh/")
                expected_value = expected_value.replace("[TAINT]", str(number_flag))
                expected_value = expected_value.replace("__XSS__", taint)
                tag_names = config_reader[section]["tag"].split(",")
                attribute = config_reader[section]["attribute"]
                case_sensitive = config_reader[section].getboolean("case_sensitive")
                match_type = config_reader[section].get("match_type", "exact")

                attribute_constraint = {attribute: True} if attribute not in ["full_string", "string"] else {}
                soup = bs(response, "html.parser")
                for tag in soup.find_all(tag_names, attrs=attribute_constraint):
                    non_exec_parent = autil.find_non_exec_parent(tag)
                    #print(tag)
                    if non_exec_parent and not (tag.name == "frame" and non_exec_parent == "frameset"):
                        continue

                    if attribute == "string" and tag.string:
                        if case_sensitive:
                            if expected_value in tag.string:
                                return True
                        else:
                            if expected_value.lower() in tag.string.lower():
                                return True
                    elif attribute == "full_string" and tag.string:
                        if autil.compare(tag.string.strip(), expected_value, match_type, case_sensitive):
                            return True
                    else:
                        # Found attribute specified in .ini file in attributes of the HTML tag
                        if attribute in tag.attrs:
                            if autil.compare(tag[attribute], expected_value, match_type, case_sensitive):
                                return True

                break

        return False