# -*- coding: utf-8 -*- 

import multiprocessing
import os
from platform import platform
import random
import re
import sys
import threading
import time
import numpy as np
from multiprocessing import Pool, Lock
from copy import deepcopy
from subprocess import Popen
from subprocess import PIPE
import multiprocessing as mp

from multiprocessing import Process
from multiprocessing import Semaphore
from multiprocessing import Value
from multiprocessing.managers import BaseManager
from src.target_pool import TargetPool
from struct import *
import requests
import src.utils as utils
from src.throughput_counter import ThroughputCounter
from src.header_analyzer import HeaderAnalyzer
from src.response_analyzer import ResponseAnalyzer
from src.web_input import WebInput
from src.seed import Seed, SeedPool
from src.logger import Logger
from src.parameter_history import ParameterHistoryList, ParameterHistory
from configparser import ConfigParser 
import platform

config = ConfigParser() 
config.read('../config.ini')


def kill_proc(proc):
    if proc.poll() is None:
        proc.kill()

# error handling for Mac
if platform.system() == "Darwin":
    multiprocessing.set_start_method("fork")

_Detected = False

class WebFuzzer():

    def __init__(self, request_lock, request_list,  target_url, mode, login, method, session, vul_logger, timeout=5, seed_mode="init",http_executor=None):
        self._session = session
        """
        if login == "yes": 
            from src.http_executor import login 
            login(self._session)
        """
        self.request_lock = request_lock 
        self.request_list = request_list 

        self._log_path = './'
        self._eng_path = 'php'
        self._target_url = target_url
        self._mode = mode
        self.vul_logger = vul_logger
        self._root_url, self._params = self.ParseURL(target_url)
        # Assign an initial process pool of which size is 40
        self._pool_size = int(config['fuzzer']['process'])
        #self._process_pool = Pool(self._pool_size)
        self._semaphore = Semaphore(self._pool_size)
        self.header_analyzer = HeaderAnalyzer()
        self.response_analyzer = ResponseAnalyzer(self._root_url)
        self.timeout = timeout
        self.http_executor = http_executor
        self.seed_mode = seed_mode

        # Initialize logger 
        #self.logger = Logger(self._root_url, self._mode)
        # Paramter History list [# of selections, # of updates] * # of parameters
        self.start_time = 0
        self.method = method
        target_detected = False

    def UpdateProgress(self):
        pass

    def ParseURL(self, target_url):
        split_url = target_url.split("?")
        root_url = split_url[0]
        params = {}
        #param_dict = {'GET-act': (0, 'board'), 'GET-mid': (1, 'read'), 'GET-idx': (2, '1')}
        if len(split_url) > 1:
            param_list = split_url[1].split("&")
            idx = 0
            for param in param_list:
                if param.split("=")[0] != "":
                    # key is the name of parameter
                    key = "GET-" + param.split("=")[0]
                    # value is the tuple (idex of parameter, value)
                    try:
                        value = (idx, param.split("=")[1])
                    except:
                        value = (idx, "")
                    if key in list(params.keys()):
                        if "du-" + key not in list(params.keys()):
                            key = "du-" + key
                        else: key = "" 
                    if key != "":
                        params[key] = value
                        idx += 1
       
        return root_url, params

    def callback_func(self, result):
        print("callback_func got result :", result)

    def Fuzz(self, cov_logger, start_time):
        self.coverage_reporter = cov_logger
        # print("Let's start a fuzzing campaign")
        self.start_time = start_time
        fuzz_iteration = 0

        # Initialize shared memory for coverage checker
        #shared_coverage_checker = CoverageChecker()
        #shm = shared_coverage_checker.OpenNewMemory()


        # Initialize counters
        counter = ThroughputCounter()
        counter.StartTimer()

        # Initialize input
        #param_dict = {'GET-int': (0, '12'), 'GET-id': (1, '12')}
        param_dict = self._params
        # print(param_dict)
        wi = WebInput(param_dict)
        wi.Encode()
        
        # Initialize seed pool
        BaseManager.register("SeedPool", SeedPool)
        BaseManager.register("TargetPool", TargetPool)
        BaseManager.register("ParameterHistoryList", ParameterHistoryList)
        manager = BaseManager()
        manager.start()
        cov, dist, new_node, detected, detected_idx, vul_type, response, headers, content_length_changes = self.ExecuteRemotePUT(self._root_url,wi, -1)
        #if detected: 
        #    self.target_pool.AddTarget(wi, detected_idx, self.method, vul_type)
        #self.logger.LogCoverage(time.time()-self.start_time,cov)
        #self.logger.LogBasicBlock(time.time()-self.start_time, self.header_analyzer.covered_blocks)
        self.shared_seed_pool = manager.SeedPool(wi, cov, dist, self._mode)

        # Add initial seeds 
        mutated_value = deepcopy(wi)
        #if self.seed_mode == "init":
        self.shared_seed_pool.AddInitialSeeds(mutated_value)
        self.target_pool = manager.TargetPool(self._root_url)
        
        idx_list = [x for x in range(0, len(param_dict))]
        self.target_pool.AddTarget(wi,{"blind":idx_list}, self.method, "blind")

        self.parameter_history = manager.ParameterHistoryList(len(param_dict), response, headers, self._params, self._mode)

        #print("Time budget: " + str(len(param_dict)) + " sec\n\n\n")
        #self.timeout = time.time() + 15*(len(param_dict)) # 60 mins
        finish_time = time.time() + self.timeout
        # Finding Target
        while True :
            #print(time.time() - finish_time)
            if time.time() > finish_time:
                #print("break")
                break

            if self._semaphore.acquire():
                # Pick a seed from seed pool based on its fitness.
                p = Process(target=self.Execute, args=(
                    self._semaphore, counter, fuzz_iteration, finish_time))
                p.start()
                self._semaphore.release()
                
            else:
                self.shared_seed_pool.Sort()
                time.sleep(1)
            p.join()
            # Mutate the seed
            # Execute the mutated test
            # self.ExecutePUT("123")
            # Check the results
            # Determine whether to add the test into seed
            #if self.shared_seed_pool.TargetDetected() == True:
            #    break
            if self.parameter_history.NumberOfDetected() == len(param_dict):
                break
            
            
           

            if fuzz_iteration % 10 == 0:
                # print the progress window
                #utils.clear_line(5)
                # total length is 60
                """
                utils.clear_line(5)
                print('╭─ Fuzzing Progress ──────────────────────────────────────────╮')
                print('%-5s %-30s %-20.2f %5s' % ("|","Elapsed time (sec):", counter.GetElapsedTime(),"|"))
                print('%-5s %-30s %-20.2f %5s' % ("|",'Throughput (exec/sec):',counter.GetThroughput(),'|'))
                #print('%-5s %-30s %-20s %5s' % ("|", "Covered Blocks: ", self.header_analyzer.covered_blocks, "|"))
                print('%-5s %-30s %-20.2f %5s' % ("|", "Max Coverage: ", self.header_analyzer.max_coverage , "|"))
                print('╰─────────────────────────────────────────────────────────────╯')
                """
            #if fuzz_iteration % 50 == 0:
                #self.coverage_reporter.log_coverage(time.time() - self.start_time) 
                #self.logger.LogRequests(time.time()-self.start_time, counter.GetTotalCount())
            fuzz_iteration += 1
            
        
        
        time.sleep(2.0)
        #shm.close()
        #shm.unlink()
        #print("Fuzzing process done")
        # self._process_pool.close()
        # self._process_pool.join()
    
    def Execute(self, semaphore, counter, input, finish_time):
        # Initialize shared memory for coverage checker
        #shared_coverage_checker = CoverageChecker()
        #shm = shared_coverage_checker.OpenExistingMemory()
        
        target_url_prefix = self._root_url

        with semaphore:
            
            # If mode is "random" seed pool provides random seed. Or, seed pool provides max score seed
            seed = self.shared_seed_pool.ReturnMaxScoreSeed()

            c_proc = mp.current_process()
            #print("Running on Process",c_proc.name,"PID",c_proc.pid)
            # Compute the energy from a given seed.

            # Iterate the computed energy times.
            for i in range(seed.energy):
                if time.time() > finish_time:
                    #print("break")
                    break
                # Mutate the given seed
                import copy
                seed.mutated_value = copy.deepcopy(seed.current_value)
                prev_coverage = seed.max_coverage
                prev_distance = seed.min_distance
                
                if self._mode == "random" or self._mode == "appoarch1":
                    param_selection = self.parameter_history.ReturnRandomParam()
                else:
                    param_selection = self.parameter_history.ReturnMaxParamter()
                
                seed.mutated_value.Mutation(param_selection)

                # Execute the mutated seed
                cur_coverage, cur_distance, new_node, detected, detected_param_idx, vul_type, response, headers, content_length_changes = self.ExecuteRemotePUT(
                    target_url_prefix, seed.mutated_value, param_selection)
        
                """
                if shared_coverage_checker.CheckUpdate(cur_coverage):
                    print("Running on Process: ",
                          c_proc.name, ", PID:", c_proc.pid)
                    #print("! Current Coverage !", shared_coverage_checker.GetCurrentCoverage())
                    print('! Update Coverage !', cur_coverage, ", Given input:",
                          seed.mutated_value.DecodeAsSessionParams(target_url_prefix))
                    shared_coverage_checker.UpdateCoverage(cur_coverage)
                    #print("! After Coverage !", shared_coverage_checker.GetCurrentCoverage())
                """
                # if coverage increases
                updated = False
               
                
                if new_node:
                    #print("new_node!!!!!!!")
                    updated = True
                   
                    self.shared_seed_pool.AddNewSeed(seed.mutated_value, cur_coverage, cur_distance, 0)
                if detected: 
                    #if self._mode == "black":
                    self.target_pool.AddTarget(seed.mutated_value, detected_param_idx, self.method, vul_type)
                if content_length_changes > 0:
                    updated = True
                    if detected:    
                        self.shared_seed_pool.AddNewSeed(seed.mutated_value, cur_coverage, cur_distance, 1)
                      
                    else:
                        if self._mode != "black":
                     
                            self.shared_seed_pool.AddNewSeed(seed.mutated_value, cur_coverage, cur_distance, 0)
                elif random.random() < 0.1 and self.seed_mode == "random":
                    self.shared_seed_pool.AddNewSeed(seed.mutated_value, cur_coverage, cur_distance, 0)

                self.parameter_history.UpdateParameter(param_selection, updated, content_length_changes)
            seed.using = False
            # Update the throughput counter
            counter.AddCounter(seed.energy)
            #shm.close()

    def Attack(self):
        # Exploit the target vulnerability 
        from src.attack_xss import AttackXSS
        from src.attack_sqli import AttackSQLI
        from src.attack_cmi import AttackEXEC
        
        if AttackXSS(self.target_pool, self._session, self.vul_logger, self.http_executor).Run():
            pass
            #self.logger.LogCoverage(time.time()-self.start_time,100)
        
        AttackSQLI(self.target_pool, self._session, self.vul_logger, self.http_executor).Run()
        
        AttackSQLI(self.target_pool, self._session, self.vul_logger, self.http_executor).Blind()
      
        AttackEXEC(self.target_pool, self._session, self.vul_logger, self.http_executor).Run() 
        AttackEXEC(self.target_pool, self._session, self.vul_logger, self.http_executor).Blind()
       
    def CheckSinkDetected(self):
        return True

    def ReadCoverageBitmap(self, stdout):
        #matches = re.search("\[CovBitmap\]:([0-9]+)", stdout.decode('utf-8'))
        matches = re.search(
            "\[CovByteArray\]:([0-9a-z]+)", stdout.decode('utf-8'))
        if matches:
            bitmap = matches.group()[15:]
            int_list = []
            for b in bitmap:
                int_list.append(int(b, 16))
            return bytes(int_list)
        return None

    def ExecuteRemotePUT(self, target_url, web_input, param_selection):
        # from src.http_executor import ExecutePUTbyRequest

        final_params = web_input.DecodeAsSessionParams()
     
        
        headers, response = self.http_executor.ExecutePUTbyRequest(target_url, self._session, final_params, self.method, param_selection, self.vul_logger)
        target_detected = False

        self.response_analyzer.search_new_resources(response.replace(final_params['ownurl'],'').replace(final_params['ownreferer'],'').replace(final_params['ownreferer'],''), self.request_list, self.request_lock)

        if self._mode == "html":
            new_node = self.response_analyzer.LinesofCode(response)
            coverage = 0 
        else:
            new_node = self.header_analyzer.NewNodeCovered(headers)
            coverage = self.header_analyzer.CoverageCalcuation(headers)
            distance = self.header_analyzer.DistanceCalculation(headers)
            target_detected, vul_info = self.header_analyzer.CheckTarget(headers)
        
        # collect vulnerable candidates
        vul_type = ""
        detected_param_idx_total = {}
        target_detected_xss, detected_param_idx = self.response_analyzer.CheckXSS(response, web_input.DecodeAsList())
        target_detected_sqli = self.response_analyzer.CheckSQLI(response)
        target_detected_cmdi = self.response_analyzer.CheckCMDI(response)
        content_length_changes = self.response_analyzer.CheckContentLength(headers)
        if content_length_changes > 0:
            new_node = True 

        if target_detected_xss:

            target_detected = True
            detected_param_idx_total["xss"] = detected_param_idx
            vul_type += "xss"
        if target_detected_sqli:
           
            target_detected = True
            vul_type += "sqli"
            detected_param_idx_total["sqli"] = [param_selection]
        if target_detected_cmdi:
            target_detected = True 
            vul_type += "cmdi"  
            detected_param_idx_total["cmdi"] = [param_selection]
        # Blind sqli
        if target_detected and "sql" in vul_info and not target_detected_sqli:
            target_detected = True
            vul_type += "blind"
            detected_param_idx_total["blind"] = list(map(lambda x: x, range(0, len(final_params))))
        return coverage, distance, new_node, target_detected, detected_param_idx_total, vul_type, response, headers, content_length_changes

    def ExecutePUT(self, target, input):
        cmd = ['php'] + [target] + [str(input)]
        proc = Popen(cmd,
                     stdout=PIPE, stderr=PIPE)
        timer = threading.Timer(10.0, kill_proc, [proc])
        timer.start()
        stdout, stderr = proc.communicate()
        timer.cancel()

        c_proc = mp.current_process()
        #print('%d c_proc stdout' % c_proc.pid)
        # print(stdout)
        return self.ReadCoverageBitmap(stdout), 0
        #print('Return code: %d' % proc.returncode)

        # if proc.returncode in [-4, -11]:
        #log = [self._eng_path] + self._opt
        #log += [js_path, str(proc.returncode)]
        #log = str.encode(','.join(log) + '\n')
        # self._crash_log.write(log)
        #msg = 'Found a bug (%s)' % js_path
        #print('we have an error.')
        #print_msg(msg, 'INFO')
        # else:
        #  os.remove(input)


def run(request_lock, request_list, target_url, mode, login, method, session, vul_logger, cov_logger, start_time, timeout, seed_mode, http_executor):
    fuzzer = WebFuzzer(request_lock, request_list, target_url, mode, login, method, session, vul_logger, timeout,seed_mode, http_executor)
    fuzzer.Fuzz(cov_logger, start_time)
    fuzzer.Attack()
