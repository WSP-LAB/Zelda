# -*- coding: utf-8 -*- 
import argparse
import os
import sys
from src.crawler_wrapper import CrawlerWrapper
from src.net.web import Request
from colorama import Fore, Back, Style
from itertools import chain
import time
import requests
from urllib.parse import urlparse
from seleniumrequests import Chrome
# from src.http_executor import login 
from src.logger import VunerabilityLogger
from src.webFuzz_coverage import webFuzzCoverage
from src.http_executor import HTTPExecutor, login
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By 
from selenium.webdriver.support.ui import WebDriverWait 
from selenium.webdriver.support import expected_conditions as EC 
from selenium.webdriver.chrome.service import Service
import asyncio 
from requests_html import HTMLSession
from os             import system
from multiprocessing import Process, Queue, Manager, Lock
from configparser import ConfigParser 

config = ConfigParser() 
config.read('../config.ini')

def clear(): 
    return system('clear')

def get_args():
  arg_parser = argparse.ArgumentParser()
  arg_parser.add_argument('--opt', required=False,
                          choices=['preprocess', 'fuzz'])
  arg_parser.add_argument('--config', required=False)
  arg_parser.add_argument('--url', required=True)
  arg_parser.add_argument('--login', required=True,choices=['yes','no', 'chrome'])
  return arg_parser.parse_args(sys.argv[1:])

def combine_url_params(url, params):
  result_url = url + "?"
  for param in params:
    result_url += (str(param[0]) + "=" + str(param[1]) + "&")
  return result_url

def equal_request(base_request, compare_request):
  if base_request.path != compare_request.path:
    return False 
  
  if base_request._method != compare_request._method:
    return False 
  
  if base_request._method == "GET":
    if len(base_request.get_params) != len(compare_request.get_params):
      return False 
    if len(base_request.get_params) == 0:
      return True
    if base_request.get_params[0][0] != compare_request.get_params[0][0]:
      return False 
  else: 
    if len(base_request.post_params) != len(compare_request.post_params):
      return False 
    if len(base_request.post_params) == 0:
      return True
    if base_request.post_params[0][0] != compare_request.post_params[0][0] or base_request.post_params[-1][0] != compare_request.post_params[-1][0]:
      return False 

  return True 

def pick_injection_url(request_list, visited_url):
  i = 0 
  while True: 
    pick_url = request_list[i]
    new_request_list = list(filter(lambda a: not equal_request(pick_url,a), request_list))
    for url in visited_url: 
      if equal_request(url, pick_url):
        i+=1 

  return pick_url, new_request_list

def valid_urls(request_list):
  # only php files
  new_request_list = list(filter(lambda a: a.path[-2:] != "js", request_list))
  new_request_list = list(filter(lambda a: a.path[-3:] != "ccs", new_request_list))
  new_request_list = list(filter(lambda a: a.path[-2:] != "html", new_request_list))
  new_request_list = list(filter(lambda a: "logout" not in a.path , new_request_list))
  #new_request_list = list(filter(lambda a: "sqli_1.php" in a.path , new_request_list))
  #if "wordpress" in new_request_list[0].path: 
  #  new_request_list = list(filter(lambda a: "iubenda" in a.path , new_request_list))
  new_request_list = list(filter(lambda a: a.get_params != [] or a.post_params !=[], new_request_list))

  #print(request_list[0].get_params)
  #new_request_list = list(filter(lambda a: "security_level" not in ''.join(a.get_params) and "security_level" not in ''.join(a.post_params), new_request_list))
  return new_request_list

def no_auth_crawl(request_lock, request_list, args, initial_session, vul_logger, driver): 
  print("no auth crawl start")
  root_url = append_trailing_slash(args.url)
  crawler = CrawlerWrapper(request_lock,request_list, root_url, initial_session, vul_logger, driver, "no")

  crawler.add_start_url(root_url)
  crawler.set_max_depth(40)
  crawler.set_max_files_per_dir(0)
  crawler.set_max_links_per_page(0)
  crawler.set_scan_force("normal")
  crawler.set_max_scan_time(0)

  # should be a setter
  crawler.verbosity(0)
  crawler.set_timeout(30.0)
  crawler.set_modules(None)

  crawler.set_verify_ssl(bool(0))
  
  attack_options = {
                "level": 1,
                "timeout": 6.0
            }

  crawler.set_attack_options(attack_options)
  # reset crawler 
  crawler.flush_attacks()
  crawler.flush_session()

  
  # crawling - no browser
  if crawler.has_scan_started():
      if crawler.have_attacks_started():
          pass
      else:
          print(("[*] Resuming scan from previous session, please wait"))
          crawler.browse()
  else:
      crawler.browse()
  
  # crawling - with browser 
  crawler = CrawlerWrapper(request_lock,request_list, root_url, initial_session, vul_logger, driver, "headless")

  crawler.add_start_url(root_url)
  crawler.set_max_depth(40)
  crawler.set_max_files_per_dir(0)
  crawler.set_max_links_per_page(0)
  crawler.set_scan_force("normal")
  crawler.set_max_scan_time(0)

  # should be a setter
  crawler.verbosity(0)
  crawler.set_timeout(30.0)
  crawler.set_modules(None)

  crawler.set_verify_ssl(bool(0))
  
  attack_options = {
                "level": 1,
                "timeout": 6.0
            }

  crawler.set_attack_options(attack_options)
  # reset crawler 
  crawler.flush_attacks()
  crawler.flush_session()

  
  # crawling
  if crawler.has_scan_started():
      if crawler.have_attacks_started():
          pass
      else:
          print(("[*] Resuming scan from previous session, please wait"))
          crawler.browse()
  else:
      crawler.browse()


  http_resources = crawler.persister.get_links() 
  forms = crawler.persister.get_forms() 

  injection_points_1 = chain(http_resources, forms)

def auth_crawl(request_lock, request_list, args, initial_session, vul_logger, driver): 
  print("auth crawl start")
  root_url = append_trailing_slash(args.url)
  login(initial_session, root_url, args.login, driver)
  # no login 
  crawler = CrawlerWrapper(request_lock,request_list, root_url, initial_session, vul_logger, driver, "no")

  crawler.add_start_url(root_url)
  crawler.set_max_depth(40)
  crawler.set_max_files_per_dir(0)
  crawler.set_max_links_per_page(0)
  crawler.set_scan_force("normal")
  crawler.set_max_scan_time(0)

  # should be a setter
  crawler.verbosity(0)
  crawler.set_timeout(30.0)
  crawler.set_modules(None)

  crawler.set_verify_ssl(bool(0))
  
  attack_options = {
                "level": 1,
                "timeout": 6.0
            }

  crawler.set_attack_options(attack_options)
  # reset crawler 
  crawler.flush_attacks()
  crawler.flush_session()

  
  # crawling
  if crawler.has_scan_started():
      if crawler.have_attacks_started():
          pass
      else:
          print(("[*] Resuming scan from previous session, please wait"))
          crawler.browse()
  else:
      crawler.browse()
  
  # print(Fore.YELLOW + ("[*] Wapiti found {0} URLs and forms during the scan").format(crawler.count_resources()) + Fore.RESET)
  # crawling - with browser 
  crawler = CrawlerWrapper(request_lock,request_list, root_url, initial_session, vul_logger, driver, "headless")

  crawler.add_start_url(root_url)
  crawler.set_max_depth(40)
  crawler.set_max_files_per_dir(0)
  crawler.set_max_links_per_page(0)
  crawler.set_scan_force("normal")
  crawler.set_max_scan_time(0)

  # should be a setter
  crawler.verbosity(0)
  crawler.set_timeout(30.0)
  crawler.set_modules(None)

  crawler.set_verify_ssl(bool(0))
  
  attack_options = {
                "level": 1,
                "timeout": 6.0
            }

  crawler.set_attack_options(attack_options)
  # reset crawler 
  crawler.flush_attacks()
  crawler.flush_session()

  
  # crawling
  if crawler.has_scan_started():
      if crawler.have_attacks_started():
          pass
      else:
          print(("[*] Resuming scan from previous session, please wait"))
          crawler.browse()
  else:
      crawler.browse()
  http_resources = crawler.persister.get_links() 
  forms = crawler.persister.get_forms() 

  injection_points_2 = chain(http_resources, forms)
  request_list = list(injection_points_2)


def exec_fuzz(request_lock, request_list, target_url, mode, login, method, session, vul_logger, cov_logger,  start_time, timeout, seed_mode, http_executor):
  from src.webfuzzer import run
  run(request_lock, request_list, target_url, mode, login, method, session, vul_logger, cov_logger,  start_time, timeout, seed_mode, http_executor) 

def append_trailing_slash(url):
    parsed = urlparse(url)
    path = parsed.path

    # URL path가 비어있으면 슬래시 추가
    if not path:
        return url + '/'

    # URL path가 파일 형태인지 디렉터리 형태인지 확인
    if '.' in os.path.basename(path):
        return url  # 파일 이름이므로 변경하지 않음
    else:
        # 이미 슬래시가 있으면 그대로 반환
        if url.endswith('/'):
            return url
        else:
            return url + '/'

def main():
  
  mode = "final"
  seed_mode = "random"
  # set stdout printer 
  printer = print
  printer_refresh = clear
  printer_flush = sys.stdout.flush

  args = get_args()
  config_path = args.config

  initial_session = requests.Session()
  
  root_url = append_trailing_slash(args.url)

  parsed_uri = urlparse(root_url)

  result = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)

  # Coverage collector
  coverage_reporter = None
  
  
  # Chrome driver setting - no auth
  options = webdriver.ChromeOptions()
  options.add_argument("--headless")
  options.add_argument('--no-sandbox')
  options.add_argument("--disable-web-security")
  options.add_argument("--disable-extensions")
  options.add_argument('--disable-dev-shm-usage')
  
  # Chrome driver file
  service = Service(executable_path=config['crawler']['chromedriver_path'])
  driver1 = Chrome(service=service, options=options)

 

  crawl_time = time.time()
  vul_logger = VunerabilityLogger(root_url, mode, crawl_time , 0)
  
  
  # multi-process 
  # Process1: No authentication crawl 
  # Process2: Athenticated Crawl 
  # Process3: Fuzzing
  # Shared resource: session, request_list 
  manager = Manager() 
  request_list = manager.list() 
  # add the first request 
  if "?" in root_url:
      params = []
      for param in root_url.split("?")[1].split('&'):
         try:
          params.append([param.split('=')[0],param.split('=')[1]])
         except: 
          params.append(['',''])
      request_list.append(
          Request(
             path=root_url.split("?")[0],
             get_params=params,
             post_params=[],
            file_params=[],
            encoding='utf-8',
            referer=root_url,
            enctype="application/x-www-form-urlencoded"
         )
      )
  
  else: 
     request_list.append(
          Request(
             path=root_url.split("?")[0],
             get_params=[["",""]],
             post_params=[],
            file_params=[],
            encoding='utf-8',
            referer=root_url,
            enctype="application/x-www-form-urlencoded"
         )
     )
    

  request_lock = Lock() 
  
  initial_session_1 = requests.Session()
  process1 = Process(target=no_auth_crawl, args=(request_lock, request_list, args, initial_session_1, vul_logger, driver1))
  process1.start() 

  if args.login == "yes" or args.login == "chrome":
    # Chrome driver setting - no auth
    options = webdriver.ChromeOptions()
    if args.login != "chrome":
      options.add_argument("--headless")
    options.add_argument('--no-sandbox')
    options.add_argument("--disable-web-security")
    options.add_argument("--disable-extensions")
    options.add_argument('--disable-dev-shm-usage')
    
    # Chrome driver file
    service = Service(executable_path=config['crawler']['chromedriver_path'])
    driver2 = Chrome(service=service, options=options)

    process2 = Process(target=auth_crawl, args=(request_lock, request_list, args, initial_session,vul_logger, driver2)) 
    process2.start() 
    
  
  while True: 
    printer_refresh()
    if process1.is_alive():
      printer("Unathenticated Crawl Status: Running") 
    elif args.login == "no":
      printer("Unathenticated Crawl Status: Done")
      break
    if args.login != "no":
      printer("Authenticated Crawl Status: Running" if process2.is_alive() else "Authenticated Crawl Status: Done")
      if not process1.is_alive() and not process2.is_alive():
        break 
    if time.time() - crawl_time > 90:
      print("1 minute!")
      break
    if len(request_list) > 200: 
      print("Full!")
      break 
    print("Current resource pool size: "+ str(len(request_list)))
    #print(request_list)
    printer_flush()
  

  method = ""
  fuzz = False
  start_time = time.time() 

  # log crawling time
  vul_logger.LogTime(start_time - crawl_time)
  crawling_time = start_time - crawl_time


  # request_list = valid_urls(request_list)
  
  print("WebFuzz campaign starts.\n")  
 
  past_time = start_time
  
  
  
  # Chrome driver setting - no auth
  options = webdriver.ChromeOptions()
  options.add_argument("--headless")
  options.add_argument('--no-sandbox')
  options.add_argument("--disable-web-security")
  options.add_argument("--disable-extensions")
  options.add_argument('--disable-dev-shm-usage')
 
  # Chrome driver file
  service = Service(executable_path=config['crawler']['chromedriver_path'])
  driver3 = Chrome(service=service, options=options)
  driver3.get(root_url)
  
  
    
  
  # fuzz session 
  fuzz_session = requests.Session()
  
  if args.login == "chrome":
    login(fuzz_session, root_url, args.login, driver3)
    '''
    driver3.delete_all_cookies()
    cookies = driver2.get_cookies() 
    for cookie in cookies:
      print(cookie)
      driver3.add_cookie(cookie)
      fuzz_session.cookies.set(cookie['name'],cookie['value'],domain=cookie['domain'],path=cookie['path'])
    '''

  http_executor = HTTPExecutor(start_time=start_time, driver=driver3)
  current_time = time.time()
  time_value = current_time - crawl_time 
  if args.login == "yes" :
    login(fuzz_session, root_url, args.login, driver3)
  request_idx =0
  detection_start_time = time.time()
  login_time = time.time() 
  
  while len(request_list) > request_idx:
    if args.login == "yes" and time.time() - login_time > 300 :
      login(fuzz_session, root_url, args.login, driver3)
      login_time = time.time()
    printer_refresh()
    #print(request_list)
    printer("Unathenticated Crawl Status: Running" if process1.is_alive() else "Unathenticated Crawl Status: Done")
    if args.login != "no":
      printer("Authenticated Crawl Status: Running" if  process2.is_alive() else "Authenticated Crawl Status: Done")
    printer("Resource Pool Size: " +  str(len(request_list)))
    printer("Current idx: " + str(request_idx))

    each_request = request_list[request_idx]
    request_idx += 1

    if each_request.get_params != [] or each_request.post_params != []: 
      fuzz = False
      if each_request._method == "GET":
        method = "get"
        target_url = combine_url_params(each_request.path, each_request.get_params)
        fuzz = True
      else: 
        method = "post"
        target_url = combine_url_params(each_request.path, each_request.post_params)
        fuzz = True
      
      
      # fuzzing each url 
      if fuzz and args.opt == 'fuzz':
        printer("Taget URL: " + target_url)
        #exec_fuzz(request_lock, request_list, target_url, mode, args.login, method, initial_session, vul_logger, coverage_reporter,  start_time, int(args.timeout), seed_mode, http_executor, float(args.hyper))
        process3 = Process(target=exec_fuzz, args=(request_lock, request_list, target_url, mode, args.login, method, fuzz_session, vul_logger, coverage_reporter,  start_time, int(config['fuzzer']['fuzz_timeout']), seed_mode, http_executor)) 
        process3.start()
        process3.join() 
    printer_flush() 

    current_time = time.time()
    time_value = current_time - detection_start_time 
    timeout_sec = int(config['test']['timeout'])
    if (time_value + crawling_time) > timeout_sec - 3600:
      vul_logger.LogTime(time.time() - start_time)
      vul_logger.LogRequest()
    if (time_value + crawling_time) > timeout_sec - 1000:
      vul_logger.LogTime(time.time() - start_time)
      vul_logger.LogRequest()
    if (time_value + crawling_time) > timeout_sec - 1:
      break
  vul_logger.LogTime(time.time() - start_time)
  vul_logger.LogRequest()
  print("Total time: " + str(time.time() - detection_start_time))

  process1.join()
  if args.login != "no":
    process2.join()
  
if __name__ == '__main__':
  main()


