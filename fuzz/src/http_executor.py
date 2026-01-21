import requests
import http
from configparser import ConfigParser
from src.login_credentials import login_credentials 
import time
http.client._MAXHEADERS = 100000
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import asyncio 
import pyppeteer as pyp 

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
import json 

# Function to check if network is idle
def is_network_idle(driver):

    return driver.execute_script("return document.readyState") == "complete"

def phoenixcart_login(browser, login_url):
    browser.get(login_url)
    browser.implicitly_wait(5)
    browser.find_element('name', 'username').send_keys('admin')
    browser.find_element('name', 'password').send_keys('admin')
    browser.find_element('xpath', '/html/body/div[1]/div/div/div/div/form/ul/li[3]/button').click()
    browser.implicitly_wait(10)
    
def phpwcms_login(browser, login_url):
    browser.get(login_url)
    browser.implicitly_wait(5)
    browser.find_element('id', 'form_loginname').send_keys('admin')
    browser.find_element('id', 'form_password').send_keys('admin')
    browser.find_element('xpath', '/html/body/div[1]/div/div/form/table/tbody/tr[4]/td[2]/input').click()
    browser.implicitly_wait(10)

def webgoat_login(browser, LOGIN_INFO, login_url):

    # JavaScript code to send a POST request with input data
    browser.request('POST', login_url, data = LOGIN_INFO)
    
    
def login(session, input_url, mode, driver):

    print("Start Login\n")
    login_url, start_url, LOGIN_INFO = login_credentials(session, input_url)
    if mode == "chrome":
        if "Phoenix" in login_url:
            phoenixcart_login(driver, login_url)
        #elif "phpwcms" in login_url:
        #    phpwcms_login(driver, login_url)
        else:
            driver.implicitly_wait(5)
            driver.get(login_url)
            time.sleep(10)
            
            _cookies = driver.get_cookies() 
            cookie_dict = {}
        
            for cookie in _cookies:
                session.cookies.set(cookie['name'],cookie['value'],domain=cookie['domain'],path=cookie['path'])
  
        # driver.quit() 
        #print(cookie_dict)
        #session.cookies.update(_cookies)
  
    else:
        """
        if "WebGoat" in login_url:
            print("WebGoat!")
            
            webgoat_login(driver, LOGIN_INFO, login_url)
            driver.get(start_url)
            time.sleep(5)
            _cookies = driver.get_cookies() 
            cookie_dict = {}
            print(_cookies)
            for cookie in _cookies:
                session.cookies.set(cookie['name'],cookie['value'],domain=cookie['domain'],path=cookie['path'])
        """
        try:
            login_res = session.post(login_url, data=LOGIN_INFO,timeout=4)
        except:
            pass
        driver.set_page_load_timeout(4) 
        try:
            driver.get(login_url)
            driver.delete_all_cookies()
            domain = login_url.split("://")[1].split(":")[0].split("/")[0]
            for key in list(session.cookies.get_dict().keys()):
                driver.add_cookie({'name':key, 'value':session.cookies.get_dict()[key], 'domain':domain, 'path':'/'+ login_url.split('/')[1]})
                #print({'name':key, 'value':session.cookies.get_dict()[key]})
                #driver.add_cookie({'name':key, 'value':session.cookies.get_dict()[key]})
                print(driver.get_cookies())
        except:
            pass
        
        print("Login!\n")
        try:
            req = session.get(start_url,timeout=4)
        except:
            pass
        start_url = start_url
     
    return start_url

class HTTPExecutor:
    def __init__(self, start_time, driver):
        self.start_time = start_time
        self.current_time = time.time() 
        self.past_time = start_time 
        self.timeout = 10
        self.mode = "" # "chrome"
        self.driver= driver

    def ExecutePUTbyRequest(self, url, session, original_params, method, mutated_idx = -1, vul_logger = None):
        url_injection = False

        if list(original_params.keys())[mutated_idx] == "ownurl":
            url_injection = True

        params = {}
        headers = {}
        cookies = {}
        #print(original_params)
        for key in original_params.keys():
            if key == "ownurl":
                add_to_url = original_params[key]
                if add_to_url != "":
                    url += "/"
                    url += add_to_url
                    url += "/"
                
            elif key == "ownreferer" :
                if original_params[key] != "":
                    headers["Referer"] = original_params[key]
                else:
                    headers["Referer"] = url
            elif key == "owncookie" :
                if original_params[key] != "":
                    cookies["insert"] = original_params[key]
            elif key == "ownuseragent":
                if original_params[key] != "":
                    headers["User-Agent"] = original_params[key]
            elif "security_level" in key:
                params[key] = 0
            else: 
                params[key] = original_params[key]
            
            
        #print(params)
        
        _cookies = self.driver.get_cookies()
        #print(_cookies)
        for cookie in _cookies:
            session.cookies.set(cookie['name'], cookie['value'],path=cookie['path'], domain=cookie['domain'])
        cookies.update(session.cookies.get_dict())
        # print(cookies)
        try:
            #print(str(params))
            #print(method)
            if method == "get":
                vul_logger.CountRequest()
                #print(params)
                response = session.get(url=url, params=params, headers=headers, cookies=cookies, timeout=4, allow_redirects=True)
                
            else: 
                if url_injection:
                    vul_logger.CountRequest()
                    response = session.get(url=url,params=params, headers=headers, cookies=cookies,  timeout=4, allow_redirects=True)
                else:
                    vul_logger.CountRequest()
                    if "__RequestVerificationToken" in params.keys():
                        vul_logger.CountRequest()
                        response = session.get(url=url,params=params, headers=headers, cookies=cookies,  timeout=4, allow_redirects=True)
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(response.text, "html.parser")
                        token = soup.findAll("input", {"type": "hidden"})[0]['value']
                        params["__RequestVerificationToken"] = token
                    response = session.post(url=url, data=params, headers=headers, cookies=cookies,  timeout=4, allow_redirects=False) 
                    #print(cookies)
                    #print(params)
                    
                    
            #print(response.text)
                    #response = session.get(url=url,  headers=headers, cookies=cookies,  timeout=3)  
            #if self.mode == "chrome":
                #self.driver.request(url=url,params=params, headers=headers, cookies=cookies,  timeout=7, allow_redirects=True)
            #print(cookies)
            #print(self.current_time - self.past_time)
            
            # log coverage
            
            self.current_time = time.time() 

            #print(response.text)
            return response.headers,response.text

        except Exception as exception:
            if "Read timed out" in str(exception):
                print("Read timed out")
                return {}, "Read timed out"
            else:
                return {},""







