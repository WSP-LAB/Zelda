from src.net import crawler, jsoncookie
from src.net.sqlite_persister import SqlitePersister
from collections import deque
from datetime import datetime
import sys
import os
from colorama import Fore, Back, Style
from hashlib import md5
from urllib.parse import urlparse
import asyncio 
from src.net import web
import json 
import time
class CrawlerWrapper():
    def __init__(self, request_lock, request_list, root_url, session, vul_logger, browser=None, mode="headdless"):
        self._shared_lock = request_lock 
        self._shared_list = request_list
        self.target_url = root_url 
        self.server = urlparse(root_url).netloc
        self.vul_logger = vul_logger

        self.crawler=crawler.Crawler(root_url, session=session, browser=browser, request_lock=request_lock, request_list=request_list, mode=mode)
        self.crawler.scope = crawler.Scope.PUNK
        self._start_urls = deque([root_url])
        self.urls = []
        self.forms = []
        self.attacks = []
        self._history_file = os.path.join(
            SqlitePersister.CRAWLER_DATA_DIR,
            "{}_{}_{}.db".format(
                self.server.replace(':', '_'),
                self.crawler.scope,
                md5(root_url.encode(errors="replace")).hexdigest()[:8]
            )
        )
        # print(self._history_file)
        self.persister = SqlitePersister(self._history_file)
        self.color = 0
        self.verbose = 0
        self.module_options = None
        self.attack_options = {}
        self._excluded_urls = []
        self._bad_params = set()
        self._max_depth = 40
        self._max_links_per_page = -1
        self._max_files_per_dir = 0
        self._scan_force = "normal"
        self._max_scan_time = 0
        self._bug_report = True

        self.report_gen = None
        self.report_generator_type = "html"
        self.output_file = ""
    
    def set_mode(self, mode):
        self.crawler.set_mode(mode)

    def add_request(self, http_resource):
        #print(http_resource)
        #time.sleep(1)
        #print(self._shared_list)
        self._shared_lock.acquire() 
        if self._shared_list == []:
            self._shared_list.append(http_resource) 
        elif http_resource in self._shared_list:
            #print(http_resource)
            #print(self._shared_list)
            pass
        else:
            if http_resource.path[-2:] == "js":
                pass 
            elif http_resource.path[-3:] == "ccs":
                pass
            elif http_resource.path[-2:] == "html":
                pass
            elif "logout" in http_resource.path:
                pass 
            
            #elif http_resource.get_params == [] and http_resource.post_params ==[]:
            #    pass 
            else:
                
                self._shared_list.append(http_resource) 
        self._shared_lock.release()  

    def browse(self):

        """Extract hyperlinks and forms from the webpages found on the website"""
        for resource in self.persister.get_to_browse():
            self._start_urls.append(resource)
        for resource in self.persister.get_links():
            self._excluded_urls.append(resource)
        for resource in self.persister.get_forms():
            self._excluded_urls.append(resource)

        stopped = False

        explorer = crawler.Explorer(self.crawler)
        explorer.max_depth = self._max_depth
        explorer.max_files_per_dir = self._max_files_per_dir
        explorer.max_requests_per_depth = self._max_links_per_page
        explorer.forbidden_parameters = self._bad_params
        explorer.qs_limit = 1 #SCAN_FORCE_VALUES[self._scan_force]
        explorer.verbose = (self.verbose > 0)
        explorer.load_saved_state(self.persister.output_file[:-2] + "pkl")

        self.persister.set_root_url(self.target_url)
        start = datetime.utcnow()
        import time
        start_time = time.time()
        past_time = start_time
        print(Fore.RED + "[*] Start Scanning...", end="\r")
        try:
            #print(self._start_urls)
            #print(type(explorer.explore(self._start_urls, self._excluded_urls)))
            for resource in explorer.explore(self._start_urls, self._excluded_urls):
                # Browsed URLs are saved one at a time
                current_time = time.time() 
     
                # self.persister.add_request(resource)
                self.add_request(resource)
                #print(resource)
                if (datetime.utcnow() - start).total_seconds() > self._max_scan_time >= 1:
                    print(("Max scan time was reached, stopping."))
                    break
        except KeyboardInterrupt:
            stopped = True
        sys.stdout.write("\033[K")
        print(Fore.GREEN + "[*] Scanning complete" + Fore.RESET)
        print(("[*] Saving scan state, please wait..."))

        # Not yet scanned URLs are all saved in one single time (bulk insert + final commit)
        self.persister.set_to_browse(self._start_urls)
        # Let's save explorer values (limits)
        explorer.save_state(self.persister.output_file[:-2] + "pkl")

        
        # print((" Note"))
        # print("========")

        # print(("This scan has been saved in the file {0}").format(self.persister.output_file))
        if stopped:
            print(("The scan will be resumed next time unless you pass the --skip-crawl option."))

    


    def set_timeout(self, timeout: float = 6.0):
        """Set the timeout for the time waiting for a HTTP response"""
        self.crawler.timeout = timeout

    def set_verify_ssl(self, verify: bool = False):
        """Set whether SSL must be verified."""
        self.crawler.secure = verify

    def set_proxy(self, proxy: str = ""):
        """Set a proxy to use for HTTP requests."""
        self.crawler.set_proxy(proxy)

    def add_start_url(self, url: str):
        """Specify an URL to start the scan with. Can be called several times."""
        self._start_urls.append(url)

    def add_excluded_url(self, url_or_pattern: str):
        """Specify an URL to exclude from the scan. Can be called several times."""
        self._excluded_urls.append(url_or_pattern)

    def set_cookie_file(self, cookie: str):
        """Load session data from a cookie file"""
        if os.path.isfile(cookie):
            jc = jsoncookie.JsonCookie()
            jc.open(cookie)
            cookiejar = jc.cookiejar(self.server)
            jc.close()
            self.crawler.session_cookies = cookiejar

    def set_auth_credentials(self, auth_basic: tuple):
        """Set credentials to use if the website require an authentication."""
        self.crawler.credentials = auth_basic

    def set_auth_type(self, auth_method: str):
        """Set the authentication method to use."""
        self.crawler.auth_method = auth_method

    def add_bad_param(self, param_name: str):
        """Exclude a parameter from an url (urls with this parameter will be
        modified. This function can be call several times"""
        self._bad_params.add(param_name)

    def set_max_depth(self, limit: int):
        """Set how deep the scanner should explore the website"""
        self._max_depth = limit

    def set_max_links_per_page(self, limit: int):
        self._max_links_per_page = limit

    def set_max_files_per_dir(self, limit: int):
        self._max_files_per_dir = limit

    def set_scan_force(self, force: str):
        self._scan_force = force

    def set_max_scan_time(self, minutes: float):
        self._max_scan_time = minutes * 60

    def set_color(self):
        """Put colors in the console output (terminal must support colors)"""
        self.color = 1

    def verbosity(self, vb: int):
        """Define the level of verbosity of the output."""
        self.verbose = vb

    def set_bug_reporting(self, value: bool):
        self._bug_report = value

    def set_attack_options(self, options: dict = None):
        self.attack_options = options if isinstance(options, dict) else {}

    def set_modules(self, options=""):
        """Activate or deactivate (default) all attacks"""
        self.module_options = options

    def set_report_generator_type(self, report_type="xml"):
        """Set the format of the generated report. Can be html, json, txt or xml"""
        self.report_generator_type = report_type

    def set_output_file(self, output_file: str):
        """Set the filename where the report will be written"""
        self.output_file = output_file

    def add_custom_header(self, key: str, value: str):
        self.crawler.add_custom_header(key, value)

    def flush_attacks(self):
        self.persister.flush_attacks()

    def flush_session(self):
        self.persister.close()
        try:
            os.unlink(self._history_file)
        except FileNotFoundError:
            pass

        try:
            os.unlink(self.persister.output_file[:-2] + "pkl")
        except FileNotFoundError:
            pass
        self.persister = SqlitePersister(self._history_file)

    def count_resources(self):
        return self.persister.count_paths()

    def has_scan_started(self):
        return self.persister.has_scan_started()

    def have_attacks_started(self):
        return self.persister.have_attacks_started()