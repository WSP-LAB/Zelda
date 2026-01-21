from src.attack_sqli import _find_pattern_in_response
from src.attack_cmi import _find_pattern_in_response_exec
from urllib.parse import urlparse, urlunparse, unquote
from bs4 import BeautifulSoup
from posixpath import normpath
import re
from random import choice
from string import ascii_letters
from enum import Enum
from functools import lru_cache
from urllib.parse import urlparse, urlunparse, unquote
from hashlib import md5
from http.client import IncompleteRead
import warnings
from ast import literal_eval
from collections import deque, defaultdict
from posixpath import normpath
import pickle
import math
import functools
from time import sleep
from selenium import webdriver
# Third-parties
import requests
import urllib3
from src.net import web
import warnings
warnings.filterwarnings("ignore")

class ResponseAnalyzer():
    def __init__(self, url):
        self.content = "" 
        self.current_lines_of_code = []
        self.initial_content_length = 0 
        self.max_content_diff = 0
        self.collected_urls = [] 
        self.collected_forms = [] 
        self._url = url
        self.base_domain = url.replace("http://", "").split("/")[0].split(":")[0]

    def is_in_scope(self, url):
        if url[-2:] == "js" or url[-3:] in ["ccs", "svg","png","mp4","jpg"]:
            return False
        if "setup" in url or "logout" in url or "logoff" in url or "/DVWA/security.php" in url:
            return False
        elif self.base_domain in url:
            return True
        else:
            return False 

    def CheckContentLength(self, header):
        #print(header)
        try:
            current_content_length = int(header["Content-Length"])
        
            # set initial value
            if self.initial_content_length == 0:
                self.initial_content_length = current_content_length

            # calcuate content length difference 
            content_length_score = abs(self.initial_content_length - current_content_length)

            # compare with max difference
            if content_length_score > self.max_content_diff:
                self.max_content_diff = content_length_score 
            # caculate and return normalized score 
            if self.max_content_diff != 0:
                return content_length_score / self.max_content_diff
            else: return 0
        except:
            return 0
    
    def make_absolute(self, link: str) -> str:
        """Convert a relative URL to an absolute one (with scheme, host, path, etc) and use the base href if present.
        
        @type link: str
        @param link: A relative URL.
        @rtype: str
        """
        # print(link)
        if not link.strip():
            return ""

        current_url_parts = urlparse(self._url)
        scheme = current_url_parts.scheme
        domain = current_url_parts.netloc
        path = current_url_parts.path
        params = current_url_parts.params

        try:
            parts = urlparse(link)
        except ValueError:
            # malformed URL, for example "Invalid IPv6 URL" errors due to square brackets
            return ""

        query_string = parts.query
        url_path = parts.path or '/'
        url_path = normpath(url_path.replace("\\", "/"))

        # https://stackoverflow.com/questions/7816818/why-doesnt-os-normpath-collapse-a-leading-double-slash
        url_path = re.sub(r"^/{2,}", "/", url_path)

        # normpath removes the trailing slash so we must add it if necessary
        if (parts.path.endswith(('/', '/.')) or parts.path == '.') and not url_path.endswith('/'):
            url_path += '/'

        # a hack for auto-generated Apache directory index
        if query_string in [
            "C=D;O=A", "C=D;O=D", "C=M;O=A", "C=M;O=D",
            "C=N;O=A", "C=N;O=D", "C=S;O=A", "C=S;O=D"
        ]:
            query_string = ""

        if parts.scheme:
            if parts.scheme == "http" or parts.scheme == "https":
                if parts.netloc and parts.netloc != "http:":  # malformed url
                    netloc = parts.netloc
                    try:
                        # urlparse tries to convert port in base10. an error is raised if port is not digits
                        port = parts.port
                    except ValueError:
                        port = None

                    if (parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80):
                        # Beware of IPv6 addresses
                        netloc = parts.netloc.rsplit(":", 1)[0]
                    return urlunparse((parts.scheme, netloc, url_path, parts.params, query_string, ''))
        elif link.startswith("//"):
            if parts.netloc:
                netloc = parts.netloc
                try:
                    port = parts.port
                except ValueError:
                    port = None

                if (parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80):
                    # Beware of IPv6 addresses
                    netloc = parts.netloc.rsplit(":", 1)[0]
                return urlunparse((scheme, netloc, url_path or '/', parts.params, query_string, ''))
        elif link.startswith("/"):
            return urlunparse((scheme, domain, url_path, parts.params, query_string, ''))
        elif link.startswith("?"):
            return urlunparse((scheme, domain, path, params, query_string, ''))
        elif link == "": 
            return self._url
        elif link.startswith("#"):
            #print(unquote(self._url))
            #print(unquote(self._url + link))
            return unquote(self._url + link)
        else:
            # relative path to file, subdirectory or parent directory
            current_directory = path if path.endswith("/") else path.rsplit("/", 1)[0] + "/"
            # new_path = (current_directory + parts.path).replace("//", "/").replace("/./", "/")

            new_path = normpath(current_directory + url_path)
            if url_path.endswith('/') and not new_path.endswith('/'):
                new_path += '/'

            # links going to a parent directory (..)
            # while re.search(r"/([~:!,;%a-zA-Z0-9\.\-+_]+)/\.\./", new_path) is not None:
            #     new_path = re.sub(r"/([~:!,;%a-zA-Z0-9\.\-+_]+)/\.\./", "/", new_path)
            # while re.search("/\./", new_path) is not None:
            #     new_path = re.sub("/\./", "/", new_path)
            # if new_path == "":
            #     new_path = '/'

            # Fix for path going back up the root directory (eg: http://srv/../../dir/)
            # new_path = re.sub(r'^(/?\.\.//*)*', '', new_path)
            # if not new_path.startswith('/'):
            #     new_path = '/' + new_path

            return urlunparse((scheme, domain, new_path, parts.params, query_string, ''))
        # Returns an empty string for everything that we don't want to deal with
        return ""

    def get_urls(self, response):
        new_list = []
        new_urls = []
        soup = BeautifulSoup(response, 'html.parser')
        # basic urls
        for tag in soup.find_all("a", href=True):
            new_list.append(self.make_absolute(tag["href"].split("#")[0].strip()))

        # crawl SPAs 
        for tag in soup.find_all("a", href=True):
            new_list.append(self.make_absolute(tag["href"]))

        for tag in soup.find_all(["frame", "iframe"], src=True):
            new_list.append(self.make_absolute(tag["src"].split("#")[0].strip()))

        for tag in soup.find_all("form", action=True):
            new_list.append(self.make_absolute(tag["action"]))

        for tag in soup.find_all("button", formaction=True):
            new_list.append(self.make_absolute(tag["formaction"]))

        import markdown 
        # cover markdown links 
        for tag in soup.find_all("div", "markdown"):
            result = markdown.markdown(tag.text)
            # print(result)
            markdown_soup = BeautifulSoup(result,"html.parser")
            for real_tag in markdown_soup.find_all("a", href=True):
                new_list.append(self.make_absolute(real_tag["href"].split("#")[0].strip())) 
    
        for url in new_list: 
            if self.is_in_scope(url):
                new_urls.append(web.Request(
                    url,
                    method="GET",
                    get_params=[],
                    post_params=[],
                    file_params=[],
                    encoding='utf-8',
                    referer=self._url,
                    enctype=""
                ))
        
        return new_urls 

    def get_forms(self, response):
        autofill = True
        soup = BeautifulSoup(response, 'html.parser')
        new_forms = []
        for form in soup.find_all("form"):
            url = self.make_absolute(form.attrs.get("action", "").strip() or self._url)
            if self.is_in_scope(url):
                # If no method is specified then it's GET. If an invalid method is set it's GET.
                method = "POST" if form.attrs.get("method", "GET").upper() == "POST" else "GET"
                enctype = "" if method == "GET" else form.attrs.get("enctype", "application/x-www-form-urlencoded").lower()
                get_params = []
                post_params = []
                # If the form must be sent in multipart, everything should be given to requests in the files parameter
                # but internally we use the file_params list only for file inputs sent with multipart (as they must be
                # threated differently in persister). Crawler.post() method will join post_params and file_params for us
                # if the enctype is multipart.
                file_params = []
                form_actions = set()
            
                defaults = {
                    "checkbox": "",
                    "color": "#bada55",
                    "date": "2019-03-03",
                    "datetime": "2019-03-03T20:35:34.32",
                    "datetime-local": "2019-03-03T22:41",
                    "email": "",
                    "file": ["pix.gif", "GIF89a", "image/gif"],
                    "hidden": "",
                    "month": "2019-03",
                    "number": "1337",
                    "password": "",  # 8 characters with uppercase, digit and special char for common rules
                    "radio": "beton",  # priv8 j0k3
                    "range": "37",
                    "search": "",
                    "submit": "",
                    "tel": "0606060606",
                    "text": "",
                    "time": "13:37",
                    "url": "http://wapiti.sf.net/",
                    "week": "2019-W24",
                    "username": ""
                }

                radio_inputs = {}
                for input_field in form.find_all("input", attrs={"name": True}):
                    input_type = input_field.attrs.get("type", "text").lower()

                    if input_type in {"reset", "button"}:
                        # Those input types doesn't send any value
                        continue

                    if input_type == "image":
                        if method == "GET":
                            get_params.append([input_field["name"] + ".x", "1"])
                            get_params.append([input_field["name"] + ".y", "1"])
                        else:
                            post_params.append([input_field["name"] + ".x", "1"])
                            post_params.append([input_field["name"] + ".y", "1"])
                    elif input_type in defaults:
                        if input_type == "text" and "mail" in input_field["name"] and autofill:
                            # If an input text match name "mail" then put a valid email address in it
                            input_value = defaults["email"]
                        elif input_type == "text" and "pass" in input_field["name"] or \
                                "pwd" in input_field["name"] and autofill:
                            # Looks like a text field but waiting for a password
                            input_value = defaults["password"]
                        elif input_type == "text" and "user" in input_field["name"] or \
                                "login" in input_field["name"] and autofill:
                            input_value = defaults["username"]
                        else:
                            input_value = input_field.get("value", defaults[input_type] if autofill else "")

                        if input_type == "file":
                            # With file inputs the content is only sent if the method is POST and enctype multipart
                            # otherwise only the file name is sent.
                            # Having a default value set in HTML for a file input doesn't make sense... force our own.
                            if method == "GET":
                                get_params.append([input_field["name"], "pix.gif"])
                            else:
                                if "multipart" in enctype:
                                    file_params.append([input_field["name"], defaults["file"]])
                                else:
                                    post_params.append([input_field["name"], "pix.gif"])
                        elif input_type == "radio":
                            # Do not put in forms now, do it at the end
                            radio_inputs[input_field["name"]] = input_value
                        else:
                            if method == "GET":
                                get_params.append([input_field["name"], input_value])
                            else:
                                post_params.append([input_field["name"], input_value])

                # A formaction doesn't need a name
                for input_field in form.find_all("input", attrs={"formaction": True}):
                    form_actions.add(self._make_absolute(input_field["formaction"].strip() or self._url))

                for button_field in form.find_all("button"):
                    if "name" in button_field.attrs:
                        input_name = button_field["name"]
                        input_value = button_field.get("value", "")
                        if method == "GET":
                            get_params.append([input_name, input_value])
                        else:
                            post_params.append([input_name, input_value])

                    if "formaction" in button_field.attrs:
                        # If formaction is empty it basically send to the current URL
                        # which can be different from the defined action attribute on the form...
                        form_actions.add(self._make_absolute(button_field["formaction"].strip() or self._url))

                if form.find("input", attrs={"name": False, "type": "image"}):
                    # Unnamed input type file => names will be set as x and y
                    if method == "GET":
                        get_params.append(["x", "1"])
                        get_params.append(["y", "1"])
                    else:
                        post_params.append(["x", "1"])
                        post_params.append(["y", "1"])

                for select in form.find_all("select", attrs={"name": True}):
                    all_values = []
                    selected_value = None
                    for option in select.find_all("option", value=True):
                        all_values.append(option["value"])
                        if "selected" in option.attrs:
                            selected_value = option["value"]

                    if selected_value is None and all_values:
                        # First value may be a placeholder but last entry should be valid
                        selected_value = all_values[-1]

                    if method == "GET":
                        get_params.append([select["name"], selected_value])
                    else:
                        post_params.append([select["name"], selected_value])

                # if form.find("input", attrs={"type": "image", "name": False}):
                #     new_form.add_image_field()

                for text_area in form.find_all("textarea", attrs={"name": True}):
                    if method == "GET":
                        get_params.append([text_area["name"], "Hi there!" if autofill else ""])
                    else:
                        post_params.append([text_area["name"], "Hi there!" if autofill else ""])

                # I guess I should raise a new form for every possible radio values...
                # For the moment, just use the last value
                for radio_name, radio_value in radio_inputs.items():
                    if method == "GET":
                        get_params.append([radio_name, radio_value])
                    else:
                        post_params.append([radio_name, radio_value])

                if method == "POST" and not post_params and not file_params:
                    # Ignore empty forms. Those are either webdev issues or forms having only "button" types that
                    # only rely on JS code.
                    continue

                # First raise the form with the URL specified in the action attribute
                new_form = web.Request(
                    url,
                    method=method,
                    get_params=get_params,
                    post_params=post_params,
                    file_params=file_params,
                    encoding='utf-8',
                    referer=self._url,
                    enctype=enctype
                )
            
                new_forms.append(new_form)

                # Then if we saw some formaction attribute, raise the form with the given formaction URL
                for url in form_actions:
                    new_form = web.Request(
                        url,
                        method=method,
                        get_params=get_params,
                        post_params=post_params,
                        file_params=file_params,
                        encoding=self.apparent_encoding,
                        referer=self.url,
                        enctype=enctype
                    )
                    new_forms.append(new_form)
        return new_forms 

    def search_new_resources(self, response, request_list, request_lock):
        try:
            if bool(BeautifulSoup(response, "html.parser").find()):
                new_list = self.get_urls(response)
                new_forms = self.get_forms(response)
                for resource in new_list:
                    if resource not in request_list: 
                        request_lock.acquire()
                
                        request_list.append(resource)
                        request_lock.release()
                for resource in new_forms: 
                    #print(resource)
                    if resource not in request_list: 
                        #print(resource)
                        request_lock.acquire()
              
                        request_list.append(resource)
                        request_lock.release()
        except:
            pass
    def DiffHTML(self, response):
        new_node = False
        for key in headers.keys():
            if "I-" in key:
                if not (key.replace("I-","") in self.covered_blocks): 
                    #print(key)
                    new_node = True 
                    break
        return new_node
                
    
    def LinesofCode(self, response):
        length = response.count("\n")
        if length in self.current_lines_of_code:
            return False 
        else:
            self.current_lines_of_code.append(length)
            return True
        

    # Potential XSS check  
    def CheckXSS(self, response, payloads):
        content = response
        from difflib import SequenceMatcher
        reflected = False
        reflected_idx = []
        idx = 0
   
        for payload in payloads:

            if content.find(payload.rstrip('\x00').rstrip('\n')) != -1 and len(payload.rstrip('\x00').rstrip('\n')) > 1:
                
                reflected = True 
                reflected_idx.append(idx)
            else: 
                if "'" in payload: 
                    split_index = payload.find("'")
                elif '"' in payload:
                    split_index = payload.find('"')
                else: split_index = -1
                
                if split_index != -1:
                    split_payload =  payload[split_index+1:].rstrip('\x00').rstrip('\n')
                        
                    if content.find( split_payload ) != -1 and len( split_payload ) > 1:
                        reflected = True 
                        reflected_idx.append(idx)
                        break 
            idx += 1 
       
        
       
        #print(reflected_idx)
        return reflected, reflected_idx


    # Potential SQLI check 
    def CheckSQLI(self, response):
        content = response
        
        if _find_pattern_in_response(content):
            return True
        else: return False

    # Potential CMDI check
    def CheckCMDI(self, response):
        content = response
        __, __, warned = _find_pattern_in_response_exec(content, False)
        
        return warned
