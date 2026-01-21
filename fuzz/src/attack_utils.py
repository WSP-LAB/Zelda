from math import ceil

def injectPayload(original_params, payload, target_idx, number_flag=None):
    result_params = {}
    # get the key of target idx
    idx = 0
    
    for key in original_params.keys():
        if idx == target_idx:
            payload = payload.replace("[VALUE]", original_params[key])
            payload = payload.replace("[TAINT]", str(number_flag))
            payload = payload.replace("[SQL]", '\\' + '"' + '\\' + "\\'>")
            result_params[key] = payload 
        else:
            result_params[key] = original_params[key]
        idx += 1

    #print(result_params)
    return result_params

# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2020-2022 Nicolas Surribas
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
from configparser import ConfigParser
from typing import Tuple, List
from html.parser import attrfind_tolerant
from urllib.parse import urlparse
from os.path import join as path_join
import random
from bs4 import BeautifulSoup, element
from enum import Enum
from src.net.web import Request
#from wapitiCore.attack.attack import PayloadType, Flags, random_string
#from wapitiCore.net import Response


# Everything under those tags will be treated as text
#from wapitiCore.parsers.html_parser import Html

NONEXEC_PARENTS = {
    "iframe",
    "noframes",
    "noembed",
    "noscript",
    "plaintext",
    "style",
    "template",
    "textarea",
    "title",
    "xmp",
    "frameset"
}
class PayloadType(Enum):
    pattern = 1
    time = 2
    get = 3
    post = 4
    file = 5
    xss_closing_tag = 6
    xss_non_closing_tag = 7


class Flags:
    def __init__(
            self,
            payload_type=PayloadType.pattern,
            section="",
            method=PayloadType.get,
            platform="all",
            dbms="all"
    ):
        self.payload_type = payload_type
        self.section = section
        self.method = method
        self.platform = platform
        self.dbms = dbms

    def with_method(self, method):
        return Flags(
            payload_type=self.payload_type,
            section=self.section,
            method=method,
            platform=self.platform,
            dbms=self.dbms
        )

    def with_section(self, section):
        return Flags(
            payload_type=self.payload_type,
            section=section,
            method=self.method,
            platform=self.platform,
            dbms=self.dbms
        )

    def __str__(self):
        return (
            f"Flags(payload_type={self.payload_type}, "
            f"section='{self.section}', "
            f"method={self.method}, "
            f"platform='{self.platform}', "
            f"dbms='{self.dbms}')"
        )

    def __eq__(self, other):
        if not isinstance(other, Flags):
            raise ValueError("Can't compare a Flags object to another kind of object")

        return (
                self.payload_type == other.payload_type and
                self.section == other.section and
                self.method == other.method and
                self.platform == other.platform and
                self.dbms == other.dbms
        )

def random_string(prefix: str = "w", length: int = 10) -> str:
    """Create a random unique ID that will be used to test injection."""
    # doesn't uppercase letters as BeautifulSoup make some data lowercase
    code = prefix + "".join(
        [random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, length - len(prefix))]
    )
    return code

def find_non_exec_parent(tag):
    """Return the tag name of the most upper parent preventing JS execution"""
    no_exec_parent = ""
    for parent in tag.parents:
        if parent and parent.name in NONEXEC_PARENTS:
            no_exec_parent = parent.name

    return no_exec_parent


def is_context_executable(node):
    """Returns whether the current tag doesn't follows a tag that stop JS execution (such as frameset)."""
    # Search for any frameset sat that appeared before in the DOM but weren't parent
    if set(node.find_all_previous("frameset")) - set(node.find_parents("frameset")):
        return False
    return True


def get_special_attributes(node):
    specials = set()
    # We don't care about the value of the following attributes but we need to know if they are present
    for attribute in ("href", "src", "style"):
        if attribute in node.attrs:
            specials.add(attribute)

    if "type" in node.attrs:
        specials.add(f"type={node.attrs['type'].lower()}")
    if "rel" in node.attrs:
        # BeautifulSoup returns a list for rel attribute.
        specials.add(f"rel={node.attrs['rel'][0].lower()}")
    return specials


def get_similar_case_replacement(original_keyword, new_keyword) -> str:
    #assert len(original_keyword) == len(new_keyword)
    result = ""
    for old_char, new_char in zip(original_keyword, new_keyword):
        if old_char.islower():
            result += new_char.lower()
        else:
            result += new_char.upper()
    return result


def replace_with_unique_values(text: str, keyword: str) -> Tuple[str, List[str]]:
    new_text = text
    lower_text = text.lower()
    start = 0
    taints = []
    while True:
        try:
            start = lower_text.index(keyword, start)
        except ValueError:
            break

        end = start + len(keyword)
        old_string = text[start:end]
        replacement = get_similar_case_replacement(old_string, random_string("x", len(old_string)))
        taints.append(replacement)
        new_text = new_text.replace(old_string, replacement, 1)
        start = end

    return new_text, taints


def put_back_code_in_context(context, tainted_code, original_code):
    for key, value in context.items():
        if isinstance(value, str):
            context[key] = value.replace(tainted_code, original_code)


def find_separator(html_code, tainted_attr_value, tag_name):
    lower_code = html_code.lower()
    code_index = lower_code.index(tainted_attr_value)
    tag_index = lower_code.rindex("<" + tag_name, 0, code_index)
    tag_end = lower_code.index(">", code_index + len(tainted_attr_value))
    attributes_string = lower_code[tag_index + len(tag_name) + 1:tag_end]
    for __, __, attrvalue in attrfind_tolerant.findall(attributes_string):
        if tainted_attr_value in attrvalue:
            if attrvalue[:1] == '\'' == attrvalue[-1:] or attrvalue[:1] == '"' == attrvalue[-1:]:
                return attrvalue[:1]
    return ""


# type/name/tag ex: attrval/img/src
def get_context_list(html_code, original_keyword):
    #print(original_keyword)
    #tainted_code, taints = replace_with_unique_values(html_code, original_keyword)
    tainted_code = html_code
    taints = [original_keyword]
    root_node = BeautifulSoup(tainted_code, "html.parser")
    
    context_list = []
    
    #  print("Keyword is: {0}".format(keyword))
    for keyword in taints:
        keyword = keyword.lower()
        # if keyword in found_taints:
        #     continue
        print("Keyword is: {0}".format(keyword))
        for node in root_node.descendants:
            
            # Several taints may be found in the same node but a taint will appear only once in the code
            if keyword in str(node).lower():
                
                if isinstance(node, element.Tag) and is_context_executable(node):
                    events = set(name for name in node.attrs.keys() if name.startswith("on"))
                    if keyword in str(node.attrs).lower():
                        for attr_name, attr_value in node.attrs.items():
                            # Be careful: attr_value may be a list, for example with attribute "rel" of tag "link"
                            if keyword in str(attr_value).lower():
                                # print("Found in attribute value {0} of tag {1}".format(attr_name, bs_node.name))
                                bad_parent = find_non_exec_parent(node)

                                try:
                                    separator = find_separator(tainted_code, keyword, node.name)
                                except ValueError:
                                    separator = ""

                                context = {
                                    "type": "attrval",
                                    "name": attr_name,
                                    "tag": node.name,
                                    "non_exec_parent": bad_parent,
                                    "events": events,
                                    "separator": separator
                                }

                                special_attributes = get_special_attributes(node)
                                if special_attributes:
                                    context["special_attributes"] = special_attributes

                                put_back_code_in_context(context, keyword, original_keyword)
                                if context not in context_list:
                                    context_list.append(context)

                            if keyword in attr_name:
                                # print("Found in attribute name {0} of tag {1}".format(attr_name, bs_node.name))
                                bad_parent = find_non_exec_parent(node)
                                context = {
                                    "type": "attrname",
                                    "name": attr_name,
                                    "tag": node.name,
                                    "non_exec_parent": bad_parent,
                                    "events": events
                                }

                                special_attributes = get_special_attributes(node)
                                if special_attributes:
                                    context["special_attributes"] = special_attributes

                                put_back_code_in_context(context, keyword, original_keyword)
                                if context not in context_list:
                                    context_list.append(context)

                    elif keyword in node.name.lower():
                        # print("Found in tag name")
                        bad_parent = find_non_exec_parent(node)
                        context = {
                            "type": "tag",
                            "value": node.name,
                            "non_exec_parent": bad_parent,
                            "events": events
                        }

                        put_back_code_in_context(context, keyword, original_keyword)
                        if context not in context_list:
                            context_list.append(context)

                elif isinstance(node, element.Comment) and is_context_executable(node):
                    # print("Found in comment, tag {0}".format(parent.name))
                    bad_parent = find_non_exec_parent(node)
                    context = {"type": "comment", "parent": node.parent.name, "non_exec_parent": bad_parent}
                    put_back_code_in_context(context, keyword, original_keyword)
                    if context not in context_list:
                        context_list.append(context)

                elif isinstance(node, element.NavigableString) and is_context_executable(node):
                    # print("Found in text, tag {0}".format(parent.name))
                    bad_parent = find_non_exec_parent(node)
                    context = {"type": "text", "parent": node.parent.name, "non_exec_parent": bad_parent}
                    put_back_code_in_context(context, keyword, original_keyword)
                    if context not in context_list:
                        context_list.append(context)
                """        
                if context_list == []:
                    bad_parent = find_non_exec_parent(node)
                    context = {"type": "text", "parent": node.parent.name, "non_exec_parent":  bad_parent}
                    if context not in context_list:
                        context_list.append(context)
                """
    return context_list


def load_payloads_from_ini(filename, external_endpoint):
    config_reader = ConfigParser(interpolation=None)
    payloads = []

    with open(filename, 'r', encoding='utf-8') as file_data:
        config_reader.read_file(file_data)
    external_endpoint = external_endpoint if external_endpoint.endswith('/') else external_endpoint + "/"
    parts = urlparse(external_endpoint)
    proto_endpoint = parts.netloc + parts.path

    for section in config_reader.sections():
        payload = config_reader[section]["payload"]
        value = config_reader[section]["value"]

        clean_payload = payload.strip(" \n")
        clean_payload = clean_payload.replace("[TAB]", "\t")
        clean_payload = clean_payload.replace("[LF]", "\n")
        clean_payload = clean_payload.replace("[EXTERNAL_ENDPOINT]", external_endpoint)
        clean_payload = clean_payload.replace("[PROTO_ENDPOINT]", proto_endpoint)

        clean_value = value.replace("[EXTERNAL_ENDPOINT]", external_endpoint)
        clean_value = clean_value.replace("[PROTO_ENDPOINT]", proto_endpoint)

        infos = {
            "name": section,
            "payload": clean_payload,
            "tag": config_reader[section]["tag"].split(","),
            "attribute": config_reader[section]["attribute"],
            "value": clean_value,
            "case_sensitive": config_reader.getboolean(section, "case_sensitive", fallback=True),
            "close_tag": config_reader.getboolean(section, "close_tag", fallback=True)
        }

        if "requirements" in config_reader[section]:
            infos["requirements"] = set(config_reader[section]["requirements"].split(","))

        payloads.append(infos)

    return payloads


def meet_requirements(payload_requirements, special_attributes):
    # payload_requirements is a set of attr_name or attr_name=value strings
    payload_prefix = ""
    for requirement in payload_requirements:
        if "!" not in requirement and requirement not in special_attributes:  # Condition not met but we may fix it
            if "=" in requirement:
                # Hardest case: Make sure there isn't an attribute with the same name but different value (conflict)
                expected_attribute, expected_value = requirement.split("=")
                if any(attribute.startswith(expected_attribute + "=") for attribute in special_attributes):
                    raise RuntimeError("Requirement cannot be met")
            else:
                # We just name the attribute to appear whatever the value
                expected_attribute = requirement
                expected_value = "z"  # Can be anything

            payload_prefix += f"[ATTR_SEP]{expected_attribute}=[VALUE_SEP]{expected_value}"
        elif "!" in requirement:
            if requirement.replace("!", "") in special_attributes:
                raise RuntimeError("Requirement cannot be met")

    return payload_prefix


def apply_attrval_context(context, payloads, code):
    # Our string is in the value of a tag attribute
    # ex: <a href="our_string"></a>
    result = []

    for payload_infos in payloads:
        if not payload_infos["close_tag"]:
            # Payload keeping the tag open
            if context["tag"] in payload_infos["tag"] and payload_infos["attribute"] not in context["events"]:
                if not context["separator"]:
                    attr_separator = " "
                    value_separator = ""
                else:
                    attr_separator = value_separator = context["separator"]

                if (
                        (set(payload_infos["tag"]) & {"frame", "iframe"} and payload_infos["attribute"] == "src") or
                        (payload_infos["tag"] == ["a"] and payload_infos["attribute"] == "href")
                ):
                    # This is a special case... Maybe we should improve that kind of behavior by having something
                    # similar to the match_type (from xssPayloads.ini) in the context
                    js_code = payload_infos["payload"].replace("__XSS__", code)
                else:
                    try:
                        js_code = "y"  # Not empty value to force non-fuzzy HTML interpretation
                        js_code += meet_requirements(
                            payload_infos.get("requirements", []),
                            context.get("special_attributes", [])
                        )
                        js_code += payload_infos["payload"].replace("__XSS__", code)
                        js_code = js_code.replace("[ATTR_SEP]", attr_separator)
                        js_code = js_code.replace("[VALUE_SEP]", value_separator)
                    except RuntimeError:
                        continue

                result.append(
                    (js_code, Flags(payload_type=PayloadType.xss_non_closing_tag, section=payload_infos["name"]))
                )

        else:
            js_code = context["separator"]
            # we must deal differently with self-closing tags
            # see https://developer.mozilla.org/en-US/docs/Glossary/empty_element for reference
            if context["tag"].lower() in [
                    "area", "base", "br", "col", "embed", "hr", "img", "input", "keygen", "link", "meta", "param",
                    "source", "track", "wbr",
                    "frame"  # Not in Mozilla list but I guess it is because it is deprecated
            ]:
                # We don't even need a slash to mark the end of the tag
                js_code += ">"
            else:
                js_code += "></" + context["tag"] + ">"

            if context["non_exec_parent"] == "frameset":
                if payload_infos["tag"] != ["frame"]:
                    continue
            elif context["non_exec_parent"]:
                js_code += "</" + context["non_exec_parent"] + ">"

            js_code += payload_infos["payload"].replace("__XSS__", code)
            result.append((js_code, Flags(payload_type=PayloadType.xss_closing_tag, section=payload_infos["name"])))

    return result


def apply_attrname_context(context, payloads, code):
    # we control an attribute name
    # ex: <a our_string="/index.html">
    result = []

    if code == context["name"]:
        for payload_infos in payloads:
            if not payload_infos["close_tag"]:
                # do new stuff
                pass
            else:
                js_code = '>'
                if context["non_exec_parent"]:
                    js_code += "</" + context["non_exec_parent"] + ">"
                js_code += payload_infos["payload"].replace("__XSS__", code)

                result.append((js_code, Flags(payload_type=PayloadType.xss_closing_tag, section=payload_infos["name"])))

    return result


def apply_tagname_context(context, payloads, code):
    # we control the tag name
    # ex: <our_string name="column" />
    result = []

    if context["value"].startswith(code):
        for payload_infos in payloads:
            if not payload_infos["close_tag"]:
                # do new stuff
                pass
            else:
                js_code = ""
                if context["non_exec_parent"]:
                    js_code += "</" + context["non_exec_parent"] + ">"
                js_code += payload_infos["payload"].replace("__XSS__", code)

                js_code = js_code[1:]  # use independent payloads, just remove the first character (<)
                result.append((js_code, Flags(payload_type=PayloadType.xss_closing_tag, section=payload_infos["name"])))
    else:
        for payload_infos in payloads:
            if not payload_infos["close_tag"]:
                # do new stuff
                pass
            else:
                js_code = "/>"
                if context["non_exec_parent"]:
                    js_code += "</" + context["non_exec_parent"] + ">"
                js_code += payload_infos["payload"].replace("__XSS__", code)
                result.append((js_code, Flags(payload_type=PayloadType.xss_closing_tag, section=payload_infos["name"])))

    return result


def apply_text_context(context, payloads, code):
    # we control the text of the tag
    # ex: <textarea>our_string</textarea>
    result = []
    prefix = ""

    if context["parent"] in ["script", "title", "textarea", "style"]:
        # we can't execute javascript under title or textarea tags and it's too hard to be sure our payload
        # will be executed if we have partial control over a script tag content, so let's escape them
        if context["non_exec_parent"] != "":
            prefix = "</" + context["non_exec_parent"] + ">"
        else:
            prefix = f"</{context['parent']}>"

    for payload_infos in payloads:
        if not payload_infos["close_tag"]:
            # do new stuff
            pass
        else:
            js_code = prefix + payload_infos["payload"].replace("__XSS__", code)
            result.append((js_code, Flags(payload_type=PayloadType.xss_closing_tag, section=payload_infos["name"])))

    return result


def apply_comment_context(context, payloads, code):
    # Injection occurred in a comment tag
    # ex: <!-- <div> whatever our_string blablah </div> -->
    result = []

    prefix = "-->"
    if context["parent"] in ["script", "title", "textarea"]:
        # we can't execute javascript under title or textarea tags and it's too hard to be sure our payload
        # will be executed if we have partial control over a script tag content, so let's escape them
        if context["non_exec_parent"] != "":
            prefix += f"</{context['non_exec_parent']}>"
        else:
            prefix += f"</{context['parent']}>"

    for payload_infos in payloads:
        if not payload_infos["close_tag"]:
            # do new stuff
            pass
        else:
            js_code = prefix + payload_infos["payload"].replace("__XSS__", code)
            result.append((js_code, Flags(payload_type=PayloadType.xss_closing_tag, section=payload_infos["name"])))

    return result


def apply_context(context, payloads, code):
    
    func = {
        "attrval": apply_attrval_context,
        "attrname": apply_attrname_context,
        "tag": apply_tagname_context,
        "text": apply_text_context,
        "comment": apply_comment_context
    }[context["type"]]


    return func(context, payloads, code)


# generate a list of payloads based on where in the webpage the js-code will be injected
def generate_payloads(html_code, code, payload_file, external_endpoint="http://wapiti3.ovh/"):
    # We must keep the original source code because bs gives us something that may differ...
    context_list = get_context_list(html_code, code.rstrip('\x00').rstrip('\n'))
    print(context_list)

    
    if context_list == []:    
        if "'" in code: 
            split_index = code.find("'")
        elif '"' in code:
            split_index = code.find('"')
        else: 
            split_index = -1
        if split_index != -1:
            split_payload =  code[split_index+1:].rstrip('\x00').rstrip('\n')
            context_list = get_context_list(html_code, split_payload)
            
    payload_list = load_payloads_from_ini(payload_file, external_endpoint)
    
    payloads_and_flags = []
    
    

    for context in context_list:

        for context_payload in apply_context(context, payload_list, code):
            if context_payload not in payloads_and_flags:
                payloads_and_flags.append(context_payload)

    
        
    return payloads_and_flags


def valid_xss_content_type(response):
    """Check whether the returned content-type header allow javascript evaluation."""
    # When no content-type is returned, browsers try to display the HTML
    if "content-type" not in response.headers:
        return True

    # else only text/html will allow javascript (maybe text/plain will work for IE...)
    if "text/html" in response.headers["content-type"]:
        return True
    return False


def compare(left_value: str, right_value: str, method: str, case_sensitive: bool = True):
    """Compare two strings given a comparison method and case sensitivity"""
    if not case_sensitive:
        left_value = left_value.lower()
        right_value = right_value.lower()

    if method == "exact":
        return left_value == right_value
    if method == "starts_with":
        return left_value.startswith(right_value)

    raise ValueError(f"Unsupported comparison method {method}")



class Mutator:
    def __init__(
            self, methods="FGP", payloads=None, qs_inject=False, max_queries_per_pattern: int = 1000,
            parameters=None,  # Restrict attack to a whitelist of parameters
            skip=None  # Must not attack those parameters (blacklist)
    ):
        self._mutate_get = "G" in methods.upper()
        self._mutate_file = "F" in methods.upper()
        self._mutate_post = "P" in methods.upper()
        self._payloads = payloads
        self._qs_inject = qs_inject
        self._attacks_per_url_pattern = defaultdict(int)
        self._max_queries_per_pattern = max_queries_per_pattern
        self._parameters = parameters if isinstance(parameters, list) else []
        self._skip_list = skip if isinstance(skip, set) else set()
        self._attack_hashes = set()
        self._skip_list.update(COMMON_ANNOYING_PARAMETERS)

    def iter_payloads(self):
        # raise tuples of (payloads, flags)
        if isinstance(self._payloads, tuple):
            yield self._payloads
        elif isinstance(self._payloads, (list, GeneratorType)):
            yield from self._payloads
        elif isinstance(self._payloads, FunctionType):
            result = self._payloads()
            if isinstance(result, GeneratorType):
                yield from result
            else:
                yield result

    def mutate(self, request: Request):
        get_params = request.get_params
        post_params = request.post_params
        file_params = request.file_params
        referer = request.referer

        for params_list in [get_params, post_params, file_params]:
            if params_list is get_params and not self._mutate_get:
                continue

            if params_list is post_params and not self._mutate_post:
                continue

            if params_list is file_params and not self._mutate_file:
                continue

            for i in range(len(params_list)):
                param_name = quote(params_list[i][0])

                if self._skip_list and param_name in self._skip_list:
                    continue

                if self._parameters and param_name not in self._parameters:
                    continue

                saved_value = params_list[i][1]
                if saved_value is None:
                    saved_value = ""

                if params_list is file_params:
                    params_list[i][1] = ["__PAYLOAD__", params_list[i][1][1]]  # second entry is file content
                else:
                    params_list[i][1] = "__PAYLOAD__"

                attack_pattern = Request(
                    request.path,
                    method=request.method,
                    get_params=get_params,
                    post_params=post_params,
                    file_params=file_params
                )

                if hash(attack_pattern) not in self._attack_hashes:
                    self._attack_hashes.add(hash(attack_pattern))

                    for payload, original_flags in self.iter_payloads():

                        if ("[FILE_NAME]" in payload or "[FILE_NOEXT]" in payload) and not request.file_name:
                            continue

                        # no quoting: send() will do it for us
                        payload = payload.replace("[FILE_NAME]", request.file_name)
                        payload = payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])

                        if isinstance(request.path_id, int):
                            payload = payload.replace("[PATH_ID]", str(request.path_id))

                        payload = payload.replace(
                            "[PARAM_AS_HEX]",
                            hexlify(param_name.encode("utf-8", errors="replace")).decode()
                        )

                        if params_list is file_params:
                            if "[EXTVALUE]" in payload:
                                if "." not in saved_value[0][:-1]:
                                    # Nothing that looks like an extension, skip the payload
                                    continue
                                payload = payload.replace("[EXTVALUE]", saved_value[0].rsplit(".", 1)[-1])

                            # Injection takes place on the filename here
                            payload = payload.replace("[VALUE]", saved_value[0])
                            payload = payload.replace("[DIRVALUE]", saved_value[0].rsplit('/', 1)[0])
                            params_list[i][1] = (payload, saved_value[1], saved_value[2])
                            method = PayloadType.file
                        else:
                            if "[EXTVALUE]" in payload:
                                if "." not in saved_value[:-1]:
                                    # Nothing that looks like an extension, skip the payload
                                    continue
                                payload = payload.replace("[EXTVALUE]", saved_value.rsplit(".", 1)[-1])

                            payload = payload.replace("[VALUE]", saved_value)
                            payload = payload.replace("[DIRVALUE]", saved_value.rsplit('/', 1)[0])
                            params_list[i][1] = payload
                            if params_list is get_params:
                                method = PayloadType.get
                            else:
                                method = PayloadType.post

                        evil_req = Request(
                            request.path,
                            method=request.method,
                            get_params=get_params,
                            post_params=post_params,
                            file_params=file_params,
                            referer=referer,
                            link_depth=request.link_depth
                        )
                        # Flags from iter_payloads should be considered as mutable (even if it's ot the case)
                        # so let's copy them just to be sure we don't mess with them.
                        yield evil_req, param_name, payload, original_flags.with_method(method)

                params_list[i][1] = saved_value

        if not get_params and request.method == "GET" and self._qs_inject:
            attack_pattern = Request(
                "{}?__PAYLOAD__".format(request.path),
                method=request.method,
                referer=referer,
                link_depth=request.link_depth
            )

            if hash(attack_pattern) not in self._attack_hashes:
                self._attack_hashes.add(hash(attack_pattern))

                for payload, original_flags in self.iter_payloads():
                    # Ignore payloads reusing existing parameter values
                    if "[VALUE]" in payload:
                        continue

                    if "[DIRVALUE]" in payload:
                        continue

                    if ("[FILE_NAME]" in payload or "[FILE_NOEXT]" in payload) and not request.file_name:
                        continue

                    payload = payload.replace("[FILE_NAME]", request.file_name)
                    payload = payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])

                    if isinstance(request.path_id, int):
                        payload = payload.replace("[PATH_ID]", str(request.path_id))

                    payload = payload.replace(
                        "[PARAM_AS_HEX]",
                        hexlify(b"QUERY_STRING").decode()
                    )

                    evil_req = Request(
                        "{}?{}".format(request.path, quote(payload)),
                        method=request.method,
                        referer=referer,
                        link_depth=request.link_depth
                    )

                    yield evil_req, "QUERY_STRING", payload, original_flags.with_method(PayloadType.get)


class FileMutator:
    def __init__(self, payloads=None, parameters=None, skip=None):
        self._payloads = payloads
        self._attack_hashes = set()
        self._parameters = parameters if isinstance(parameters, list) else []
        self._skip_list = skip if isinstance(skip, set) else set()

    def iter_payloads(self):
        # raise tuples of (payloads, flags)
        if isinstance(self._payloads, tuple):
            yield self._payloads
        elif isinstance(self._payloads, (list, GeneratorType)):
            yield from self._payloads
        elif isinstance(self._payloads, FunctionType):
            result = self._payloads()
            if isinstance(result, GeneratorType):
                yield from result
            else:
                yield result

    def mutate(self, request: Request):
        get_params = request.get_params
        post_params = request.post_params
        referer = request.referer

        for i in range(len(request.file_params)):
            new_params = request.file_params
            param_name = new_params[i][0]

            if self._skip_list and param_name in self._skip_list:
                continue

            if self._parameters and param_name not in self._parameters:
                continue

            for payload, original_flags in self.iter_payloads():

                if ("[FILE_NAME]" in payload or "[FILE_NOEXT]" in payload) and not request.file_name:
                    continue

                # no quoting: send() will do it for us
                payload = payload.replace("[FILE_NAME]", request.file_name)
                payload = payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])

                if isinstance(request.path_id, int):
                    payload = payload.replace("[PATH_ID]", str(request.path_id))

                payload = payload.replace(
                    "[PARAM_AS_HEX]",
                    hexlify(param_name.encode("utf-8", errors="replace")).decode()
                )

                new_params[i][1] = ("content.xml", payload, "text/xml")

                evil_req = Request(
                    request.path,
                    method=request.method,
                    get_params=get_params,
                    post_params=post_params,
                    file_params=new_params,
                    referer=referer,
                    link_depth=request.link_depth
                )
                # Flags from iter_payloads should be considered as mutable (even if it's ot the case)
                # so let's copy them just to be sure we don't mess with them.
                yield evil_req, param_name, payload, original_flags.with_method(PayloadType.file)


class PayloadReader:
    """Class for reading and writing in text files"""

    def __init__(self):
        self._timeout = 4
        self._endpoint_url = "http://wapiti3.ovh/"

    def read_payloads(self, filename):
        """returns a array"""
        lines = []
        try:
            with open(filename, errors="ignore") as file:
                for line in file:
                    clean_line, flags = self.process_line(line)
                    if clean_line:
                        lines.append((clean_line, flags))
        except IOError as exception:
            print(exception)
        return lines

    def process_line(self, line):
        flag_type = PayloadType.pattern
        clean_line = line.strip(" \n")
        clean_line = clean_line.replace("[TAB]", "\t")
        clean_line = clean_line.replace("[LF]", "\n")
        clean_line = clean_line.replace("[FF]", "\f")  # Form feed
        clean_line = clean_line.replace("[TIME]", str(int(ceil(self._timeout)) + 1))
        clean_line = clean_line.replace("[EXTERNAL_ENDPOINT]", self._endpoint_url)

        if "[TIMEOUT]" in clean_line:
            flag_type = PayloadType.time
            clean_line = clean_line.replace("[TIMEOUT]", "")

        clean_line = clean_line.replace("\\0", "\0")

        return clean_line, Flags(payload_type=flag_type)

