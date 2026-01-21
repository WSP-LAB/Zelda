
import os
import time

from random import seed
from random import random
from random import randint
from random import choice
import string

SPECIAL_CHAR = ["'", '"', "/", "("]

class WebInput:
  def __init__(self, param_dict):
    self._input_dict = param_dict
    
    self._input_dict["GET-ownurl"] = (len(param_dict), "")
    self._input_dict["GET-ownreferer"] =  (len(param_dict), "")
    self._input_dict["GET-owncookie"] =  (len(param_dict), "")
    self._input_dict["GET-ownuseragent"] =  (len(param_dict), "")

    self._max_bytes = 32
    # input_bytes = | GET/POST parameters | URL | Referer Header | Cookie | User-Agent
    self._input_bytes = bytearray(len(self._input_dict)*self._max_bytes)
    self._pos_dict = {}
    for k, (pos, v) in self._input_dict.items():
      self._pos_dict[pos] = ("GET", k)
    seed(time.time())



  def Encode(self):
    for k, (pos, v) in self._input_dict.items():
      byte_pos = pos * self._max_bytes
      try:
        for b in v.encode('ascii'):#to_bytes(self._max_bytes, byteorder='little'):
          #print("Byte pos:", byte_pos, " b: ", b, ", Type:", type(b))
          #self._input_bytes[byte_pos:byte_pos+1] = b.to_bytes(1, byteorder='little')[0:1]
          self._input_bytes[byte_pos] = b
          byte_pos += 1
      except:
        pass
      #self._input_bytes[byte_pos:byte_pos+self._max_bytes] = v.to_bytes(self._max_bytes, byteorder='little')[:]

    #print("Encode: ", self._input_bytes)
    return self._input_bytes

  def Mutation(self, idx):
    key = list(self._input_dict.keys())[idx]
    value = self._input_dict[key][1]
    
    # special cases
    if value == "":
      self.CreateFlag(idx)
    random_value = random()
    #print(random_value)
    # parameter name
    if random_value < 0.18:
      if "email" in key: 
        self.SpecialCases(idx, "email")
      elif "phone" in key:
        self.SpecialCases(idx, "phone")
      elif "name" in key:
        self.SpecialCases(idx, "name")
      elif "url" in key:
        self.SpecialCases(idx, "url")
      elif "referer" in key:
        self.SpecialCases(idx, "referer")
    # value mutation
    elif random_value  < 0.36 :
      self.InjectSpecialChar(idx)
    elif random_value  < 0.54:
      self.NumberMuation(idx)
    elif random_value  < 0.72:
      self.StringMutate(idx)
    elif random_value  < 0.90:
      self.RandomByteMutate(idx)
    elif random_value  < 1:
      self.ClearInput(idx)
  
  def ClearInput(self, idx):
    for i in range(idx * self._max_bytes, (idx + 1) * self._max_bytes):

      self._input_bytes[i] = 0

  def StringMutate(self, idx):
    result = ""
    string_pool = string.ascii_lowercase 
    length = randint(1, 10)
    for i in range(length):
        result += choice(string_pool) 
    byte_pos = idx * self._max_bytes
    # convert the mutated value to byte array
    for x in result.encode():
      self._input_bytes[byte_pos] = x
      byte_pos += 1

  def CreateFlag(self, idx):
    result = ""
    string_pool = string.ascii_lowercase 
    for i in range(10):
      result += choice(string_pool) 
    
    result += str(randint(0,50000))
    byte_pos = idx * self._max_bytes
    # convert the mutated value to byte array
    for x in result.encode():
      self._input_bytes[byte_pos] = x
      byte_pos += 1

  def RandomByteMutate(self, idx):
    for i in range(idx * self._max_bytes, (idx + 1) * self._max_bytes):
      p = random()
      if p > 0.6:
        if self._input_bytes[i] != 0:
          self._input_bytes[i] = randint(0, 255)
    #print("After Mutation=>", self._input_bytes)

  def StringMutation(self, idx):
    pass 
  
  def IntegerToBytes(self, num):
    pass 

  def StringToBytes(self, string_value):
    pass
  
  def InjectSpecialChar(self, idx):

    result_list = list(self.DecodeAsList()[idx]) 
    i = 0
    for c in SPECIAL_CHAR:
      result_list[i] = c 
      i += 1
    #result_list[-1]= "\\"
    byte_pos = idx * self._max_bytes
    # convert the mutated value to byte array
    result = "".join(result_list)

    for x in result.encode():
      #print(x)
      self._input_bytes[byte_pos] = x
      byte_pos += 1

  def NumberMuation(self, idx):
    random_num = randint(0,50000)
    byte_pos = idx * self._max_bytes
    # convert the mutated value to byte array
    for x in str(random_num).encode():
      self._input_bytes[byte_pos] = x
      byte_pos += 1

  def InjectKeyword(self, idx):
    keywordFile = open("../fuzz/data/actionKeywords.txt", "r")
    actionKeywords = keywordFile.readlines() 
    
    actionKeyword = choice(actionKeywords)
    byte_pos = idx * self._max_bytes
    # convert the mutated value to byte array
    for x in actionKeyword.encode():
      self._input_bytes[byte_pos] = x
      byte_pos += 1

  def SpecialCases(self, idx, type):
    result = ""
    string_pool = string.ascii_lowercase 
    if type ==  "email":
      
      for i in range(15):
        result += choice(string_pool) 
        if i == 6:
          result += "@"
        if i == 11:
          result += "."
    if type == "name":
      result = ""
      for i in range(10):
        result += choice(string_pool) 
    if type == "phone":
      result = str(randint(0,50000))
    if type == "url":
      result = ""
      for i in range(10):
        result += choice(string_pool) 
    if type == "referer":
      result = ""
      for i in range(10):
        result += choice(string_pool) 
    byte_pos = idx * self._max_bytes
    # convert the mutated value to byte array
    for x in result.encode():
      self._input_bytes[byte_pos] = x
      byte_pos += 1
    
    
  def Decode(self, input_bytearray):
    iteration = int(len(input_bytearray) / self._max_bytes)
    for i in range(iteration):
      start_idx = self._max_bytes * i
      end_idx = start_idx + self._max_bytes
      #print(start_idx, end_idx)
      #print(input_bytearray[start_idx:end_idx].decode('ascii',errors='ignore'))
  
  def DecodeAsSessionParams(self):
    #given_url += "?"
    params = {}
    iteration = int(len(self._input_bytes) / self._max_bytes)
    for i in range(iteration):
      start_idx = self._max_bytes * i
      end_idx = start_idx + self._max_bytes
      #print(start_idx, end_idx)
      try:
        (type, url_key) = self._pos_dict[i]
        params[url_key[4:]] = self._input_bytes[start_idx:end_idx].decode('ascii', errors='ignore').replace('\00', '')
      except:
        pass
      #print("Pos: ", i, ", URL_KEY:", url_key)
      
        #print("start idx: ", start_idx, ":", end_idx)  
        #given_url += (url_key[4:] + "=" + self._input_bytes[start_idx:end_idx].decode('ascii', errors='ignore').replace('\00', '') + "&")
      
    return params

  def DecodeAsList(self):
    input_list = []
    iteration = int(len(self._input_bytes) / self._max_bytes)
    for i in range(iteration):
      start_idx = self._max_bytes * i
      end_idx = start_idx + self._max_bytes
      #print(start_idx, end_idx)
      try:
        (type, url_key) = self._pos_dict[i]
        #print("Pos: ", i, ", URL_KEY:", url_key)
        input_list.append(self._input_bytes[start_idx:end_idx].decode('ascii', errors='ignore'))
      except:
        pass
    return input_list
    
if __name__ == '__main__':
  param_dict = {'GET-int': (0, '123'), 'GET-id': (1, '24')}
  wi = WebInput(param_dict)
  encoded = wi.Encode()
  prefix_url = "http://localhost/target"
  wi.Decode(encoded)
  
  given_url = wi.DecodeAsSessionParams(prefix_url)

  print("InitialURL=>", given_url)
 
  for i in range(100):
    wi.RandomByteMutate()
    given_url = wi.DecodeAsSessionParams(prefix_url)
    print("=>", given_url)

