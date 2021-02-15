
import os
class staticTaintManager:

   def loadMappings(self):
      file_path = './' + self.file_name
      if os.path.exists(file_path):
          with open(file_path, 'r') as f:
          	lines = f.readlines()
          	for line in lines:
          	    tokens = line.rstrip("\n").split(" ")
          	    func_name = tokens[0]
          	    in_out_taints = (tokens[1], tokens[2])
          	    #print("[LOG] type of in_out: ", type(in_out_taints))
          	    self.stMapper[func_name] = in_out_taints


   def __init__(self):
      self.file_name = "stmMappings.txt"
      self.stMapper = {}
      self.loadMappings()

   def get_taints(self, func_name, current_taint):
       if current_taint == "High":
          taint = self.stMapper[func_name][1]
          return taint
       else:
          return current_taint
