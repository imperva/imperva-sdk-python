# Copyright 2018 Imperva. All rights reserved.

import re
import os

valid_string_pattern  = re.compile(r'^[a-zA-Z0-9 _\.\'\-\[\]\,\(\)\:\+]*$')

#
# In "imperva-sdk", all Class parameters start with a capital letter.
# This is done to differentiate them from Class functions and other internal variables (export/import purposes).
# For example, if the "server group" API has an "operationMode" parameter - in "imperva-sdk" it will be called "OperationMode"
#
is_parameter = re.compile(r'^[A-Z].*$')

class MxObject(object):
  ''' Parent MX Class '''
  
  def __init__(self, connection=None, Name=None):
    if not connection.IsAuthenticated:
      raise MxException("Object must have an active MX connection")
    validate_string(Name=Name)
    self._Name = Name
    self._connection = connection

  def __repr__(self):
    return "<imperva-sdk '%s' Object - '%s'>" % (type(self).__name__, self.Name)

  # Recursive dictionary representation of the MX object (used for JSON export/import) 
  def __iter__(self):
    iters = {}
    for field in dir(self):
      # Only variables should start with a capital letter
      if is_parameter.match(field):
        variable_function = getattr(self, field)
        iters[field] = variable_function
      # If the object has a "get_all" function, we need to build the child objects
      elif field.startswith('get_all_'):
        child_title = field.replace('get_all_', '')
        iters[child_title] = []
        get_all_function = getattr(self, field)
        children = get_all_function()
        for child in children:
          iters[child_title].append(dict(child))
    for x,y in iters.items():
      yield x, y
      
def validate_string(**kwargs):
  for param in kwargs:
    if not kwargs[param]:
      raise MxException("Missing parameter - '%s'" % param)
    if not valid_string_pattern.match(kwargs[param]):
      raise MxException("Invalid string value for parameter - '%s - %s'" % (param, kwargs[param]))
  return True

class MxException(Exception):
	pass
class MxExceptionNotFound(Exception):
	pass

class MxList(list):
  def append(self, item):
    raise MxException('No appending allowed.')
  def remove(self, item):
    raise MxException('No removing allowed.')

def imperva-sdk_version():
  try:
    here = os.path.abspath(os.path.dirname(__file__))
    with open(here + '/__init__.py', 'r') as fd:
      version_file = fd.read()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
      return version_match.group(1)
  except:
    pass
  return "Error getting imperva-sdk version"
  
