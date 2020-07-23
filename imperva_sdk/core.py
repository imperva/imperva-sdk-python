# Copyright 2018 Imperva. All rights reserved.

import re
import os
import copy
import json
valid_string_pattern = re.compile(r'^[a-zA-Z0-9 _\.\'\-\[\]\,\(\)\:\+\#]*$')

#
# In "imperva_sdk", all Class parameters start with a capital letter.
# This is done to differentiate them from Class functions and other internal variables (export/import purposes).
# For example, if the "server group" API has an "operationMode" parameter - in "imperva_sdk" it will be called "OperationMode"
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
    return "<imperva_sdk '%s' Object - '%s'>" % (type(self).__name__, self.Name)

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
          if child:
            iters[child_title].append(dict(child))
          else:
            print("Child of <imperva_sdk '%s' Object - '%s'> is null" % (type(self).__name__, self.Name))
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

def imperva_sdk_version():
  try:
    here = os.path.abspath(os.path.dirname(__file__))
    with open(here + '/__init__.py', 'r') as fd:
      version_file = fd.read()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
      return version_match.group(1)
  except:
    pass
  return "Error getting imperva_sdk version"
  
# Utility Functions
    
def ReplaceFollowedAction(http1xProtPol,followedActionName):
    if type(http1xProtPol) is list:
        for item in http1xProtPol:
            ReplaceFollowedAction(item,followedActionName)
    elif type(http1xProtPol) is dict:
        for key in http1xProtPol:
            if type(key) is str and key == 'followedAction':
                http1xProtPol[key] = followedActionName
            else:
                ReplaceFollowedAction(http1xProtPol[key],followedActionName)

def AddOperationToListDict(applyToListDict):
    if type(applyToListDict) == list:
        # we assume a list of dictionaries
        for applyToDict in applyToListDict:
            applyToDict['operation'] = 'add'
    elif type(applyToListDict) == dict:
        applyToListDict['operation'] = 'add'
    else:
        raise Exception('AddOperationToListDict - applyToListDict is not a list of dict ! :' + str(applyToListDict))
    return applyToListDict

def GetSiteSgServices(mx, siteName):
    sgs = mx.get_all_server_groups(Site=siteName)
    siteSgSrvDict = {}
    siteSgSrvDictList = []
    for sg in sgs:
        services = mx.get_all_web_services(ServerGroup=sg.Name, Site=siteName)
        for service in services:
            siteSgSrvDict['siteName'] = siteName
            siteSgSrvDict['serverGroupName'] = sg.Name
            siteSgSrvDict['webServiceName'] = service.Name
            siteSgSrvDictList.append(copy.deepcopy(siteSgSrvDict))
    return siteSgSrvDictList[0] if len(siteSgSrvDictList) == 1 else siteSgSrvDictList

def GetAllApplyTo(mx):
    applyTo = []
    sites = mx.get_all_sites()
    for site in sites:
        applyToItem = GetSiteSgServices(mx, site.Name)
        if len(applyToItem) != 0:
            if type(applyToItem) is list:
                applyTo += copy.deepcopy(applyToItem)
            elif type(applyToItem) is dict:
                applyTo.append(copy.deepcopy(applyToItem))
            else:
                raise Exception('In GetAllApplyTo: applyToItem not a list nor a dict!')           
    return applyTo

def CurateApplyTo(mx, http1xProtPol):
    http1xProtPol['applyTo'] = GetAllApplyTo(mx)
    AddOperationToListDict(http1xProtPol['applyTo'])
    return http1xProtPol

# example:    response = self._mx_api('GET', '/conf/systemDefinitions/httpProxy'); so urlBase starts w/ /conf
def GetPolicy(mx,urlBase,polName):
  return mx._mx_api('GET', urlBase + '/%s' % polName)

def PostPutPolicy(mx,dictBody,urlBase,polName):
  retPol = False
  try:
    mx._mx_api('POST', urlBase + '/%s' % polName, data=json.dumps(dictBody))
    retPol = True
  except Exception as e: 
    print("An error was thrown by POST on policy: " + polName + "Error: " + str(e) + "; trying a PUT...")
    try:
      mx._mx_api('PUT',  urlBase + '/%s' % polName, data=json.dumps(dictBody))
      retPol = True
    except Exception as e:
      print("An error was thrown by PUT on policy: " + polName + "Error: " + str(e) + "; This has to be fixed...")
      retPol = False
  return retPol

def PolicyNameContainsToken(strTokens, pol):
    rez = False
    for strToken in strTokens:
        if strToken.lower() in pol.lower():
            rez = True
    return rez
 
def EnableRules(rules):
    lRules = copy.deepcopy(list(rules))
    for ruleDict in lRules:
        assert type(ruleDict) == dict 
        ruleDict['enabled'] = True
    return lRules 

def SetFollowedAction(rules,followedAction):
    lRules = copy.deepcopy(list(rules))
    for ruleDict in lRules:
        assert type(ruleDict) == dict 
        ruleDict['followedAction'] = followedAction
    return lRules 


