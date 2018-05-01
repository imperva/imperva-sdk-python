# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class WebApplication(MxObject):
  ''' 
  MX Web Application Class 

  >>> wa = ws.get_web_application("Default Web Application")
  >>> wa.Name = "web application name"                                                                  
  >>> wa.LearnSettings
  u'LearnAll'
  >>> wa.LearnSettings = 'LearnAllExceptStatics'

  '''
  
  # Store created WebApplication objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = WebApplication._exists(connection=kwargs['connection'], Site=kwargs['Site'], ServerGroup=kwargs['ServerGroup'], WebService=kwargs['WebService'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None, Site=None, ServerGroup=None, WebService=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'WebApplication':
        if cur_obj.Name == Name and cur_obj._Site == Site and cur_obj._ServerGroup == ServerGroup and cur_obj._WebService == WebService:
          return cur_obj
    return None
  
  def __init__(self, connection=None, WebService=None, Name=None, ServerGroup=None, Site=None, LearnSettings=None, ParseOcspRequests=False, RestrictMonitoringToUrls=None, IgnoreUrlsDirectories=None, Mappings=[]):
    super(WebApplication, self).__init__(connection=connection, Name=Name)
    validate_string(WebService=WebService, Site=Site, ServerGroup=ServerGroup, Name=Name)
    self._Name = Name
    self._Site = Site
    self._ServerGroup = ServerGroup
    self._WebService = WebService
    self._LearnSettings = LearnSettings
    self._ParseOcspRequests = ParseOcspRequests
    self._RestrictMonitoringToUrls = RestrictMonitoringToUrls
    self._IgnoreUrlsDirectories = IgnoreUrlsDirectories
    self._Mappings = Mappings

  # Overriding iter (dict) function to handle profile and mappings properly
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
    try:
      iters["Profile"] = self.get_profile()
    except MxExceptionNotFound:
      # Probably working with old version of MX that doesn't have profile APIs
      pass
    for x,y in iters.items():
      yield x, y

  #
  # Web Application parameters
  # 
  @property
  def Name(self):
    ''' Web Application name (string) '''
    return self._Name
  @property
  def LearnSettings(self):
    ''' Web Application parameter learn mode ('LearnAll', 'LearnAllExceptStatics' or 'LearnUrlsWithParams') '''
    return self._LearnSettings
  @property
  def ParseOcspRequests(self):
    ''' Indicates whether to parse OCSP requests for this application (boolean). Default=False '''
    return self._ParseOcspRequests
  @property
  def RestrictMonitoringToUrls(self):
    ''' Name of URL Prefixes / Directory Group global object that restricts monitoring to these URLs (string) '''
    return self._RestrictMonitoringToUrls
  @property
  def IgnoreUrlsDirectories(self):
    ''' Name of URL Prefixes / Directory Group global object of URLs to ignore (string) '''
    return self._IgnoreUrlsDirectories
  @property
  def Mappings(self):
    ''' 
    Host to Application mappings (taken from service to application level) 

    >>> app.Mappings
    [{ "priority": 1, "host": "www.myapp.com", "hostMatchType": "Exact" }]
 
    '''
    return self._Mappings
  @Name.setter
  def Name(self, Name):
    if Name != self._Name:
      self._connection._update_web_application(Name=self._Name, Site=self._Site, ServerGroup=self._ServerGroup, WebService=self._WebService, Parameter='appName', Value=Name)
      self._Name = Name
  @LearnSettings.setter
  def LearnSettings(self, LearnSettings):
    if LearnSettings != self._LearnSettings:
      self._connection._update_web_application(Name=self._Name, Site=self._Site, ServerGroup=self._ServerGroup, WebService=self._WebService, Parameter='learnSettings', Value=LearnSettings)
      self._LearnSettings = LearnSettings
  @ParseOcspRequests.setter
  def ParseOcspRequests(self, ParseOcspRequests):
    if ParseOcspRequests != self._ParseOcspRequests:
      self._connection._update_web_application(Name=self._Name, Site=self._Site, ServerGroup=self._ServerGroup, WebService=self._WebService, Parameter='parseOCSPRequests', Value=ParseOcspRequests)
      self._ParseOcspRequests = ParseOcspRequests
  @RestrictMonitoringToUrls.setter
  def RestrictMonitoringToUrls(self, RestrictMonitoringToUrls):
    if RestrictMonitoringToUrls != self._RestrictMonitoringToUrls:
      self._connection._update_web_application(Name=self._Name, Site=self._Site, ServerGroup=self._ServerGroup, WebService=self._WebService, Parameter='restrictMonitoringToUrls', Value=RestrictMonitoringToUrls)
      self._RestrictMonitoringToUrls = RestrictMonitoringToUrls
  @IgnoreUrlsDirectories.setter
  def IgnoreUrlsDirectories(self, IgnoreUrlsDirectories):
    if IgnoreUrlsDirectories != self._IgnoreUrlsDirectories:
      self._connection._update_web_application(Name=self._Name, Site=self._Site, ServerGroup=self._ServerGroup, WebService=self._WebService, Parameter='ignoreUrlsDirectories', Value=IgnoreUrlsDirectories)
      self._IgnoreUrlsDirectories = IgnoreUrlsDirectories
  @Mappings.setter
  def Mappings(self, Mappings):
    for old_map in self._Mappings:
      if old_map not in Mappings:
        self._connection._mx_api('DELETE', '/conf/webServices/%s/%s/%s/hostToAppMappings/%d' % (self._Site, self._ServerGroup, self._WebService, old_map['priority']))
    for new_map in Mappings:
      if new_map not in self._Mappings:
        body = {
          'host': new_map['host'],
          'hostMatchType': new_map['hostMatchType']
        }
        self._connection._mx_api('POST', '/conf/webServices/%s/%s/%s/hostToAppMappings/%s/%d' % (self._Site, self._ServerGroup, self._WebService, self._Name, new_map['priority']), data=json.dumps(body))
      
  #
  # Web Application internal functions
  #
  @staticmethod
  def _get_all_web_applications(connection, ServerGroup=None, Site=None, WebService=None):
    validate_string(Site=Site, ServerGroup=ServerGroup, WebService=WebService)
    res = connection._mx_api('GET', '/conf/webApplications/%s/%s/%s' % (Site, ServerGroup, WebService))
    try:
      wa_names = res['webApplications']
    except:
      raise MxException("Failed getting Web Applications")
    wa_objects = []
    for wa in wa_names:
      wa_objects.append(connection.get_web_application(Site=Site, ServerGroup=ServerGroup, WebService=WebService, Name=wa))
    return wa_objects
  @staticmethod
  def _get_web_application(connection, Name=None, ServerGroup=None, Site=None, WebService=None):
    validate_string(Site=Site, ServerGroup=ServerGroup, WebService=WebService, Name=Name)
    obj_exists = WebApplication._exists(connection=connection, Name=Name, Site=Site, ServerGroup=ServerGroup, WebService=WebService)
    if obj_exists:
      return obj_exists
    try:
      wa_json = connection._mx_api('GET', '/conf/webApplications/%s/%s/%s/%s' % (Site, ServerGroup, WebService, Name))
    except: 
      return None
    if 'restrictMonitoringToUrls' not in wa_json: wa_json['restrictMonitoringToUrls'] = None
    if 'ignoreUrlsDirectories' not in wa_json: wa_json['ignoreUrlsDirectories'] = None
    # get mappings
    Mappings = []
    service_mappings = connection._mx_api('GET', '/conf/webServices/%s/%s/%s/hostToAppMappings' % (Site, ServerGroup, WebService))
    for cur_map in service_mappings["hostToAppMappings"]:
      if cur_map["application"] == Name:
        del cur_map["application"]
        Mappings.append(cur_map)
    return WebApplication(connection=connection, Name=Name, WebService=WebService, ServerGroup=ServerGroup, Site=Site, LearnSettings=wa_json['learnSettings'], ParseOcspRequests=wa_json['parseOCSPRequests'], RestrictMonitoringToUrls=wa_json['restrictMonitoringToUrls'], IgnoreUrlsDirectories=wa_json['ignoreUrlsDirectories'], Mappings=Mappings)
  @staticmethod
  def _create_web_application(connection, Name=None, WebService=None, ServerGroup=None, Site=None, LearnSettings=None, ParseOcspRequests=None, RestrictMonitoringToUrls=None, IgnoreUrlsDirectories=None, Profile=None, Mappings=None, update=False):
    validate_string(Site=Site, ServerGroup=ServerGroup, WebService=WebService, Name=Name)
    wa = connection.get_web_application(Site=Site, ServerGroup=ServerGroup, WebService=WebService, Name=Name)
    if wa:
      if update:
        parameters = locals()
        for cur_key in parameters:
          if is_parameter.match(cur_key) and cur_key not in ['Name', 'Site', 'ServerGroup', 'WebService', 'Profile'] and parameters[cur_key] != None:
            setattr(wa, cur_key, parameters[cur_key])
        if Profile:
          try:
            wa.update_profile(Profile=Profile)
          except MxExceptionNotFound:
            pass
        return wa
      else:
        raise MxException("Web Application '%s' already exists" % Name)
    body = {}
    if LearnSettings: body['learnSettings'] = LearnSettings
    if ParseOcspRequests: body['parseOCSPRequests'] = ParseOcspRequests
    if RestrictMonitoringToUrls: body['restrictMonitoringToUrl'] = RestrictMonitoringToUrls
    if IgnoreUrlsDirectories: body['ignoreUrlsDirectories'] = IgnoreUrlsDirectories
    connection._mx_api('POST', '/conf/webApplications/%s/%s/%s/%s' % (Site, ServerGroup, WebService, Name), data=json.dumps(body))
    wa = WebApplication(connection=connection, Name=Name, WebService=WebService, ServerGroup=ServerGroup, Site=Site, LearnSettings=LearnSettings, ParseOcspRequests=ParseOcspRequests, RestrictMonitoringToUrls=RestrictMonitoringToUrls, IgnoreUrlsDirectories=IgnoreUrlsDirectories)
    if Profile:
      try:
        wa.update_profile(Profile=Profile)
      except MxExceptionNotFound:
        pass
    if Mappings:
      wa.Mappings = Mappings
    return wa
  @staticmethod
  def _delete_web_application(connection, Name=None, WebService=None, ServerGroup=None, Site=None):
    validate_string(WebService=WebService, ServerGroup=ServerGroup, Site=Site, Name=Name)
    wa = connection.get_web_application(Site=Site, ServerGroup=ServerGroup, WebService=WebService, Name=Name)
    if wa:
      connection._mx_api('DELETE', '/conf/webApplications/%s/%s/%s/%s' % (Site, ServerGroup, WebService, Name))
      connection._instances.remove(wa)
      del wa
    else:
      raise MxException("Web Application does not exist")
    return True    
  @staticmethod
  def _update_web_application(connection, WebService=None, ServerGroup=None, Site=None, Name=None, Parameter=None, Value=None):
    body = { Parameter: Value }
    connection._mx_api('PUT', '/conf/webApplications/%s/%s/%s/%s' % (Site, ServerGroup, WebService, Name), data=json.dumps(body))
    return True
  @staticmethod
  def _get_profile(connection, WebService=None, ServerGroup=None, Site=None, Application=None):
    profile = connection._mx_api('GET', '/conf/webProfile/%s/%s/%s/%s' % (Site, ServerGroup, WebService, Application))
    directories = connection._mx_api('GET', '/conf/webProfile/%s/%s/%s/%s/directories' % (Site, ServerGroup, WebService, Application))
    profile['directories'] = directories
    return profile
  @staticmethod
  def _update_profile(connection, WebService=None, ServerGroup=None, Site=None, Application=None, Profile=None, SwaggerJson=None):
    if (Profile and SwaggerJson) or (not Profile and not SwaggerJson):
      raise MxException("Must define either Profile or SwaggerJson parameter")
    if SwaggerJson:
      Profile = _swagger2profile(SwaggerJson)
    directories = list(Profile['directories'])
    del Profile['directories']
    connection._mx_api('PUT', '/conf/webProfile/%s/%s/%s/%s' % (Site, ServerGroup, WebService, Application), data=json.dumps(Profile), timeout=1800)
    connection._mx_api('PUT', '/conf/webProfile/%s/%s/%s/%s/directories' % (Site, ServerGroup, WebService, Application), data=json.dumps(directories))
    return None
  @staticmethod
  def _get_profile_url(connection, WebService=None, ServerGroup=None, Site=None, Application=None, UrlName=None):
    try:
      profile = connection._mx_api('GET', '/conf/webProfile/%s/%s/%s/%s/url/%s' % (Site, ServerGroup, WebService, Application, UrlName))
      return profile
    except:
      return None
  @staticmethod
  def _delete_profile_url(connection, WebService=None, ServerGroup=None, Site=None, Application=None, UrlName=None):
    connection._mx_api('DELETE', '/conf/webProfile/%s/%s/%s/%s/url/%s' % (Site, ServerGroup, WebService, Application, UrlName))
    return True
  @staticmethod
  def _update_profile_url(connection, WebService=None, ServerGroup=None, Site=None, Application=None, UrlProfile=None, UrlName=None):
    connection._mx_api('PUT', '/conf/webProfile/%s/%s/%s/%s/url/%s' % (Site, ServerGroup, WebService, Application, UrlName), data=json.dumps(UrlProfile))
    return None

  #
  # Web Application extra functions
  #
  def get_profile(self):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_profile`. '''
    return self._connection.get_profile(Site=self._Site, ServerGroup=self._ServerGroup, WebService=self._WebService, Application=self.Name)
  def update_profile(self, Profile=None, SwaggerJson=None):
    ''' See :py:meth:`imperva_sdk.MxConnection.update_profile`. '''
    return self._connection.update_profile(Site=self._Site, ServerGroup=self._ServerGroup, WebService=self._WebService, Application=self.Name, Profile=Profile, SwaggerJson=SwaggerJson)
  def get_profile_url(self, UrlName=None):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_profile_url`. '''
    return self._connection.get_profile_url(Site=self._Site, ServerGroup=self._ServerGroup, WebService=self._WebService, Application=self.Name, UrlName=UrlName)
  def delete_profile_url(self, UrlName=None):
    ''' See :py:meth:`imperva_sdk.MxConnection.delete_profile_url`. '''
    return self._connection.delete_profile_url(Site=self._Site, ServerGroup=self._ServerGroup, WebService=self._WebService, Application=self.Name, UrlName=UrlName)
  def update_profile_url(self, UrlProfile=None, UrlName=None):
    ''' See :py:meth:`imperva_sdk.MxConnection.update_profile_url`. '''
    return self._connection.update_profile_url(Site=self._Site, ServerGroup=self._ServerGroup, WebService=self._WebService, Application=self.Name, UrlProfile=UrlProfile, UrlName=UrlName)

# Function for converting Swagger JSON to Profile format
def _swagger2profile(swagger=None):
  if "swagger" not in swagger:
    # Not swagger JSON
    return None

  profile = {
    "learnedHosts": [],
    "patternUrls": [],
    "cookies": [],
    "susceptibleDirectories": [],
    "actionUrls": [],
    "webProfileUrls": [],
    "directories": [{'fullPath': "/", 'locked': True}]
  }

  if "host" in swagger:
    profile["learnedHosts"] = [swagger["host"].split(":")[0]]

  base_path = ""
  if "basePath" in swagger:
    base_path = swagger["basePath"]

  for path in swagger['paths']:
    url = {
      'status': 'InProtection',
      'locked': True,
      'urlFullPath': base_path + path,
      'allowedMethods': [],
      'contentTypes': [],
      'parameters': []
    }

    split_url = url['urlFullPath'].split('/')
    for i in range(len(split_url) - 2):
      directory = '/'.join(split_url[0:i+2])
      if {'fullPath': directory, 'locked': True} not in profile['directories']:
        profile['directories'].append({'fullPath': directory, 'locked': True})

    for method in swagger['paths'][path]:
      if {'status': 'decided', 'method': method.upper()} not in url['allowedMethods']:
        url['allowedMethods'].append({'status': 'decided', 'method': method.upper()})
      if 'consumes' in swagger['paths'][path][method]:
        for content_type in swagger['paths'][path][method]['consumes']:
          if content_type.lower() == "application/json" or content_type.lower() == "text/json":
            if "JSON" not in url['contentTypes']:
              url['contentTypes'].append("JSON")
          if content_type.lower() == "application/xml" or content_type.lower() == "text/xml":
            if "XML" not in url['contentTypes']:
              url['contentTypes'].append("XML")
      if 'produces' in swagger['paths'][path][method]:
        for content_type in swagger['paths'][path][method]['produces']:
          if content_type.lower() == "application/json" or content_type.lower() == "text/json":
            if "JSON" not in url['contentTypes']:
              url['contentTypes'].append("JSON")
          if content_type.lower() == "application/xml" or content_type.lower() == "text/xml":
            if "XML" not in url['contentTypes']:
              url['contentTypes'].append("XML")
      if 'parameters' in swagger['paths'][path][method]:
        for parameter in swagger['paths'][path][method]['parameters']:
          if "type" in parameter:
            add_parameter = {
              "name": parameter["name"],
              "required": False,
              "minLength": 0,
              "maxLength": 2147483647,
              "nullable": True,
              "readOnly": False,
              "prefix": False,
              "type": "UTF8"
            }
            if "required" in parameter:
              # Currently we can't handle required parameters because of multiple methods per URL
              #add_parameter["required"] = parameter["required"]
              pass
            if parameter["type"] == "integer":
              add_parameter['type'] = "Numeric"
            new_parameter = True
            for check_parameter in url["parameters"]:
              if check_parameter["name"] == add_parameter["name"]:
                check_parameter["type"] = "UTF8"
                check_parameter["required"] = False
                new_parameter = False
            if new_parameter:
              url["parameters"].append(add_parameter)
          elif "schema" in parameter:
            if "$ref" in parameter["schema"]:
              definition = parameter["schema"]["$ref"].split('/')[-1]
              if definition in swagger['definitions']:
                def_object = swagger['definitions'][definition]
                if def_object['type'] == "object":
                  for def_parameter in def_object['properties']:
                    add_parameter = {
                      "name": def_parameter,
                      "required": False,
                      "minLength": 0,
                      "maxLength": 2147483647,
                      "nullable": True,
                      "readOnly": False,
                      "prefix": False,
                      "type": "UTF8"
                    }
                    if 'required' in def_object and def_parameter in def_object['required']:
                      # Currently we can't handle required parameters because of multiple methods per URL
                      #add_parameter['required'] = True
                      pass
                    if "type" in def_object['properties'][def_parameter] and def_object['properties'][def_parameter]["type"] == "integer":
                      add_parameter['type'] = "Numeric"
                    new_parameter = True
                    for check_parameter in url["parameters"]:
                      if check_parameter["name"] == add_parameter["name"]:
                        check_parameter["type"] = "UTF8"
                        check_parameter["required"] = False
                        new_parameter = False
                    if new_parameter:
                      url["parameters"].append(add_parameter)
                    
    profile["webProfileUrls"].append(url)

  return profile

