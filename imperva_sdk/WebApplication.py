# Copyright 2018 Imperva. All rights reserved.

import json
import hashlib
import re
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
        parameters = dict(locals())
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
      WebApplication._create_swagger_custom_parameter_types_for_arrays(connection)
      Profile = _swagger_to_profile(connection, SwaggerJson)
      if connection.Version < "12.3.0.0":
        for url in Profile["webProfileUrls"]:
          for parm in url["parameters"]:
            parm.pop("base64Encoded")
    directories = list(Profile['directories'])
    del Profile['directories']
    connection._mx_api('PUT', '/conf/webProfile/%s/%s/%s/%s' % (Site, ServerGroup, WebService, Application), data=json.dumps(Profile), timeout=1800)
    connection._mx_api('PUT', '/conf/webProfile/%s/%s/%s/%s/directories' % (Site, ServerGroup, WebService, Application), data=json.dumps(directories))
    return None

  @staticmethod
  def _create_swagger_custom_parameter_types_for_arrays(mx_conn):
      custom_parameter_types = []
      regex_pattern = re.compile("^swagger_(csv|ssv|tsv|piped)_delimited_(integer|number)s$")
      for custom_parameter_type in mx_conn.get_all_parameter_type_global_objects():
        if regex_pattern.search(custom_parameter_type.Name):
          custom_parameter_types.append(custom_parameter_type.Name)
      if len(custom_parameter_types) < 8:
        print("Adding common custom parameter types for numeric arrays")
        mx_conn.create_parameter_type_global_object(Name="swagger_csv_delimited_integers",
          Regex="^[-+]?[0-9]{1,19}(,[-+]?[0-9]{1,19})*$", update=True)
        mx_conn.create_parameter_type_global_object(Name="swagger_ssv_delimited_integers",
          Regex="^[-+]?[0-9]{1,19}(,[-+]?[0-9]{1,19})*$", update=True)
        mx_conn.create_parameter_type_global_object(Name="swagger_tsv_delimited_integers",
          Regex="^[-+]?[0-9]{1,19}(\\t[-+]?[0-9]{1,19})*$", update=True)
        mx_conn.create_parameter_type_global_object(Name="swagger_piped_delimited_integers",
          Regex="^[-+]?[0-9]{1,19}(\\|[-+]?[0-9]{1,19})*$", update=True)
        mx_conn.create_parameter_type_global_object(Name="swagger_csv_delimited_numbers",
          Regex="^[-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?(,[-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?)*$", update=True)
        mx_conn.create_parameter_type_global_object(Name="swagger_ssv_delimited_numbers",
          Regex="^[-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?( [-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?)*$", update=True)
        mx_conn.create_parameter_type_global_object(Name="swagger_tsv_delimited_numbers",
          Regex="^[-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?(\\t[-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?)*$", update=True)
        mx_conn.create_parameter_type_global_object(Name="swagger_piped_delimited_numbers",
          Regex="^[-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?(\\|[-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?)*$", update=True)

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
def _swagger_to_profile(mx_conn=None, swagger_json_file=None):
  swagger = swagger_json_file.get_expanded_json()
  profile = {
    "learnedHosts": swagger_json_file.get_all_hosts(),
    "patternUrls": [],
    "cookies": [],
    "susceptibleDirectories": [],
    "actionUrls": [],
    "webProfileUrls": [],
    "headers": [],
    "directories": [{'fullPath': "/", 'locked': True}]
  }
  _add_security_urls(swagger_json_file, profile)
  default_content_types = []
  for content_type in swagger.get("consumes", []):
    _add_content_type(content_type, default_content_types)
  for path in swagger['paths']:
    base_path = swagger_json_file.get_base_path(swagger['paths'][path])
    url = _create_new_url(base_path + path.translate({ord('{'): None, ord('}'): None}))
    split_url = url['urlFullPath'].split('/')
    for i in range(len(split_url) - 2):
      directory = '/'.join(split_url[0:i+2])
      if {'fullPath': directory, 'locked': True} not in profile['directories']:
        profile['directories'].append({'fullPath': directory, 'locked': True})
    for method in swagger['paths'][path]:
      common_parms_exists = 0
      if method == "parameters":
        common_parms_exists = 1
        _handle_swagger_parameters(mx_conn, swagger['paths'][path]['parameters'], url, True)
      if method in ["summary", "description", "servers", "parameters"]:
        continue
      if {'status': 'decided', 'method': method.upper()} not in url['allowedMethods']:
        url['allowedMethods'].append({'status': 'decided', 'method': method.upper()})
      for content_type in swagger['paths'][path][method].get("consumes", []):
        _add_content_type(content_type, url['contentTypes'])
      if 'parameters' in swagger['paths'][path][method]:
        _handle_swagger_parameters(mx_conn, swagger['paths'][path][method]['parameters'],
                                   url, len(swagger['paths'][path]) - common_parms_exists == 1)
      if "requestBody" in swagger['paths'][path][method]:
        _handle_request_body(mx_conn, swagger['paths'][path][method]["requestBody"], url)
    if len(url['contentTypes']) == 0 and len(default_content_types) > 0:
      url['contentTypes'] = default_content_types
    profile["webProfileUrls"].append(url)
  return profile


def _create_new_url(url_full_path):
  return {
      'status': 'InProtection',
      'locked': True,
      'urlFullPath': url_full_path,
      'allowedMethods': [],
      'contentTypes': [],
      'parameters': []
  }


def _add_security_urls(swagger_json_file, profile):
  security_schemes_dict = swagger_json_file.get_security_schemes()
  if not security_schemes_dict:
    return
  for sec_scheme_key in security_schemes_dict:
    sec_scheme_dict = security_schemes_dict[sec_scheme_key]
    in_attr = sec_scheme_dict.get("in", None)
    if in_attr == "header":
      profile["headers"].append({"headerName": sec_scheme_dict["name"]})
    _add_oauth2_urls(swagger_json_file, profile, sec_scheme_dict)                       # Swagger 2.0
    for flow_key in sec_scheme_dict.get("flows", {}):
      _add_oauth2_urls(swagger_json_file, profile, sec_scheme_dict["flows"][flow_key])  # OpenAPI 3.0 and above


def _add_oauth2_urls(swagger_json_file, profile, flow_dict):
  authorization_url = flow_dict.get("authorizationUrl", None)
  parsed_url = swagger_json_file.get_parsed_url(authorization_url)
  if parsed_url and parsed_url["path"]:
    url = _create_new_url(parsed_url["path"])
    url["allowedMethods"].append({"method": "GET", "status": "decided"})
    url["contentTypes"].append("URL")
    profile["webProfileUrls"].append(url)
  token_url = flow_dict.get("tokenUrl", None)
  parsed_url = swagger_json_file.get_parsed_url(token_url)
  if parsed_url and parsed_url["path"]:
    url = _create_new_url(parsed_url["path"])
    url["allowedMethods"].append({"method": "POST", "status": "decided"})
    url["allowedMethods"].append({"method": "GET", "status": "decided"})
    url["contentTypes"].append("URL")
    profile["webProfileUrls"].append(url)


def _handle_request_body(mx_conn, body_dict, url):
  for content_type in body_dict.get("content", {}):
    _add_content_type(content_type, url['contentTypes'])
    schema_dict = body_dict["content"][content_type].get("schema", {})
    body_type = schema_dict.get("type", None)
    if body_type != "object":
      print("Got request body type: {}. Currently, supporting only type = object.".format(body_type))
      continue
    for parm_name in schema_dict.get("properties", {}):
      _handle_single_param(mx_conn, url, schema_dict["properties"][parm_name], parm_name, "body", False)


def _add_content_type(actual_content_type, content_type_enum_list):
  lower_content_type = actual_content_type.lower()
  if lower_content_type in ["application/json", "text/json"]:
    if "JSON" not in content_type_enum_list:
      content_type_enum_list.append("JSON")
  elif lower_content_type in ["application/xml", "text/xml"]:
    if "XML" not in content_type_enum_list:
      content_type_enum_list.append("XML")
  elif "URL" not in content_type_enum_list:
    content_type_enum_list.append("URL")


def _get_parameter_attribute(swagger_parm_obj, attr_name, default_val=None):
  if attr_name in swagger_parm_obj:
    return swagger_parm_obj[attr_name]
  if "schema" in swagger_parm_obj and type(swagger_parm_obj["schema"]) is dict and attr_name in swagger_parm_obj["schema"]:
    return swagger_parm_obj["schema"][attr_name]
  return default_val


def _handle_swagger_parameters(mx_conn, parameters_dict, url, is_single_method):
  for param_obj in parameters_dict:
    parameter = param_obj
    in_attr = _get_parameter_attribute(parameter, "in")
    if in_attr is None or in_attr not in ["query", "path", "body", "formData"]:
      continue
    if in_attr != "body":
      _handle_single_param(mx_conn, url, parameter, _get_parameter_attribute(parameter, "name"), in_attr, is_single_method)
    else:
      if "schema" in parameter:
        if "type" in parameter["schema"] and parameter["schema"]["type"] == "object":
          if "properties" in parameter["schema"]:
            for parm_name in parameter["schema"]["properties"]:
              _handle_single_param(mx_conn, url, parameter["schema"]["properties"][parm_name], parm_name, in_attr, is_single_method)
        else:
          print("Body parameter is not of type 'object'")


def _get_explode_attr(in_attr, parm_dict):
  default_style = ""
  if in_attr == "query":
    default_style = "form"
  style_attr = parm_dict.get("style", default_style)
  return parm_dict.get("explode", style_attr == "form")


def _handle_single_param(mx_conn, url, parameter, parm_name, in_attr, is_single_method):
  parm_dict = parameter
  type_attr = _get_parameter_attribute(parm_dict, "type")
  collection_format_attr = _get_parameter_attribute(parm_dict, "collectionFormat")
  if type_attr == "array" and (collection_format_attr == "multi" or _get_explode_attr(in_attr, parm_dict)):
    # when multi (v2) or explode (v3) arrays are represented as passing same parameter multiple times
    # (each with different value). Thus, we can treat the array as a regular parameter defined under "items"
    parm_dict = _get_parameter_attribute(parameter, "items", {})
    type_attr = _get_parameter_attribute(parm_dict, "type")
  format_attr = _get_parameter_attribute(parm_dict, "format")
  add_parameter = {
    "name": parm_name,
    "required": (in_attr == "path" or is_single_method) and _get_parameter_attribute(parameter, "required", False),
    "minLength": _get_parameter_attribute(parameter, "minLength", 0),
    "maxLength": _get_parameter_attribute(parameter, "maxLength", 2**31 - 1),
    "nullable": True,
    "readOnly": False,
    "prefix": False,
    "base64Encoded": format_attr in ["byte", "base64"],
    "type": "UTF8"
  }
  if type_attr == "integer":
    add_parameter['type'] = "Numeric"
    add_parameter['minLength'] = len(str(int(_get_parameter_attribute(parm_dict, "minimum", 0))))
    add_parameter['maxLength'] = len(str(int(_get_parameter_attribute(parm_dict, "maximum", -2**63))))
    add_parameter["additionalAllowedChars"] = ["plus", "dash"]
    if format_attr == "int32" and add_parameter['maxLength'] == len(str(-2**63)):
      add_parameter['maxLength'] = len(str(-2**31))
  elif type_attr == "number":
    add_parameter['maxLength'] = len(str(10**300 / -3))
    add_parameter["additionalAllowedChars"] = ["plus", "dash", "period"]
  elif type_attr == "boolean": # boolean is one of: no, yes, true, false
    add_parameter['minLength'] = 2
    add_parameter['maxLength'] = 5
    add_parameter["additionalAllowedChars"] = []
  elif type_attr == "string":
    enum_list = _get_parameter_attribute(parm_dict, "enum", [])
    if len(enum_list) > 0:
      min_enum_length = 2**31 - 1
      max_enum_length = 0
      for enum_val in enum_list:
        if len(enum_val) > max_enum_length:
          max_enum_length = len(enum_val)
        if len(enum_val) < min_enum_length:
          min_enum_length = len(enum_val)
      add_parameter['minLength'] = min_enum_length
      add_parameter['maxLength'] = max_enum_length
      regex_pattern = "^(" + "|".join(enum_list) + ")$"
      _handle_regex_pattern(mx_conn, parm_name, "enum", regex_pattern, add_parameter)
    elif format_attr == "date":
      add_parameter['minLength'] = 8
      add_parameter['maxLength'] = 10
    elif format_attr == "date-time":
      add_parameter['minLength'] = 19
      add_parameter['maxLength'] = 32
    elif format_attr == "uuid":
      add_parameter['minLength'] = 36
      add_parameter['maxLength'] = 36
    regex_pattern = _get_parameter_attribute(parm_dict, "pattern")
    if _valid_regex_pattern(regex_pattern):
      _handle_regex_pattern(mx_conn, parm_name, "pattern", regex_pattern, add_parameter)
  elif type_attr == "array":
    delimiterFormat = _get_parameter_attribute(parameter, "collectionFormat")
    if delimiterFormat in ["csv", "tsv", "ssv", "pipes"] and in_attr in ["query", "path"]:
      items_dict = _get_parameter_attribute(parameter, "items")
      item_type = _get_parameter_attribute(items_dict, "type")
      if item_type in ["integer", "number"]:
        add_parameter["customValueType"] = "swagger_" + delimiterFormat + "_delimited_" + item_type + "s"
        add_parameter.pop("type")
  new_parameter = True
  for check_parameter in url["parameters"]:
    if check_parameter["name"] == add_parameter["name"]:
      new_parameter = False
      if check_parameter.get("type", None) != add_parameter.get("type", None) or \
              check_parameter.get("customValueType", None) != add_parameter.get("customValueType", None):
        check_parameter["type"] = "UTF8"
        check_parameter.pop("customValueType", None)
      if check_parameter["minLength"] > add_parameter["minLength"]:
        check_parameter["minLength"] = add_parameter["minLength"]
      if check_parameter["maxLength"] < add_parameter["maxLength"]:
        check_parameter["maxLength"] = add_parameter["maxLength"]
      check_parameter["required"] = check_parameter["required"] and add_parameter["required"]
  if new_parameter:
    url["parameters"].append(add_parameter)
  return


def _valid_regex_pattern(regex_pattern=None):
  if regex_pattern is None or type(regex_pattern) is not str:
    return False
  try:
    re.compile(regex_pattern)
    return True
  except:
    print("Regex pattern: " + regex_pattern + " isn't valid")
    return False


def _handle_regex_pattern(mx_conn, parm_name, parm_type, regex_pattern, add_parameter):
  custom_name = "swagger_" + parm_name + "_" + parm_type + "_" + hashlib.md5(regex_pattern.encode('utf-8')).hexdigest()
  mx_conn.create_parameter_type_global_object(Name=custom_name, Regex=regex_pattern, update=True)
  add_parameter["customValueType"] = custom_name
  add_parameter.pop("type")


