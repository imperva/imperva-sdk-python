# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class WebService(MxObject):
  ''' 
  MX Web Service Class 

  >>> ws = sg.create_web_service("web service name")
  >>> ws.ForwardedConnections
  {}
  >>> ws.krp_xff_enable()
  >>> ws.ForwardedConnections
  {'useHttpForwardingHeader': True, 'forwardedConnections': [{'headerName': 'X-Forwarded-For', 'proxyIpGroup': ''}]}
  >>> ws.SslKeys
  []
  >>> ws.upload_ssl_certificate(SslKeyName="key name", Private=key_data, Certificate=key_data)
  >>> ws.SslKeys
  [{'certificate': '', 'format': 'pem', 'private': '', 'hsm': False, 'sslKeyName': 'key name', 'password': ''}]

  '''
  
  # Store created web service objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = WebService._exists(connection=kwargs['connection'], Site=kwargs['Site'], ServerGroup=kwargs['ServerGroup'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Site=None, ServerGroup=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'WebService':
        if cur_obj.Name == Name and cur_obj._ServerGroup == ServerGroup and cur_obj._Site == Site:
          return cur_obj
    return None
      
  def __init__(self, connection=None, Name=None, ServerGroup=None, Site=None, Ports=[], SslPorts=[], ForwardedConnections={}, ForwardedClientIp={}, SslKeys=[], TrpMode=None):
    super(WebService, self).__init__(connection=connection, Name=Name)
    validate_string(Site=Site, ServerGroup=ServerGroup)
    #validate_int_list(Ports=Ports, SslPorts=SslPorts)
    self._Site = Site
    self._ServerGroup = ServerGroup
    self._Ports = Ports
    self._SslPorts = SslPorts
    self._ForwardedConnections = ForwardedConnections
    self._ForwardedClientIp = ForwardedClientIp
    self._SslKeys = SslKeys
    self._TrpMode = TrpMode

  #
  # Web Service Parameters
  #
  @property
  def Name(self):
    ''' Web Service Name (string) '''
    return self._Name
  @property
  def Ports(self):
    ''' Web Service Ports (list of int). Edit not implemented. '''
    return self._Ports
  @property
  def SslPorts(self):
    ''' Web Service SSL Ports (list of int). Edit not implemented. '''
    return self._SslPorts
  @property
  def ForwardedClientIp(self):
    ''' 
    Web Service ForwardedClientIp (edit available with `krp_xff_enable` and `krp_xff_disable` functions). For KRP - report forwarded client IP in HTTP header. 

    >>> ws.ForwardedClientIp
    {'forwardHeaderName': 'X-Forwarded-For', 'forwardClientIP': True}

    * forwardClientIP (boolean) - Indicates if the reverse proxy forwards the original IP address in the header defined by the forwardHeaderName parameter (default=False).
    * forwardHeaderName (string) - Header name that includes the original IP address of the client (default="X-Forwarded-For").

    '''
    return self._ForwardedClientIp
  @property
  def ForwardedConnections(self):
    ''' 
    Web Service ForwardedConnections (edit available with `krp_xff_enable` and `krp_xff_disable` functions). Identify real client IP according to HTTP forwarding header. 

    >>> ws.ForwardedConnections
    {u'useHttpForwardingHeader': True, u'forwardedConnections': [{u'headerName': u'X-Forwarded-For', u'proxyIpGroup': u''}, {u'headerName': u'Fake-Forward-Header', u'proxyIpGroup': u'Google IP Addresses'}]}

    * useHttpForwardingHeader (boolean) - Indicate if the gateway should identify the real client IP according to the HTTP forwarding header (XFF) in the header defined by the forwardHeaderName parameter (default=False).
    * forwardedConnections (list of dict) - List of forward connection definitions:

      * headerName (string) - Name of the forwarding header.
      * proxyIpGroup (string) - Name of the IP Group of proxies. For "Any IP" use empty string ("").

    '''
    return self._ForwardedConnections
  @property
  def SslKeys(self):
    ''' 
    Web Service SSL Certificates/Keys (edit available with `upload_ssl_certificate` and `delete_ssl_certificate` functions). Object instance does not store certificate/private/password information.

    >>> ws.SslKeys
    [{'certificate': '', 'format': 'pem', 'private': '', 'hsm': False, 'sslKeyName': u'key name', 'password': ''}]
    >>> ws.delete_ssl_certificate("key name")
    >>> ws.SslKeys
    []

    * sslKeyName (string) - The name of the SSL Key in SecureSphere.
    * format (constant) - imperva_sdk only supports 'pem' format.
    * hsm (boolean) - Is certificate used by HSM (default=False).
    * certificate (string) - Base64 encoded PEM certificate.
    * private (string) - Base64 encoded PEM certificate.
    * password (string) - File password (default="").

    '''
    return self._SslKeys
  @property
  def TrpMode(self):
    ''' Transparent Reverse Proxy Mode (True/False)'''
    return self._TrpMode

  @Name.setter
  def Name(self, Name):
    validate_string(Name=Name)
    body = json.dumps({'name': Name})
    self._connection._mx_api('PUT', '/conf/webServices/%s/%s/%s' % (self._Site, self._ServerGroup, self._Name), data=body)
    self._Name = Name
  @TrpMode.setter
  def TrpMode(self, TrpMode):
    body = json.dumps({'trpMode': TrpMode})
    self._connection._mx_api('PUT', '/conf/webServices/%s/%s/%s' % (self._Site, self._ServerGroup, self._Name), data=body)
    self._TrpMode = TrpMode

  #    
  # Web Service internal functions
  #
  @staticmethod  
  def _get_all_web_services(connection, ServerGroup=None, Site=None):
    validate_string(Site=Site, ServerGroup=ServerGroup)
    res = connection._mx_api('GET', '/conf/webServices/%s/%s' % (Site, ServerGroup))
    try:
      names = res['web-services']
    except:
      raise MxException("Failed getting web services")
    wss = []
    for name in names:
      wss.append(connection.get_web_service(Name=name, Site=Site, ServerGroup=ServerGroup))
    return wss
  @staticmethod
  def _get_web_service(connection, Name=None, ServerGroup=None, Site=None):
    validate_string(Name=Name, ServerGroup=ServerGroup, Site=Site)
    obj_exists = WebService._exists(connection=connection, Name=Name, ServerGroup=ServerGroup, Site=Site)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/webServices/%s/%s/%s' % (Site, ServerGroup, Name))
    except:
      return None
    if 'name' in res:
      Ports = []
      if 'ports' in res: Ports = res['ports']
      SslPorts = []
      if 'sslPorts' in res: SslPorts = res['sslPorts']
      TrpMode = False
      if 'trpMode' in res: TrpMode = res['trpMode']
      # Get web serive forwarded connections
      ForwardedConnections = connection._mx_api('GET', '/conf/webServices/%s/%s/%s/forwardedConnections' % (Site, ServerGroup, Name))
      ForwardedClientIp = connection._mx_api('GET', '/conf/webServices/%s/%s/%s/forwardedClientIp' % (Site, ServerGroup, Name))
      SslKeys = WebService._get_ssl_keys(connection, Name=Name, ServerGroup=ServerGroup, Site=Site)
      return WebService(connection=connection, Name=Name, ServerGroup=ServerGroup, Site=Site, Ports=Ports, SslPorts=SslPorts, ForwardedConnections=ForwardedConnections, ForwardedClientIp=ForwardedClientIp, SslKeys=SslKeys, TrpMode=TrpMode)
    else:
      return None
  @staticmethod
  def _get_ssl_keys(connection, Name=None, ServerGroup=None, Site=None):
    SslKeys = []
    ssl_certs = connection._mx_api('GET', '/conf/webServices/%s/%s/%s/sslCertificates' % (Site, ServerGroup, Name))
    for cert_name in ssl_certs['sslKeyName']:
      ssl_cert = connection._mx_api('GET', '/conf/webServices/%s/%s/%s/sslCertificates/%s' % (Site, ServerGroup, Name, cert_name))
      ssl_cert['sslKeyName'] = cert_name
      SslKeys.append(ssl_cert)
    return SslKeys
  @staticmethod    
  def _create_web_service(connection, Name=None, ServerGroup=None, Site=None, Ports=[], SslPorts=[], ForwardedConnections={}, ForwardedClientIp={}, SslKeys=[], TrpMode=None, update=False):
    validate_string(Name=Name, Site=Site, ServerGroup=ServerGroup)
    ws = connection.get_web_service(Name=Name, Site=Site, ServerGroup=ServerGroup)
    if ws:
      if update:
        # Not implemented yet
        if ForwardedConnections:
          pass
        if ForwardedClientIp:
          pass
        if SslKeys:
          pass
        if Ports:
          pass
        if SslPorts:
          pass
        if TrpMode:
          pass
        return ws
      else:
        raise MxException("Web Service already exists")
    body = {}
    if Ports: body['ports'] = Ports
    if SslPorts: body['sslPorts'] = SslPorts
    if TrpMode: body['trpMode'] = TrpMode
    connection._mx_api('POST', '/conf/webServices/%s/%s/%s' % (Site, ServerGroup, Name), data=json.dumps(body))
    if ForwardedConnections:
      for fconnection in ForwardedConnections['forwardedConnections']:
        if 'operation' not in fconnection:
          fconnection['operation'] = 'add'
      connection._mx_api('PUT', '/conf/webServices/%s/%s/%s/forwardedConnections' % (Site, ServerGroup, Name), data=json.dumps(ForwardedConnections))
      for fconnection in ForwardedConnections['forwardedConnections']:
        del fconnection['operation']
    if ForwardedClientIp:
      connection._mx_api('PUT', '/conf/webServices/%s/%s/%s/forwardedClientIp' % (Site, ServerGroup, Name), data=json.dumps(ForwardedClientIp))
    if SslKeys:
      for ssl_key in SslKeys:
        try:
          key_name = ssl_key['sslKeyName']
          post_key = {
            'format': 'pem',
            'hsm': False,
            'private': ssl_key['private'],
            'certificate': ssl_key['certificate']
          }
          if 'hsm' in ssl_key: post_key['hsm'] = ssl_key['hsm']
        except Exception as e:
          raise MxException("SslKey missing required parameter '%s'" % str(e))
        connection._mx_api('POST', '/conf/webServices/%s/%s/%s/sslCertificates/%s' % (Site, ServerGroup, Name, key_name), data=json.dumps(post_key))
      SslKeys = WebService._get_ssl_keys(connection, Name=Name, ServerGroup=ServerGroup, Site=Site)
    return WebService(connection=connection, Name=Name, ServerGroup=ServerGroup, Site=Site, Ports=Ports, SslPorts=SslPorts, ForwardedConnections=ForwardedConnections, ForwardedClientIp=ForwardedClientIp, SslKeys=SslKeys, TrpMode=TrpMode)
  @staticmethod
  def _delete_web_service(connection, Name=None, ServerGroup=None, Site=None):
    validate_string(Name=Name, ServerGroup=ServerGroup, Site=Site)
    ws = connection.get_web_service(Name=Name, Site=Site, ServerGroup=ServerGroup)
    if ws:
      connection._mx_api('DELETE', '/conf/webServices/%s/%s/%s' % (Site, ServerGroup, Name))
      connection._instances.remove(ws)
      del ws
    else:
      raise MxException("Web Service '%s' does not exist" % Name)
    return True

  #
  # Web Service child functions
  #
  def get_krp_rule(self, GatewayGroup=None, Alias=None, GatewayPorts=[]):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_krp_rule`. '''
    return self._connection.get_krp_rule(WebService=self.Name, Site=self._Site, ServerGroup=self._ServerGroup, GatewayGroup=GatewayGroup, Alias=Alias, GatewayPorts=GatewayPorts)
  def get_all_krp_rules(self):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_all_krp_rules`. '''
    return self._connection.get_all_krp_rules(Site=self._Site, ServerGroup=self._ServerGroup, WebService=self.Name)
  def create_krp_rule(self, GatewayGroup=None, Alias=None, GatewayPorts=[], ServerCertificate=None, OutboundRules=[], ClientAuthenticationAuthorities=None, Name=None, update=False):
    ''' See :py:meth:`imperva_sdk.MxConnection.create_krp_rule`. '''
    return self._connection.create_krp_rule(WebService=self.Name, Site=self._Site, ServerGroup=self._ServerGroup, GatewayGroup=GatewayGroup, Alias=Alias, GatewayPorts=GatewayPorts, ServerCertificate=ServerCertificate, OutboundRules=OutboundRules, ClientAuthenticationAuthorities=ClientAuthenticationAuthorities, Name=None, update=update)
  def delete_krp_rule(self, GatewayGroup=None, Alias=None, GatewayPorts=[]):
    ''' See :py:meth:`imperva_sdk.MxConnection.delete_krp_rule`. '''
    return self._connection.delete_krp_rule(WebService=self.Name, Site=self._Site, ServerGroup=self._ServerGroup, GatewayGroup=GatewayGroup, Alias=Alias, GatewayPorts=GatewayPorts)
  def get_trp_rule(self, ServerIp=None, ListenerPorts=[]):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_trp_rule`. '''
    return self._connection.get_trp_rule(WebService=self.Name, Site=self._Site, ServerGroup=self._ServerGroup, ServerIp=ServerIp, ListenerPorts=ListenerPorts)
  def get_all_trp_rules(self):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_all_trp_rules`. '''
    return self._connection.get_all_trp_rules(Site=self._Site, ServerGroup=self._ServerGroup, WebService=self.Name)
  def create_trp_rule(self, ServerIp=None, ListenerPorts=[], ServerSidePort=None, EncryptServerConnection=None, Certificate=None, Name=None, update=False):
    ''' See :py:meth:`imperva_sdk.MxConnection.create_trp_rule`. '''
    return self._connection.create_trp_rule(WebService=self.Name, Site=self._Site, ServerGroup=self._ServerGroup, ServerIp=ServerIp, ListenerPorts=ListenerPorts, ServerSidePort=ServerSidePort, EncryptServerConnection=EncryptServerConnection, Certificate=Certificate, Name=None, update=update)
  def delete_trp_rule(self, ServerIp=None, ListenerPorts=[]):
    ''' See :py:meth:`imperva_sdk.MxConnection.delete_trp_rule`. '''
    return self._connection.delete_trp_rule(WebService=self.Name, Site=self._Site, ServerGroup=self._ServerGroup, ServerIp=ServerIp, ListenerPorts=ListenerPorts)
  def get_web_application(self, Name=None):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_web_application`. '''
    return self._connection.get_web_application(WebService=self.Name, Site=self._Site, ServerGroup=self._ServerGroup, Name=Name)
  def get_all_web_applications(self):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_all_web_applications`. '''
    return self._connection.get_all_web_applications(Site=self._Site, ServerGroup=self._ServerGroup, WebService=self.Name)
  def create_web_application(self, Name=None, LearnSettings=None, ParseOcspRequests=None, RestrictMonitoringToUrls=None, IgnoreUrlsDirectories=None, Profile=None, Mappings=None, update=False):
    ''' See :py:meth:`imperva_sdk.MxConnection.create_web_application`. '''
    return self._connection.create_web_application(WebService=self.Name, Site=self._Site, ServerGroup=self._ServerGroup, Name=Name, LearnSettings=LearnSettings, ParseOcspRequests=ParseOcspRequests, RestrictMonitoringToUrls=RestrictMonitoringToUrls, IgnoreUrlsDirectories=IgnoreUrlsDirectories, Profile=Profile, Mappings=Mappings, update=update)
  def delete_web_application(self, Name=None):
    ''' See :py:meth:`imperva_sdk.MxConnection.delete_web_application`. '''
    return self._connection.delete_web_application(WebService=self.Name, Site=self._Site, ServerGroup=self._ServerGroup, Name=Name)

  def get_all_plugins(self):
    """ Exports (from current MX connection) all plugins defined for the current Web Service. """
    return self._connection._mx_api('GET', '/conf/webServices/%s/%s/%s/plugins' % (self._Site, self._ServerGroup, self.Name))

  def update_all_plugins(self, swagger_json_list=None, plugins_definitions=None, print_payload=False):
    """ Updates all plugins defined for current Web Service.
    Input should be either an alrready exported plugins object or a list of swagger JSON objects."""
    if (swagger_json_list and plugins_definitions) or (not swagger_json_list and not plugins_definitions):
      raise MxException("Must define either plugins_definitions or swagger_json_list parameter")
    data = plugins_definitions or _swagger_to_plugins(swaggers=swagger_json_list)
    if print_payload:
      print(json.dumps(data, sort_keys=True, indent=4, separators=(',', ': ')))
    return self._connection._mx_api('PUT', '/conf/webServices/%s/%s/%s/plugins' % (self._Site, self._ServerGroup, self.Name), data=json.dumps(data))
  #
  # Web Service extra functions
  #
  def krp_xff_enable(self):
    '''
    For AWS KRP enable XFF. Use "X-Forwarded-For" client IP address from any proxy (ELB) and pass the IP forward in XFF header (client IP).

    Modifies ForwardedConnections and ForwardedClientIp attributes.
    '''
    ForwardedConnections = {'useHttpForwardingHeader': True, 'forwardedConnections': [{'headerName': 'X-Forwarded-For', 'proxyIpGroup': '', 'operation': 'add'}]}
    if self._ForwardedConnections:
      for current_fconnection in self._ForwardedConnections['forwardedConnections']:
        if current_fconnection['headerName'] == 'X-Forwarded-For' and current_fconnection['proxyIpGroup'] == '':
          del ForwardedConnections['forwardedConnections']
          break
    self._connection._mx_api('PUT', '/conf/webServices/%s/%s/%s/forwardedConnections' % (self._Site, self._ServerGroup, self.Name), data=json.dumps(ForwardedConnections))
    self._ForwardedConnections = {'useHttpForwardingHeader': True, 'forwardedConnections': [{'headerName': 'X-Forwarded-For', 'proxyIpGroup': ''}]}
    ForwardedClientIp = {'forwardHeaderName': 'X-Forwarded-For', 'forwardClientIP': True}
    self._connection._mx_api('PUT', '/conf/webServices/%s/%s/%s/forwardedClientIp' % (self._Site, self._ServerGroup, self.Name), data=json.dumps(ForwardedClientIp))
    self._ForwardedClientIp = ForwardedClientIp
    return True
  def krp_xff_disable(self):
    '''
    For AWS KRP disable XFF.

    Modifies ForwardedConnections and ForwardedClientIp attributes.
    '''
    ForwardedConnections = {'useHttpForwardingHeader': False}
    if self._ForwardedConnections:
      for current_fconnection in self._ForwardedConnections['forwardedConnections']:
        if current_fconnection['headerName'] == 'X-Forwarded-For' and current_fconnection['proxyIpGroup'] == '':
          ForwardedConnections['forwardedConnections'] = [{'headerName': 'X-Forwarded-For', 'proxyIpGroup': '', 'operation': 'remove'}]
          break
    self._connection._mx_api('PUT', '/conf/webServices/%s/%s/%s/forwardedConnections' % (self._Site, self._ServerGroup, self.Name), data=json.dumps(ForwardedConnections))
    self._ForwardedConnections = {}
    ForwardedClientIp = {'forwardHeaderName': 'X-Forwarded-For', 'forwardClientIP': False}
    self._connection._mx_api('PUT', '/conf/webServices/%s/%s/%s/forwardedClientIp' % (self._Site, self._ServerGroup, self.Name), data=json.dumps(ForwardedClientIp))
    self._ForwardedClientIp = {}
    return True
  def upload_ssl_certificate(self, SslKeyName=None, Hsm=False, Private=None, Certificate=None):
    ''' Uploads SSL Certificate to Web Service. See :py:attr:`imperva_sdk.WebService.SslKeys`. '''
    ssl_key = {
      'format': 'pem',
      'hsm': Hsm,
      'private': Private,
      'certificate': Certificate
    }
    self._connection._mx_api('POST', '/conf/webServices/%s/%s/%s/sslCertificates/%s' % (self._Site, self._ServerGroup, self.Name, SslKeyName), data=json.dumps(ssl_key))
    self._SslKeys = WebService._get_ssl_keys(self._connection, Name=self.Name, ServerGroup=self._ServerGroup, Site=self._Site)
    return True
  def delete_ssl_certificate(self, SslKeyName=None):
    ''' Deletes SSL Certificate from Web Service. See :py:attr:`imperva_sdk.WebService.SslKeys`. '''
    self._connection._mx_api('DELETE', '/conf/webServices/%s/%s/%s/sslCertificates/%s' % (self._Site, self._ServerGroup, self.Name, SslKeyName))
    self._SslKeys = WebService._get_ssl_keys(self._connection, Name=self.Name, ServerGroup=self._ServerGroup, Site=self._Site)
    return True


def _swagger_to_plugins(swaggers=None):
  paths_list = []
  unique_paths = {}
  for swagger in swaggers:
    _parse_single_swagger_json(swagger, paths_list, unique_paths)
  if len(paths_list) == 0:
    return []
  _sort_and_build_path_hierarchy(paths_list)
  plugins_depth = _generate_plugins_def_per_depth(paths_list)
  final_plugins = _get_ordered_plugins(plugins_depth)
  return {"plugins": final_plugins}


def _remove_path_parameter_recursively(paths_list, path_ind, prefix):
  path_dict = paths_list[path_ind]
  path_dict["depth"] += 1
  path_dict["path"] = prefix + path_dict["path"][len(prefix) + 2:]
  for child_ind in path_dict["children"]:
    _remove_path_parameter_recursively(paths_list, child_ind, prefix)


def _parse_single_swagger_json(swagger, paths_list, unique_paths):
  swagger_version = swagger.get("swagger", None) or swagger.get("openapi", None)
  if swagger_version is None or swagger_version[0:3] not in ["2.0", "3.0"]:
    print("Not swagger JSON or not supported swagger version")
    return None
  base_path = ""
  if "basePath" in swagger:
    base_path = swagger["basePath"]
  for path in swagger['paths']:
    full_path = base_path + path
    if full_path.find("{") > 0:
      if unique_paths.get(full_path, -1) == -1:
        unique_paths[full_path] = len(paths_list)
        paths_list.append({"path": full_path, "parent": -1, "children": [], "artificial": False, "depth": 0})
      else:
        paths_list[unique_paths[full_path]]["artificial"] = False
      tokens = full_path.split("}")
      token_ind = 1
      while token_ind < len(tokens) - 1:
        truncated_path = "}".join(tokens[0:token_ind]) + "}"
        token_ind = token_ind + 1
        if unique_paths.get(truncated_path, -1) == -1:
          unique_paths[truncated_path] = len(paths_list)
          paths_list.append({"path": truncated_path, "parent": -1, "children": [], "artificial": True, "depth": 0})


def _sort_and_build_path_hierarchy(paths_list):
  paths_list.sort(key=lambda k: k['path'])
  curr_ind = 1
  while curr_ind < len(paths_list):
    prev_ind = curr_ind - 1
    prev_path_len = len(paths_list[prev_ind]["path"])
    while paths_list[curr_ind]["path"][0:prev_path_len] != paths_list[prev_ind]["path"] and paths_list[prev_ind]["parent"] > -1:
      prev_ind = paths_list[prev_ind]["parent"]
      prev_path_len = len(paths_list[prev_ind]["path"])
    if paths_list[curr_ind]["path"][0:prev_path_len] == paths_list[prev_ind]["path"]:
      paths_list[curr_ind]["parent"] = prev_ind
      paths_list[prev_ind]["children"].append(curr_ind)
    curr_ind = curr_ind + 1


def _update_plugin_path_regexp(plugin, paths_list, path_dict, right_curl_ind):
  if len(path_dict["children"]) > 0:
    plugin["pathReplace"] += '$3'
    concat_separator = "(("
    for child_ind in path_dict["children"]:
      plugin["pathRegexp"] += concat_separator
      concat_separator = "|"
      child_path = paths_list[child_ind]["path"]
      last_offset = child_path.find("{")
      if last_offset == -1:
        last_offset = len(child_path)
      plugin["pathRegexp"] += child_path[right_curl_ind - 1:last_offset].replace("/", "\\/")
    if not path_dict["artificial"]:
      plugin["pathRegexp"] += "|$"
    plugin["pathRegexp"] += ").*)"


def _generate_plugins_def_per_depth(paths_list):
  plugins_depth = [[]]
  path_ind = 0
  while path_ind < len(paths_list):
    path_dict = paths_list[path_ind]
    left_curl_ind = path_dict["path"].find("{")
    if left_curl_ind > 0:
      right_curl_ind = path_dict["path"].find("}")
      parm_name = path_dict["path"][left_curl_ind + 1:right_curl_ind]
      plugin = {
        'pluginType': 'URL to Parameter',
        'pathRegexp': '(' + path_dict["path"][0:left_curl_ind].replace("/", "\\/") + ')(.*?)',
        'pathReplace': '$1' + parm_name,
        'paramValue': '$2',
        'paramName': parm_name
      }
      _remove_path_parameter_recursively(paths_list, path_ind, path_dict["path"][0:left_curl_ind] + parm_name)
      _update_plugin_path_regexp(plugin, paths_list, path_dict, right_curl_ind)
      if len(plugins_depth) == path_dict["depth"]:
        plugins_depth.append([])
      plugins_depth[path_dict["depth"]].append(plugin)
    path_ind += 1
  return plugins_depth


def _get_ordered_plugins(plugins_depth):
  final_plugins = []
  priority = 1
  for depth_list in plugins_depth:
    for plugin_dict in depth_list:
      plugin_dict["pluginOrder"] = priority
      priority += 1
      final_plugins.append(plugin_dict)
  return final_plugins
