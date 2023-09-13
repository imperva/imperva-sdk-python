# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class ServerGroup(MxObject):
  ''' 
  MX Server Group Class Updated

  >>> sg = site.create_server_group("my server group")
  >>> sg.OperationMode = 'active'
  '''

  # Store created server group objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = ServerGroup._exists(connection=kwargs['connection'], Site=kwargs['Site'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Site=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'ServerGroup':
        if cur_obj.Name == Name and cur_obj._Site == Site:
          return cur_obj
    return None
    
  def __init__(self, connection=None, Name=None, Site=None, OperationMode=None, ProtectedIps=[], ServerIps=[]):
    super(ServerGroup, self).__init__(connection=connection, Name=Name)
    validate_string(Name=Name, Site=Site)
    self._Site = Site
    self._OperationMode = OperationMode
    self._ProtectedIps = ProtectedIps
    self._ServerIps = MxList(ServerIps)

  #
  # Server Group Parameters
  #
  @property
  def Name(self):
    ''' Server Group Name '''
    return self._Name

  @Name.setter
  def Name(self, Name):
    validate_string(Name=Name)
    ServerGroup._update_server_group(self._connection, Name=self._Name, Site=self._Site, Parameter='name', Value=Name)
    self._Name = Name

  @property
  def OperationMode(self):
    ''' Server Group Operation Mode - 'simulation', 'active' or 'disabled' '''
    return self._OperationMode

  @property
  def ProtectedIps(self):
    ''' Protected IPs - e.g. [{'ip': '192.168.1.1', 'gateway-group': 'gg name'}, {'ip': '192.168.1.2', 'gateway-group': 'gg name'}] '''
    return self._ProtectedIps

  @ProtectedIps.setter
  def ProtectedIps(self, ProtectedIps):
    for old_ip in self._ProtectedIps:
      if old_ip not in ProtectedIps:
        # Delete previous protected IP
        self._connection._mx_api('DELETE', '/conf/serverGroups/%s/%s/protectedIPs/%s?gatewayGroup=%s' % (self._Site, self._Name, old_ip['ip'], old_ip['gateway-group']))
    for new_ip in ProtectedIps:
      if new_ip not in self._ProtectedIps:
        # Create new protected IP
        self._connection._mx_api('POST', '/conf/serverGroups/%s/%s/protectedIPs/%s?gatewayGroup=%s' % (self._Site, self._Name, new_ip['ip'], new_ip['gateway-group']), data=json.dumps({}))
    self._ProtectedIps = ProtectedIps

  @property
  def ServerIps(self):
    ''' Server IPs - e.g. ["192.168.1.1","192.168.1.2"] '''
    return self._ServerIps

  @ServerIps.setter
  def ServerIps(self, ServerIps):
    for old_ip in self._ServerIps:
      if old_ip not in ServerIps:
        # Delete previous server IP
        self._connection._mx_api('DELETE', '/conf/services/%s/%s/servers/%s' % (self._Site, self._Name, old_ip))
    for new_ip in ServerIps:
      if new_ip not in self._ServerIps:
        # Create new server IP
        self._connection._mx_api('POST', '/conf/serverGroups/%s/%s/servers/%s' % (self._Site, self._Name, new_ip), data=json.dumps({}))
    self._ServerIps = ServerIps


  @OperationMode.setter
  def OperationMode(self, OperationMode):
    valid_modes = ['simulation', 'active', 'disabled']
    if OperationMode not in valid_modes:
      raise MxException("OperationMode must be one of - %s" % ",".join(valid_modes))
    ServerGroup._update_server_group(self._connection, Name=self._Name, Site=self._Site, Parameter='operationMode', Value=OperationMode)
    self._OperationMode = OperationMode
    
  #	
  # Server Group functions (should be called from other objects like MxConnection)
  #
  @staticmethod  
  def _get_all_server_groups(connection, Site=None):
    validate_string(Site=Site)
    res = connection._mx_api('GET', '/conf/serverGroups/%s' % Site)
    try:
      sg_names = res['server-groups']
    except:
      raise MxException("Failed getting server groups")
    sgs = []
    for sg_name in sg_names:
      sgs.append(ServerGroup._get_server_group(connection=connection, Name=sg_name, Site=Site))
    return sgs
  @staticmethod
  def _get_server_group(connection, Name=None, Site=None):
    validate_string(Name=Name, Site=Site)
    obj_exists = ServerGroup._exists(connection=connection, Site=Site, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/serverGroups/%s/%s' % (Site, Name))
      protected_ips = connection._mx_api('GET', '/conf/serverGroups/%s/%s/protectedIPs' % (Site, Name))
      # get IPs for this server group for the OS connections
      os_conns = connection._mx_api('GET', '/conf/serverGroups/%s/%s/servers' % (Site, Name))
      serverIps = [con["ip"] for con in os_conns.get("connections")]
      return ServerGroup(connection=connection, Name=res['name'], Site=Site, OperationMode=res['operationMode'],
                         ProtectedIps=protected_ips['protected-ips'], ServerIps=serverIps)
    except:
      return None
  @staticmethod
  def _create_server_group(connection, Name=None, Site=None, OperationMode=None, ProtectedIps=[], ServerIps=[], update=False):
    validate_string(Name=Name, Site=Site)
    sg = connection.get_server_group(Name=Name, Site=Site)
    if sg:
      if update:
        if OperationMode and OperationMode != sg.OperationMode:
          sg.OperationMode = OperationMode
        if ProtectedIps:
          sg.ProtectedIps = ProtectedIps
        if ServerIps:
          sg.ServerIps = ServerIps
        return sg
      else:
        raise MxException("Server Group already exists")
    connection._mx_api('POST', '/conf/serverGroups/%s/%s' % (Site, Name))
    sg = connection.get_server_group(Name=Name, Site=Site)
    if OperationMode and OperationMode != sg.OperationMode:
      sg.OperationMode = OperationMode
    if ProtectedIps:
      sg.ProtectedIps = ProtectedIps
    if ServerIps:
      sg.ServerIps = ServerIps
    return sg
  @staticmethod
  def _delete_server_group(connection, Name=None, Site=None):
    validate_string(Name=Name, Site=Site)
    sg = connection.get_server_group(Name=Name, Site=Site)
    if sg:
      webServices = sg.get_all_web_services()
      if len(webServices) != 0:
        for webService in webServices:
          connection.delete_web_service(Name=webService.Name, ServerGroup=sg.Name, Site=Site)
      dabServices = sg.get_all_db_services()
      if len(dabServices) != 0:
        for dabService in dabServices:
          connection.delete_db_service(Name=dabService.Name, ServerGroup=sg.Name, Site=Site)         
    if sg:
      connection._mx_api('DELETE', '/conf/serverGroups/%s/%s' % (Site, Name))
      connection._instances.remove(sg)
      del sg
    else:
      raise MxException("Server Group '%s' does not exist" % Name)
    return True
  @staticmethod
  def _update_server_group(connection, Name=None, Site=None, Parameter=None, Value=None):
    body = { Parameter: Value }
    connection._mx_api('PUT', '/conf/serverGroups/%s/%s' % (Site, Name), data=json.dumps(body))
    return True
  
  #
  # Server Group child (web service) functions
  #
  def create_web_service(self, Name=None, ServerGroup=None, Site=None, Ports=[], SslPorts=[], ForwardedConnections={}, ForwardedClientIp={}, SslKeys=[], TrpMode=None, update=False):
    ''' See :py:meth:`imperva_sdk.MxConnection.create_web_service`. '''
    return self._connection.create_web_service(Name=Name, ServerGroup=self.Name, Site=self._Site, Ports=Ports, SslPorts=SslPorts, ForwardedConnections=ForwardedConnections, ForwardedClientIp=ForwardedClientIp, SslKeys=SslKeys, TrpMode=TrpMode, update=update)
  def delete_web_service(self, Name=None):
    ''' See :py:meth:`imperva_sdk.MxConnection.delete_web_service`. '''
    return self._connection.delete_web_service(Name=Name, Site=self._Site, ServerGroup=self.Name)
  def get_web_service(self, Name=None):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_web_service`. '''
    return self._connection.get_web_service(Name=Name, Site=self._Site, ServerGroup=self.Name)
  def get_all_web_services(self):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_all_web_services`. '''
    return self._connection.get_all_web_services(Site=self._Site, ServerGroup=self.Name)

  def create_db_service(self, Name=None, ServerGroup=None, Site=None, Ports=[], DefaultApp=None, DbMappings=[], TextReplacement=[], LogCollectors=[], DbServiceType=None, update=False):
    return self._connection.create_db_service(Name=Name, ServerGroup=self.Name, Site=self._Site, Ports=Ports, DefaultApp=DefaultApp, DbMappings=DbMappings, TextReplacement=TextReplacement, LogCollectors=LogCollectors, DbServiceType=DbServiceType, update=update)
  def create_db_service_pc(self, Name=None, ServerGroup=None, Site=None, Ports=[], DefaultApp=None, DbMappings=[], TextReplacement=[], LogCollectors=[], DbServiceType=None, update=False):
    return self._connection.create_db_service_pc(Name=Name, ServerGroup=self.Name, Site=self._Site, Ports=Ports, DefaultApp=DefaultApp, DbMappings=DbMappings, TextReplacement=TextReplacement, LogCollectors=LogCollectors, DbServiceType=DbServiceType, update=update)
  def delete_db_service(self, Name=None):
    return self._connection.delete_db_service(Name=Name, Site=self._Site, ServerGroup=self.Name)
  def get_db_service(self, Name=None):
    return self._connection.get_db_service(Name=Name, Site=self._Site, ServerGroup=self.Name)
  def get_all_db_services(self):
    try:
      return self._connection.get_all_db_services(Site=self._Site, ServerGroup=self.Name)
    except:
      return []
