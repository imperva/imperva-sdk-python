# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *
    
class TrpRule(MxObject):
  ''' 
  MX TRP (Transparent Reverse Proxy) Rules Class 

  '''
  
  # Store created TRP Rule objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = TrpRule._exists(connection=kwargs['connection'], Site=kwargs['Site'], ServerGroup=kwargs['ServerGroup'], WebService=kwargs['WebService'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None, Site=None, ServerGroup=None, WebService=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'TrpRule':
        if cur_obj.Name == Name and cur_obj._Site == Site and cur_obj._ServerGroup == ServerGroup and cur_obj._WebService == WebService:
          return cur_obj
    return None

  
  def __init__(self, connection=None, WebService=None, Name=None, ServerGroup=None, Site=None, ListenerPorts=[], ServerIp=None, ServerSidePort=None, EncryptServerConnection=None, Certificate=None):
    super(TrpRule, self).__init__(connection=connection, Name=Name)
    self._Name = Name
    self._Site = Site
    self._ServerGroup = ServerGroup
    self._WebService = WebService
    self._ListenerPorts = ListenerPorts
    self._ServerIp = ServerIp
    self._ServerSidePort = ServerSidePort
    self._EncryptServerConnection = EncryptServerConnection
    self._Certificate = Certificate


  #
  # TRP Rule parameters
  # 
  @property
  def Name(self):
    ''' TRP Rule internal imperva_sdk name (you can disregard)  '''
    return self._Name
  @property
  def ListenerPorts(self):
    ''' 
    The port that defines the TRP rule (list of int). In most functions you can specify only one port in the list even if there are more.
    '''
    return self._ListenerPorts
  @property
  def ServerIp(self):
    ''' The protected server IP. '''
    return self._ServerIp
  @property
  def ServerSidePort(self):
    ''' 
    The HTTP/HTTPS port on the server side.
    '''
    return self._ServerSidePort
  @property
  def EncryptServerConnection(self):
    ''' Whether web server is HTTP or HTTPS (boolean) '''
    return self._EncryptServerConnection
  @property
  def Certificate(self):
    ''' Certificate name if TRP listener is HTTPS '''
    return self._Certificate
    
  #
  # TRP Rule internal Functions
  #
  @staticmethod
  def _get_all_trp_rules(connection, ServerGroup=None, Site=None, WebService=None):
    validate_string(Site=Site, ServerGroup=ServerGroup, WebService=WebService)
    try:
      res = connection._mx_api('GET', '/conf/webServices/%s/%s/%s/trpRules' % (Site, ServerGroup, WebService))
    except MxExceptionNotFound:
      # For older versions that don't support trpRules API we return an empty list
      return []
    try:
      trp_rules_list = res['trpRules']
    except:
      raise MxException("Failed getting TRP rules")
    trp_rules_objects = []
    for rule in trp_rules_list:
      trp_rules_objects.append(connection.get_trp_rule(Site=Site, ServerGroup=ServerGroup, WebService=WebService, ServerIp=rule['serverIp'], ListenerPorts=rule['listenerPortList']))
    return trp_rules_objects
  @staticmethod
  def _get_trp_rule(connection, ServerGroup=None, Site=None, WebService=None, GatewayGroup=None, ServerIp=None, ListenerPorts=None):
    Name = '%s-%s' % (ServerIp, str(ListenerPorts))
    obj_exists = TrpRule._exists(connection=connection, Name=Name, Site=Site, ServerGroup=ServerGroup, WebService=WebService)
    if obj_exists:
      return obj_exists
    try:
      rule = connection._mx_api('GET', '/conf/webServices/%s/%s/%s/trpRules/%s/%d' % (Site, ServerGroup, WebService, ServerIp, ListenerPorts[0]))
    except: 
      return None
    Certificate = None if 'certificate' not in rule else rule['certificate']
    return TrpRule(connection=connection, Name=Name, WebService=WebService, ServerGroup=ServerGroup, Site=Site, ServerIp=ServerIp, ListenerPorts=ListenerPorts, ServerSidePort=rule['serverSidePort'], EncryptServerConnection=rule['encryptServerConnection'], Certificate=Certificate)
  @staticmethod
  def _create_trp_rule(connection, WebService=None, ServerGroup=None, Site=None, Name=None, ListenerPorts=[], ServerIp=None, ServerSidePort=None, EncryptServerConnection=None, Certificate=None, update=False):
    trp = connection.get_trp_rule(Site=Site, ServerGroup=ServerGroup, WebService=WebService, ListenerPorts=ListenerPorts, ServerIp=ServerIp)
    if trp:
      if update:
        # TRP rule already exists, we don't have TRP update yet so we'll delete the existing rule and create the new one from parameters(even if they're the same)
        connection.delete_trp_rule(Site=Site, ServerGroup=ServerGroup, WebService=WebService, ServerIp=ServerIp, ListenerPorts=ListenerPorts)
      else:
        raise MxException("TRP Rule already exists")
    body = {
      'encryptServerConnection': EncryptServerConnection,
      'serverSidePort': ServerSidePort
    }
    if Certificate: body['certificate'] = Certificate
    connection._mx_api('POST', '/conf/webServices/%s/%s/%s/trpRules/%s/%d' % (Site, ServerGroup, WebService, ServerIp, ListenerPorts[0]), data=json.dumps(body))
    return TrpRule(connection=connection, Name='%s-%s' % (ServerIp, str(ListenerPorts)), WebService=WebService, ServerGroup=ServerGroup, Site=Site, ListenerPorts=ListenerPorts, ServerIp=ServerIp, ServerSidePort=ServerSidePort, EncryptServerConnection=EncryptServerConnection, Certificate=Certificate)
  @staticmethod
  def _delete_trp_rule(connection, WebService=None, ServerGroup=None, Site=None, ServerIp=None, ListenerPorts=[]):
    trp = connection.get_trp_rule(Site=Site, ServerGroup=ServerGroup, WebService=WebService, ServerIp=ServerIp, ListenerPorts=ListenerPorts)
    if trp:
      connection._mx_api('DELETE', '/conf/webServices/%s/%s/%s/trpRules/%s/%d' % (Site, ServerGroup, WebService, ServerIp, ListenerPorts[0]))
      connection._instances.remove(trp)
      del trp
    else:
      raise MxException("TRP Rule does not exist")
    return True

