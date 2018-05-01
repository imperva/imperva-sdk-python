# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *
    
class KrpRule(MxObject):
  ''' 
  MX KRP (Reverse Proxy) Rules (Inbound + Outbound) Class 

  Each KRP rule must have at least one outbound rule.

  The `GatewayGroup` and `Alias` attributes need to be available in the MX (e.g. created when GW registers) to be used by KRP rules.

  .. note:: Edit is not implemented for the KrpRule attriebutes.

  >>> ws.create_krp_rule(Alias="alias name", GatewayGroup="gg name", GatewayPorts=[8443], ServerCertificate="key name", OutboundRules=[{'priority': 1, 'externalHost': 'www.imperva.com', 'urlPrefix': '/login', 'encrypt': True, 'internalIpHost': '192.168.0.1', 'serverPort': 443}])
  '''
  
  # Store created KRP Rule objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = KrpRule._exists(connection=kwargs['connection'], Site=kwargs['Site'], ServerGroup=kwargs['ServerGroup'], WebService=kwargs['WebService'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None, Site=None, ServerGroup=None, WebService=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'KrpRule':
        if cur_obj.Name == Name and cur_obj._Site == Site and cur_obj._ServerGroup == ServerGroup and cur_obj._WebService == WebService:
          return cur_obj
    return None

  
  def __init__(self, connection=None, WebService=None, Name=None, ServerGroup=None, Site=None, GatewayGroup=None, Alias=None, GatewayPorts=[], ServerCertificate=None, OutboundRules=[], ClientAuthenticationAuthorities=None):
    super(KrpRule, self).__init__(connection=connection, Name=Name)
    validate_string(WebService=WebService, Site=Site, ServerGroup=ServerGroup, GatewayGroup=GatewayGroup, Alias=Alias)
    #validate_int_list(GatewayPorts=GatewayPorts)
    self._Name = Name
    self._Site = Site
    self._ServerGroup = ServerGroup
    self._WebService = WebService
    self._GatewayGroup = GatewayGroup
    self._Alias = Alias 
    self._GatewayPorts = GatewayPorts 
    self._ServerCertificate = ServerCertificate
    self._OutboundRules = OutboundRules 
    self._ClientAuthenticationAuthorities = ClientAuthenticationAuthorities

  #
  # KRP Rule parameters
  # 
  @property
  def Name(self):
    ''' KRP Rule internal imperva_sdk name (you can disregard)  '''
    return self._Name
  @property
  def GatewayGroup(self):
    ''' The name of the server group that contains the gateways on which the alias was created (string). Needs to be available before KRP rule creation. '''
    return self._GatewayGroup
  @property
  def Alias(self):
    ''' The name of the Gateway alias that defines the inbound KRP rule (string). Needs to be available before KRP rule creation. '''
    return self._Alias
  @property
  def GatewayPorts(self):
    ''' 
    The port that defines the inbound KRP rule (list of int). In most functions you can specify only one port in the list even if there are more -

    >>> ws.create_krp_rule(Alias="aa", GatewayGroup="giora-tmp2", GatewayPorts=[443, 8443], ServerCertificate="key name", OutboundRules=[{'priority': 1, 'externalHost': 'www.imperva.com', 'urlPrefix': '/login', 'encrypt': True, 'internalIpHost': '192.168.0.1', 'serverPort': 443}])
    >>> ws.delete_krp_rule(Alias="aa", GatewayGroup="giora-tmp2", GatewayPorts=[443])                     
    '''
    return self._GatewayPorts
  @property
  def ServerCertificate(self):
    ''' The SSL Key name of the certificate which will be presented to the client (string). See :py:attr:`imperva_sdk.WebService.SslKeys`. '''
    return self._ServerCertificate
  @property
  def OutboundRules(self):
    ''' 
    Map of Outbound KRP rules, at least one rule is required.
 
    >>> krp_rules = ws.get_all_krp_rules()
    >>> krp_rules[0].OutboundRules
    [{u'internalIpHost': u'192.168.0.1', u'encrypt': True, 'clientAuthenticationRules': None, u'urlPrefix': u'/login', 'priority': 1, u'serverPort': 443, u'externalHost': u'www.imperva.com', u'validateServerCertificate': False}]

    * externalHost (string) - Specify the external host name for which this rule will be applied. Optional. When missing - external host is "any".
    * urlPrefix (string) - Specify the prefix of URLs (for example, /login/) for which traffic is to be directed to. Optional. When missing - url prefix is "any".
    * internalIpHost (string) - The IP address or the hostname of the Web server to which traffic is forwarded.
    * serverPort (int) - The port number on the Web server to which traffic is forwarded.
    * encrypt (boolean) - Indicate whether to encrypt the connection between the SecureSphere gateway and the Web server. Default=False.
    * clientAuthenticationRules (string) - The Client Authentication Rules that determine the course of action taken when certificate validation succeeds or fails. Optional.
    * validateServerCertificate (boolean) - Validate the certificate presented by the web server. Optional (Default=False)

    '''
    return self._OutboundRules
  @property
  def ClientAuthenticationAuthorities(self):
    ''' A Certificate Authority Group to associate with web server (string) '''
    return self._ClientAuthenticationAuthorities
    
  #
  # KRP Rule internal Functions
  #
  @staticmethod
  def _get_all_krp_rules(connection, ServerGroup=None, Site=None, WebService=None):
    validate_string(Site=Site, ServerGroup=ServerGroup, WebService=WebService)
    res = connection._mx_api('GET', '/conf/webServices/%s/%s/%s/krpInboundRules' % (Site, ServerGroup, WebService))
    try:
      krp_rules_list = res['inboundKrpRules']
    except:
      raise MxException("Failed getting KRP rules")
    krp_rules_objects = []
    for rule in krp_rules_list:
      krp_rules_objects.append(connection.get_krp_rule(Site=Site, ServerGroup=ServerGroup, WebService=WebService, GatewayGroup=rule['gatewayGroupName'], Alias=rule['aliasName'], GatewayPorts=rule['gatewayPorts']))
    return krp_rules_objects
  @staticmethod
  def _get_krp_rule(connection, ServerGroup=None, Site=None, WebService=None, GatewayGroup=None, Alias=None, GatewayPorts=None):
    validate_string(Site=Site, ServerGroup=ServerGroup, WebService=WebService, GatewayGroup=GatewayGroup, Alias=Alias)
    Name = '%s-%s-%s' % (GatewayGroup, Alias, str(GatewayPorts))
    obj_exists = KrpRule._exists(connection=connection, Name=Name, Site=Site, ServerGroup=ServerGroup, WebService=WebService)
    if obj_exists:
      return obj_exists
    try:
      inbound_rule = connection._mx_api('GET', '/conf/webServices/%s/%s/%s/krpInboundRules/%s/%s/%d' % (Site, ServerGroup, WebService, GatewayGroup, Alias, GatewayPorts[0]))
    except: 
      return None
    if 'serverCertificate' not in inbound_rule: inbound_rule['serverCertificate'] = None
    if 'clientAuthenticationAuthorities' not in inbound_rule: inbound_rule['clientAuthenticationAuthorities'] = None
    inbound_rule['OutboundRules'] = []
    outbound_rules = connection._mx_api('GET', '/conf/webServices/%s/%s/%s/krpInboundRules/%s/%s/%d/krpOutboundRules' % (Site, ServerGroup, WebService, GatewayGroup, Alias, GatewayPorts[0]))
    for outbound in outbound_rules['outboundKrpRules']:
      outbound_rule = connection._mx_api('GET', '/conf/webServices/%s/%s/%s/krpInboundRules/%s/%s/%d/krpOutboundRules/%d' % (Site, ServerGroup, WebService, GatewayGroup, Alias, GatewayPorts[0], outbound['priority']))
      outbound_rule['priority'] = outbound['priority']
      if not 'externalHost' in outbound_rule: outbound_rule['externalHost'] = None
      if not 'urlPrefix' in outbound_rule: outbound_rule['urlPrefix'] = None
      if not 'clientAuthenticationRules' in outbound_rule: outbound_rule['clientAuthenticationRules'] = None
      inbound_rule['OutboundRules'].append(outbound_rule)
    return KrpRule(connection=connection, Name=Name, WebService=WebService, ServerGroup=ServerGroup, Site=Site, GatewayGroup=GatewayGroup, Alias=Alias, GatewayPorts=inbound_rule['gatewayPorts'], ServerCertificate=inbound_rule['serverCertificate'], OutboundRules=inbound_rule['OutboundRules'], ClientAuthenticationAuthorities=inbound_rule['clientAuthenticationAuthorities'])
  @staticmethod
  def _create_krp_rule(connection, WebService=None, ServerGroup=None, Site=None, GatewayGroup=None, Alias=None, GatewayPorts=[], ServerCertificate=None, ClientAuthenticationAuthorities=None, OutboundRules=[], Name=None, update=False):
    validate_string(Site=Site, ServerGroup=ServerGroup, WebService=WebService, GatewayGroup=GatewayGroup, Alias=Alias)
    #validate_int_list(GatewayPorts=GatewayPorts)
    body = {
      'outboundRules': {}
    }
    if not OutboundRules:
      raise MxException("KRP rule must have at least one outbound rule")
    for outbound in OutboundRules:
      if not 'priority' in outbound:
        raise MxException("Outbound rule must have 'priority' parameter")
      body['outboundRules'][str(outbound['priority'])] = {}
      for outbound_key in outbound:
        if outbound[outbound_key] and outbound_key != 'priority':
          body['outboundRules'][str(outbound['priority'])][outbound_key] = outbound[outbound_key]
    krp = connection.get_krp_rule(Site=Site, ServerGroup=ServerGroup, WebService=WebService, GatewayGroup=GatewayGroup, Alias=Alias, GatewayPorts=GatewayPorts)
    if krp:
      if update:
        # KRP rule already exists, we don't have KRP update yet so we'll delete the existing rule and create the new one from parameters(even if they're the same)
        connection.delete_krp_rule(Site=Site, ServerGroup=ServerGroup, WebService=WebService, GatewayGroup=GatewayGroup, Alias=Alias, GatewayPorts=GatewayPorts)
      else:
        raise MxException("KRP Rule already exists")
    if ServerCertificate: body['serverCertificate'] = ServerCertificate
    if ClientAuthenticationAuthorities: body['clientAuthenticationAuthorities'] = ClientAuthenticationAuthorities
    connection._mx_api('POST', '/conf/webServices/%s/%s/%s/krpInboundRules/%s/%s/%d' % (Site, ServerGroup, WebService, GatewayGroup, Alias, GatewayPorts[0]), data=json.dumps(body))
    return KrpRule(connection=connection, Name='%s-%s-%s' % (GatewayGroup, Alias, str(GatewayPorts)), WebService=WebService, ServerGroup=ServerGroup, Site=Site, GatewayGroup=GatewayGroup, Alias=Alias, GatewayPorts=GatewayPorts, ServerCertificate=ServerCertificate, OutboundRules=OutboundRules, ClientAuthenticationAuthorities=ClientAuthenticationAuthorities)
  @staticmethod
  def _delete_krp_rule(connection, WebService=None, ServerGroup=None, Site=None, GatewayGroup=None, Alias=None, GatewayPorts=[]):
    validate_string(WebService=WebService, ServerGroup=ServerGroup, Site=Site, GatewayGroup=GatewayGroup, Alias=Alias)
    #validate_int_list(GatewayPorts=GatewayPorts)
    krp = connection.get_krp_rule(Site=Site, ServerGroup=ServerGroup, WebService=WebService, GatewayGroup=GatewayGroup, Alias=Alias, GatewayPorts=GatewayPorts)
    if krp:
      connection._mx_api('DELETE', '/conf/webServices/%s/%s/%s/krpInboundRules/%s/%s/%d' % (Site, ServerGroup, WebService, GatewayGroup, Alias, GatewayPorts[0]))
      connection._instances.remove(krp)
      del krp
    else:
      raise MxException("KRP Rule does not exist")
    return True

