# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class Action(MxObject):
  '''
  MX Action Class (part of Action Set)
  '''
  # Store created Action Set objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = Action._exists(connection=kwargs['connection'], Name=kwargs['Name'], ActionSet=kwargs['ActionSet'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None, ActionSet=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'Action':
        if cur_obj.Name == Name and cur_obj._ActionSet == ActionSet:
          return cur_obj
    return None

  def __init__(self, connection=None, Name=None, ActionSet=None, ActionType=None, Protocol=None, SyslogFacility=None, Host=None, SyslogLogLevel=None, SecondaryPort=None, ActionInterface=None, SecondaryHost=None, Message=None, Port=None):
    super(Action, self).__init__(connection=connection, Name=Name)
    validate_string(Name=Name)
    self._ActionSet = ActionSet
    self._ActionType = ActionType
    self._Protocol = Protocol
    self._SyslogFacility = SyslogFacility
    self._Host = Host
    self._SyslogLogLevel = SyslogLogLevel
    self._SecondaryPort = SecondaryPort
    self._ActionInterface = ActionInterface
    self._SecondaryHost = SecondaryHost
    self._Message = Message
    self._Port = Port

  #
  # Action Parameters
  #
  @property
  def Name(self):
    ''' The name of the Action (string) '''
    return self._Name
  @property
  def ActionType(self):
    ''' The type of the Action (GWSyslog / Syslog) '''
    return self._ActionType
  @property
  def Protocol(self):
    ''' The Action Syslog Protocol setting (TCP / UDP) '''
    return self._Protocol
  @property
  def SyslogFacility(self):
    ''' The Action Syslog Facility setting (USER / LOCAL0 / LOCAL1 ...) '''
    return self._SyslogFacility
  @property
  def Host(self):
    ''' The Action Syslog Host/IP setting (string) '''
    return self._Host
  @property
  def SyslogLogLevel(self):
    ''' The Action Syslog Level setting (INFO / DEBUG / ...) '''
    return self._SyslogLogLevel
  @property
  def SecondaryPort(self):
    ''' The Action Syslog Secondary Port setting (string) '''
    return self._SecondaryPort
  @property
  def ActionInterface(self):
    ''' 
    The Action Interface of the Action (string) 

    e.g. - "Gateway Log - Security Event - System Log (syslog) - JSON format (Extended)"

    '''
    return self._ActionInterface
  @property
  def SecondaryHost(self):
    ''' The Action Syslog Secondary Host setting (string) '''
    return self._SecondaryHost
  @property
  def Message(self):
    ''' 
    The Action Syslog Message setting. With SecureSphere placeholders, etc... (string) -

    >>> action.Message
    '{"header": {"vendor": "Imperva Inc.","product": "SecureSphere","product-version": "$!{SecureSphereVersion}","template-version":"1.0"},"create-time": "#DTFormat:%Y-%m-%dT%H:%M:%S%Z(${Violation.CreateTime})","gateway-name": "${Event.gateway}", "mx-ip": "$!{Event.struct.mxIp}", "server-group-name": "#jsonEscapeExtension($!{Event.violations.alert.serverGroupName})", "server-group-simulation-mode": "$!{Event.violations.alert.simulationMode}", "violation-type": "$!{Event.eventType}", "class": "$!{Event.violations.alert.alertType}", "description": "$!{Violation.Description}", "severity": "$!{Event.violations.alert.severity}", "service-name": "#jsonEscapeExtension($!{Event.serviceName})","application-name": "#jsonEscapeExtension($!{Environment.ApplicationName})","source-ip": "${Request.SourceIp}","source-port": "${Request.SourcePort}","protocol": "${Request.SourceProtocol}","dest-ip": "${Request.DestinationIp}","dest-port": "${Request.DestinationPort}","violation-id": "${Violation.Id}","violation-attributes": ${Violation.AttributesJSON},"policy-name": "#jsonEscapeExtension(${Violation.PolicyName})","action": "$!{Event.violations.alert.immediateAction}", "http": {"session-id": "$!{Request.Http.SessionId}","session-create-time": "#DTFormat:%Y-%m-%dT%H:%M:%S%Z($!{Request.Http.SessionCreationTime})","session-verified": "$!{Event.struct.session.isVerified}","user-name": "#jsonEscapeExtension($!{Request.UserName})","transaction-complete": "$!{Event.struct.complete}","response": {"size": "$!{Response.Http.Size}","time": "$!{Response.Http.Time}","code": "$!{Response.Http.Code}","headers": ${Response.Http.HeadersJSON},"cookies": ${Response.Http.CookiesJSON}},"request": {"method": "#jsonEscapeExtension($!{Request.Http.Method})","host": "#jsonEscapeExtension($!{Request.Http.Host})","user-agent": "#jsonEscapeExtension($!{Event.UserAgent})","url-path": "#jsonEscapeExtension($!{Request.Http.UrlPath})","url-full-path": "#jsonEscapeExtension($!{Request.Http.UrlFullPath})","url-query-params": "#jsonEscapeExtension($!{Request.Http.UrlQueryString})", "headers": ${Request.Http.HeadersJSON},"cookies": ${Request.Http.CookiesJSON},"parameters": ${Request.Http.ParametersJSON},"version": "$!{Request.Http.Version}"}},"additional-info": {"client-type": "#jsonEscapeExtension($!{Event.struct.botClassification.clientType})","bot-classification": "#jsonEscapeExtension($!{Event.struct.botClassification.botType})","soap": {"is-soap": "$!{Event.struct.soap}","action": "#jsonEscapeExtension($!{Event.struct.httpRequest.soapAction.soapAction})"}, "thr-services": ${Violation.Threatradar.ServiceJSON}}}'

    '''
    return self._Message
  @property
  def Port(self):
    ''' The Action Syslog Port setting (string) '''
    return self._Port

  #
  # Action setters
  #
  @Message.setter
  def Message(self, Message):
      if Message != self._Message:
          self._connection._update_action(ActionSet=self._ActionSet, Name=self._Name, Parameter='message',Value=Message)
          self._Message = Message

  @SyslogLogLevel.setter
  def SyslogLogLevel(self, SyslogLogLevel):
      if SyslogLogLevel != self._SyslogLogLevel:
          self._connection._update_action(ActionSet=self._ActionSet, Name=self._Name, Parameter='syslogLogLevel',Value=SyslogLogLevel)
          self._SyslogLogLevel = SyslogLogLevel

  @SyslogFacility.setter
  def SyslogFacility(self, SyslogFacility):
      if SyslogFacility != self._SyslogFacility:
          self._connection._update_action(ActionSet=self._ActionSet, Name=self._Name, Parameter='syslogFacility',Value=SyslogFacility)
          self._SyslogFacility = SyslogFacility
  @Host.setter
  def Host(self, Host):
      if Host != self._Host:
          self._connection._update_action(ActionSet=self._ActionSet, Name=self._Name, Parameter='host',Value=Host)
          self._Host = Host
  @Port.setter
  def Port(self, Port):
      if Port != self._Port:
          self._connection._update_action(ActionSet=self._ActionSet, Name=self._Name, Parameter='port',Value=Port)
          self._Port = Port
  @SecondaryHost.setter
  def SecondaryHost(self, SecondaryHost):
      if SecondaryHost != self._SecondaryHost:
          self._connection._update_action(ActionSet=self._ActionSet, Name=self._Name, Parameter='secondaryHost',Value=SecondaryHost)
          self._SecondaryHost = SecondaryHost
  @SecondaryPort.setter
  def SecondaryPort(self, SecondaryPort):
      if SecondaryPort != self._SecondaryPort:
          self._connection._update_action(ActionSet=self._ActionSet, Name=self._Name, Parameter='secondaryPort',Value=SecondaryPort)
          self._SecondaryPort = SecondaryPort
  @Protocol.setter
  def Protocol(self, Protocol):
      if Protocol != self._Protocol:
          self._connection._update_action(ActionSet=self._ActionSet, Name=self._Name, Parameter='protocol',Value=Protocol)
          self._Protocol = Protocol
  @Port.setter
  def Port(self, Port):
      if Port != self._Port:
          self._connection._update_action(ActionSet=self._ActionSet, Name=self._Name, Parameter='port', Value=Port)
          self._Port = Port

  #
  # Action internal functions
  #
  @staticmethod
  def _get_all_actions(connection, ActionSet=None):
    res = connection._mx_api('GET', '/conf/actionSets/%s' % ActionSet)
    try:
      actions = res['actions']
    except:
      return []
    action_objects = []
    for action in actions:
      get_action = connection.get_action(Name=action['name'], ActionSet=ActionSet)
      if get_action:
        action_objects.append(get_action)
    return action_objects        
  @staticmethod
  def _get_action(connection, Name=None, ActionSet=None):
    validate_string(Name=Name)
    obj_exists = Action._exists(connection=connection, Name=Name, ActionSet=ActionSet)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/actionSets/%s/%s' % (ActionSet, Name))
    except:
      return None
    Protocol = res['protocol'] if 'protocol' in res else None
    SecondaryHost = res['secondaryHost'] if 'secondaryHost' in res else None
    Message = res['message'] if 'message' in res else None
    Port = res['port'] if 'port' in res else None
    ActionInterface = res['actionInterface'] if 'actionInterface' in res else None
    SecondaryPort = res['secondaryPort'] if 'secondaryPort' in res else None
    SyslogLogLevel = res['syslogLogLevel'] if 'syslogLogLevel' in res else None
    Host = res['host'] if 'host' in res else None
    SyslogFacility = res['syslogFacility'] if 'syslogFacility' in res else None
    return Action(connection=connection, Name=Name, ActionSet=ActionSet, ActionType=res['type'], Protocol=Protocol, SecondaryHost=SecondaryHost, Message=Message, Port=Port, ActionInterface=ActionInterface, SecondaryPort=SecondaryPort, SyslogLogLevel=SyslogLogLevel, Host=Host, SyslogFacility=SyslogFacility)
  @staticmethod
  def _create_action(connection, Name=None, ActionSet=None, ActionType=None, Protocol=None, SyslogFacility=None, Host=None, SyslogLogLevel=None, SecondaryPort=None, ActionInterface=None, SecondaryHost=None, Message=None, Port=None, update=False):
    validate_string(Name=Name)
    action = connection.get_action(Name=Name, ActionSet=ActionSet)
    if action:
      if not update:
        raise MxException("Action '%s' already exists" % Name)
      else:
        # Update existing
        parameters = dict(locals())
        for cur_key in parameters:
            if is_parameter.match(cur_key) and cur_key not in ['Name', 'ActionSet', 'ActionType', 'ActionInterface'] and parameters[cur_key] != None:
                setattr(action, cur_key, parameters[cur_key])
      return action
    body = {'type': ActionType}
    parameters = dict(locals())
    for cur_key in parameters:
      if is_parameter.match(cur_key) and cur_key not in ['Name', 'ActionSet', 'ActionType'] and parameters[cur_key] != None:
        body[cur_key[0].lower() + cur_key[1:]] = parameters[cur_key]
      
    connection._mx_api('POST', '/conf/actionSets/%s/%s' % (ActionSet, Name), data=json.dumps(body))
    return Action(connection=connection, Name=Name, ActionSet=ActionSet, ActionType=ActionType, Protocol=Protocol, SyslogFacility=SyslogFacility, Host=Host, SyslogLogLevel=SyslogLogLevel, SecondaryPort=SecondaryPort, ActionInterface=ActionInterface, SecondaryHost=SecondaryHost, Message=Message, Port=Port)
  @staticmethod
  def _delete_action(connection, Name, ActionSet):
    validate_string(Name=Name)
    obj = connection.get_action(Name=Name, ActionSet=ActionSet)
    if obj:
      connection._mx_api('DELETE', '/conf/actionSets/%s/%s' % (ActionSet, Name))
      connection._instances.remove(obj)
      del obj
    else:
      raise MxException("Action does not exist")
    return True    

  @staticmethod
  def _update_action(connection, ActionSet=None, Name=None, Parameter=None, Value=None):
    axnObj = connection.get_action(ActionSet=ActionSet, Name=Name)
    axnDict = dict(axnObj)
    axnDict[Parameter] = Value
    body = {}
    for param in axnDict:
      if param == 'ActionType':
        lowparam = 'type'
      else:
        func = lambda s: s[:1].lower() + s[1:] if s else ''
        lowparam = func(param)
      body[lowparam] = axnDict[param]
    connection._mx_api('PUT', '/conf/actionSets/%s/%s' % (ActionSet, Name), data=json.dumps(body))
    return True
