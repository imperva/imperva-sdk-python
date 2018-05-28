# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class HttpProtocolSignaturesPolicy(MxObject):
  ''' 
  MX HTTP Protocol Signatures Policy Class 

  '''

  # Store created Web Service Custom Policy objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = HttpProtocolSignaturesPolicy._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'HttpProtocolSignaturesPolicy':
        if cur_obj.Name == Name:
          return cur_obj
    return None
  
  def __init__(self, connection=None, Name=None, SendToCd=None, DisplayResponsePage=None, ApplyTo=[], Rules=[], Exceptions=[]):
    super(HttpProtocolSignaturesPolicy, self).__init__(connection=connection, Name=Name)
    validate_string(Name=Name)
    self._SendToCd = SendToCd
    self._DisplayResponsePage = DisplayResponsePage
    self._ApplyTo = MxList(ApplyTo)
    self._Rules = MxList(Rules)
    self._Exceptions = MxList(Exceptions)

  # Override the MxObject __iter__ function to print ApplyTo WebService objects as dictionaries    
  def __iter__(self):
    iters = {}
    for field in dir(self):
      if is_parameter.match(field):
        variable_function = getattr(self, field)
        if field == 'ApplyTo':
          ApplyToNames = []
          for cur_apply in variable_function:
            ApplyToNames.append({u'siteName': cur_apply._Site, u'serverGroupName': cur_apply._ServerGroup, u'webServiceName': cur_apply.Name})
          iters[field] = ApplyToNames
        else:
          iters[field] = variable_function
    for x,y in iters.items():
      yield x, y

  #
  # HTTP Protocol Signatures Policy Parameters
  #
  @property
  def Name(self):
    ''' The name of the policy (string) '''
    return self._Name
  @property
  def SendToCd(self):
    ''' Send policy alerts to community defense. Applicable for only some predefined policies (boolean) '''
    return self._SendToCd
  @property
  def DisplayResponsePage(self):
    ''' Show response page in alerts (boolean) '''
    return self._DisplayResponsePage
  @property
  def Rules(self):
    ''' 
    Policy dictionary rules (list of dict) 

    >>> pol.Rules
    [{u'action': u'block', u'enabled': False, u'name': u'ASP Oracle Padding', u'severity': u'medium'}, {u'action': u'none', u'enabled': False, u'name': u'Fullwidth/Halfwidth Unicode Encoding on URL/Parameter', u'severity': u'noAlert'}, {u'action': u'none', u'enabled': True, u'name': u'IIS Code Upload', u'severity': u'noAlert'}, {u'action': u'none', u'enabled': True, u'name': u'Java Double Precision Non Convergence DoS', u'severity': u'noAlert'}, {u'action': u'none', u'enabled': True, u'name': u'MSSQL Data Retrieval with Implicit Conversion Errors', u'severity': u'noAlert'}, {u'action': u'none', u'enabled': True, u'name': u'PHP Address Book ', u'severity': u'noAlert'}, {u'action': u'none', u'enabled': True, u'name': u'PHP Double Precision Non Convergence DoS', u'severity': u'noAlert'}, {u'action': u'block', u'enabled': True, u'name': u'Recommended for Blocking for Web Applications ', u'severity': u'high'}, {u'action': u'none', u'enabled': True, u'name': u'Recommended for Detection for Web Applications', u'severity': u'low'}, {u'action': u'block', u'enabled': True, u'name': u'Worms and Critical Vulnerabilities for Web Applications', u'severity': u'high'}]

    '''
    return self._Rules
  @property
  def Exceptions(self):
    ''' 
    Policy exceptions (list of dict) 
 
    >>> pol.Exceptions
    [{u'comment': u'exception comment', u'predicates': [{u'type': u'httpRequestUrl', u'operation': u'atLeastOne', u'values': [u'/login'], u'match': u'prefix'}], u'ruleName': u'ASP Oracle Padding'}]

    '''
    return self._Exceptions
  @property
  def ApplyTo(self):
    '''
    Web Services that policy is applied to (list of :py:class:`imperva_sdk.WebService` objects). Can be in API JSON format or WebService objects

    >>> pol.ApplyTo = [{'siteName': 'site name', 'serverGroupName': 'server group name', 'webServiceName': 'web service name'}]
    >>> pol.ApplyTo
    [<imperva_sdk 'WebService' Object - 'web service name'>]

    * siteName - Name of the site (string)
    * serverGroupName - Name of the server group (string)
    * webServiceName - Name of the web service (string)

    '''
    return self._ApplyTo
  @SendToCd.setter
  def SendToCd(self, SendToCd):
    if SendToCd != self._SendToCd:
      self._connection._update_http_protocol_signatures_policy(Name=self._Name, Parameter='sendToCD', Value=SendToCd)
      self._SendToCd = SendToCd
  @DisplayResponsePage.setter
  def DisplayResponsePage(self, DisplayResponsePage):
    if DisplayResponsePage != self._DisplayResponsePage:
      self._connection._update_http_protocol_signatures_policy(Name=self._Name, Parameter='displayResponsePage', Value=DisplayResponsePage)
      self._DisplayResponsePage = DisplayResponsePage
  @ApplyTo.setter
  def ApplyTo(self, ApplyTo):

    change = []

    # Translate ApplyTo to objects if we need to
    ApplyToObjects = []
    for cur_apply in ApplyTo:
      if type(cur_apply).__name__ == 'dict':
        ApplyToObjects.append(self._connection.get_web_service(Site=cur_apply['siteName'], ServerGroup=cur_apply['serverGroupName'], Name=cur_apply['webServiceName']))
      elif type(cur_apply).__name__ == 'WebService':
        ApplyToObjects.append(cur_apply)
      else:
        raise MxException("Bad 'ApplyTo' parameter")

    # Check if we need to add anything
    for cur_apply in ApplyToObjects:
      if cur_apply not in self._ApplyTo:
        apply_dict = {
          'siteName': cur_apply._Site,
          'serverGroupName': cur_apply._ServerGroup,
          'webServiceName': cur_apply.Name,
          'operation': 'add'
        }
        change.append(apply_dict)
    # Check if we need to add anything
    for cur_apply in self._ApplyTo:
      if cur_apply not in ApplyToObjects:
        apply_dict = {
          'siteName': cur_apply._Site,
          'serverGroupName': cur_apply._ServerGroup,
          'webServiceName': cur_apply.Name,
          'operation': 'remove'
        }
        change.append(apply_dict)

    if change:
      self._connection._update_http_protocol_signatures_policy(Name=self._Name, Parameter='applyTo', Value=change)
      self._ApplyTo = MxList(ApplyToObjects)
  @Rules.setter
  def Rules(self, Rules):
    # Because the Rules isn't really a list and the MX can return it in different orders, we need to compare only the rules
    change = False
    for cur_rule in Rules:
      if cur_rule not in self._Rules:
        change = True
        break
    if not change:
      for cur_rule in self._Rules:
        if cur_rule not in Rules:
          change = True
          break
    if change:
      self._connection._update_http_protocol_signatures_policy(Name=self._Name, Parameter='rules', Value=Rules)
      self._Rules = Rules
  @Exceptions.setter
  def Exceptions(self, Exceptions):
    # Because the Exceptions isn't really a list and the MX can return it in different orders, we need to compare only the rules
    change = False
    for cur_rule in Exceptions:
      if cur_rule not in self._Exceptions:
        change = True
        break
    if not change:
      for cur_rule in self._Exceptions:
        if cur_rule not in Exceptions:
          change = True
          break
    if change:
      self._connection._update_http_protocol_signatures_policy(Name=self._Name, Parameter='exceptions', Value=Exceptions)
      self._Exceptions = Exceptions
      
    
  #
  # HTTP Protocol Signatures internal functions
  #
  @staticmethod
  def _get_all_http_protocol_signatures_policies(connection):
    res = connection._mx_api('GET', '/conf/policies/security/httpProtocolSignaturesPolicies')
    try:
      policy_names = res['policies']
    except:
      raise MxException("Failed getting HTTP Protocol Signatures Policies")
    policy_objects = []
    for name in policy_names:
      # Bug - we have policies with '/' character that don't work with the API...
      if '/' in name:
        continue
      pol_obj = connection.get_http_protocol_signatures_policy(Name=name)
      if pol_obj:
        policy_objects.append(pol_obj)
    return policy_objects
  @staticmethod
  def _get_http_protocol_signatures_policy(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = HttpProtocolSignaturesPolicy._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/policies/security/httpProtocolSignaturesPolicies/%s' % Name)
    except:
      return None
    if 'sendToCD' not in res: res['sendToCD'] = None
    if 'exceptions' not in res: res['exceptions'] = []
    # Translate the ApplyTo dictionary to WebService objects
    ApplyToObjects = []
    for cur_apply in res['applyTo']:
      # Check if we already have the web service instance created, we can use it instead of creating a new one
      ws = connection.get_web_service(Site=cur_apply['siteName'], ServerGroup=cur_apply['serverGroupName'], Name=cur_apply['webServiceName'])
      if ws:
        ApplyToObjects.append(ws)
    return HttpProtocolSignaturesPolicy(connection=connection, Name=Name, SendToCd=res['sendToCD'], DisplayResponsePage=res['displayResponsePage'], ApplyTo=ApplyToObjects, Rules=res['rules'], Exceptions=res['exceptions'])
  @staticmethod
  def _create_http_protocol_signatures_policy(connection, Name=None, SendToCd=None, DisplayResponsePage=None, ApplyTo=[], Rules=[], Exceptions=[], update=False):
    validate_string(Name=Name)
    pol = connection.get_http_protocol_signatures_policy(Name=Name)
    if pol:
      if not update:
        raise MxException("Policy '%s' already exists" % Name)
      else:
        # Update existing policy
        parameters = locals()
        for cur_key in parameters:
          if is_parameter.match(cur_key) and cur_key != 'Name' and parameters[cur_key] != None:
            setattr(pol, cur_key, parameters[cur_key])
      return pol
    else:
      # Create new policy
      body = {
        'displayResponsePage': DisplayResponsePage
      }
      if Rules: body['rules'] = Rules
      if Exceptions: body['exceptions'] = Exceptions
      # We want to support ApplyTo in dictionary (API) and WebService object formats
      ApplyToNames = []
      ApplyToObjects = []
      for cur_apply in ApplyTo:
        if type(cur_apply).__name__ == 'dict':
          ApplyToNames.append(cur_apply)
          ApplyToObjects.append(connection.get_web_service(Site=cur_apply['siteName'], ServerGroup=cur_apply['serverGroupName'], Name=cur_apply['webServiceName']))
        elif type(cur_apply).__name__ == 'WebService':
          ApplyToNames.append({u'siteName': cur_apply._Site, u'serverGroupName': cur_apply._ServerGroup, u'webServiceName': cur_apply.Name})
          ApplyToObjects.append(cur_apply)
        else:
          raise MxException("Bad 'ApplyTo' parameter")
      if ApplyToNames: body['applyTo'] = ApplyToNames
      try:
        connection._mx_api('POST', '/conf/policies/security/httpProtocolSignaturesPolicies/%s' % Name, data=json.dumps(body))
      except:
        # We have a version that supports this policy but without exceptions, so this is a little hack for export/import
        del body['exceptions']
        Exceptions = []
        connection._mx_api('POST', '/conf/policies/security/httpProtocolSignaturesPolicies/%s' % Name, data=json.dumps(body))
      return HttpProtocolSignaturesPolicy(connection=connection, Name=Name, SendToCd=SendToCd, DisplayResponsePage=DisplayResponsePage, ApplyTo=ApplyToObjects, Rules=Rules, Exceptions=Exceptions)
  @staticmethod
  def _delete_http_protocol_signatures_policy(connection, Name=None):
    validate_string(Name=Name)
    pol = connection.get_http_protocol_signatures_policy(Name=Name)
    if pol:
      connection._mx_api('DELETE', '/conf/policies/security/httpProtocolSignaturesPolicies/%s' % Name)
      connection._instances.remove(pol)
      del pol
    else:
      raise MxException("Policy does not exist")
    return True    
  @staticmethod
  def _update_http_protocol_signatures_policy(connection, Name=None, Parameter=None, Value=None):
    if Parameter in ['sendToCD', 'displayResponsePage']:
      if Value != True and Value != False:
        raise MxException("Parameter '%s' must be True or False" % Parameter)
    body = { Parameter: Value }
    connection._mx_api('PUT', '/conf/policies/security/httpProtocolSignaturesPolicies/%s' % Name, data=json.dumps(body))
    return True

