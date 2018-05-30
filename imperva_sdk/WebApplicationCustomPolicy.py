# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class WebApplicationCustomPolicy(MxObject):
  ''' 
  MX Web Application Custom Policy Class 

  '''

  # Store created Policy objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = WebApplicationCustomPolicy._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'WebApplicationCustomPolicy':
        if cur_obj.Name == Name:
          return cur_obj
    return None
  
  def __init__(self, connection=None, Name=None, Enabled=None, Severity=None, Action=None, FollowedAction=None, SendToCd=None, DisplayResponsePage=None, ApplyTo=[], MatchCriteria=[], OneAlertPerSession=None):
    super(WebApplicationCustomPolicy, self).__init__(connection=connection, Name=Name)
    validate_string(Name=Name, Severity=Severity, Action=Action)
    self._Enabled = Enabled
    self._Severity = Severity
    self._Action = Action
    self._FollowedAction = FollowedAction
    self._SendToCd = SendToCd
    self._DisplayResponsePage = DisplayResponsePage
    self._OneAlertPerSession = OneAlertPerSession
    self._MatchCriteria = MxList(MatchCriteria)
    self._ApplyTo = MxList(ApplyTo)

  # Override the MxObject __iter__ function to print ApplyTo WebApplication objects as dictionaries    
  def __iter__(self):
    iters = {}
    for field in dir(self):
      if is_parameter.match(field):
        variable_function = getattr(self, field)
        if field == 'ApplyTo':
          ApplyToNames = []
          for cur_apply in variable_function:
            ApplyToNames.append({u'siteName': cur_apply._Site, u'serverGroupName': cur_apply._ServerGroup, u'webServiceName': cur_apply._WebService, u'webApplicationName': cur_apply.Name})
          iters[field] = ApplyToNames
        else:
          iters[field] = variable_function
    for x,y in iters.items():
      yield x, y

  #
  # Web Service Application Policy Parameters
  #
  @property
  def Name(self):
    ''' The name of the policy (string) '''
    return self._Name
  @property
  def Enabled(self):
    ''' Is policy enabled? (boolean) '''
    return self._Enabled
  @property
  def Severity(self):
    ''' Alert Severity ('high', 'medium', 'low', 'informative', 'noAlert') '''
    return self._Severity
  @property
  def Action(self):
    ''' Policy action ('none', 'block') '''
    return self._Action
  @property
  def FollowedAction(self):
    ''' Policy followed action (string - Action Set Name) '''
    return self._FollowedAction
  @property
  def SendToCd(self):
    ''' Send policy alerts to community defense. Applicable for only some predefined policies (boolean) '''
    return self._SendToCd
  @property
  def DisplayResponsePage(self):
    ''' Show response page in alerts (boolean) '''
    return self._DisplayResponsePage
  @property
  def OneAlertPerSession(self):
    ''' Allow only one alert to be created for every web session (boolean) '''
    return self._OneAlertPerSession
  @property
  def ApplyTo(self):
    '''
    Web Applications that policy is applied to (list of :py:class:`imperva_sdk.WebApplication` objects). Can be in API JSON format or WebApplication objects

    >>> pol.ApplyTo = [{'siteName': 'site name', 'serverGroupName': 'server group name', 'webServiceName': 'web service name', 'webApplicationName': 'web application name'}]
    >>> pol.ApplyTo
    [<imperva_sdk 'WebApplication' Object - 'web application name'>]

    * siteName - Name of the site (string)
    * serverGroupName - Name of the server group (string)
    * webServiceName - Name of the web service (string)
    * webApplicationName - Name of the web application (string)

    '''
    return self._ApplyTo
  @property
  def MatchCriteria(self):
    ''' 
    Policy Match Criteria in API JSON format. See the Open API documentation for a complete list of available match criteria parameters.

    '''
    return self._MatchCriteria
  @Enabled.setter
  def Enabled(self, Enabled):
    if Enabled != self._Enabled:
      self._connection._update_web_application_custom_policy(Name=self._Name, Parameter='enabled', Value=Enabled)
      self._Enabled = Enabled
  @FollowedAction.setter
  def FollowedAction(self, FollowedAction):
    if FollowedAction != self._FollowedAction:
      self._connection._update_web_application_custom_policy(Name=self._Name, Parameter='followedAction', Value=FollowedAction)
      self._FollowedAction = FollowedAction
  @Action.setter
  def Action(self, Action):
    if Action != self._Action:
      self._connection._update_web_application_custom_policy(Name=self._Name, Parameter='action', Value=Action)
      self._Action = Action
  @Severity.setter
  def Severity(self, Severity):
    if Severity != self._Severity:
      self._connection._update_web_application_custom_policy(Name=self._Name, Parameter='severity', Value=Severity)
      self._Severity = Severity
  @SendToCd.setter
  def SendToCd(self, SendToCd):
    if SendToCd != self._SendToCd:
      self._connection._update_web_application_custom_policy(Name=self._Name, Parameter='sendToCD', Value=SendToCd)
      self._SendToCd = SendToCd
  @DisplayResponsePage.setter
  def DisplayResponsePage(self, DisplayResponsePage):
    if DisplayResponsePage != self._DisplayResponsePage:
      self._connection._update_web_application_custom_policy(Name=self._Name, Parameter='displayResponsePage', Value=DisplayResponsePage)
      self._DisplayResponsePage = DisplayResponsePage
  @OneAlertPerSession.setter
  def OneAlertPerSession(self, OneAlertPerSession):
    if OneAlertPerSession != self._OneAlertPerSession:
      self._connection._update_web_application_custom_policy(Name=self._Name, Parameter='oneAlertPerSession', Value=OneAlertPerSession)
      self._OneAlertPerSession = OneAlertPerSession
  @MatchCriteria.setter
  def MatchCriteria(self, MatchCriteria):
    # Because the lists in SecureSphere don't have order, we need to sort them so we can compare them
    tmp1 = []
    for cur_item in MatchCriteria:
      tmp1.append(''.join(sorted(str(cur_item).replace('u',''))))
    tmp1 = sorted(tmp1)
    tmp2 = []
    for cur_item in self._MatchCriteria:
      tmp2.append(''.join(sorted(str(cur_item).replace('u',''))))
    tmp2 = sorted(tmp2)
    if tmp1 != tmp2:
      self._connection._update_web_service_custom_policy(Name=self._Name, Parameter='matchCriteria', Value=MatchCriteria)
      self._MatchCriteria = MatchCriteria
  @ApplyTo.setter
  def ApplyTo(self, ApplyTo):

    change = []

    # Translate ApplyTo to objects if we need to
    ApplyToObjects = []
    for cur_apply in ApplyTo:
      if type(cur_apply).__name__ == 'dict':
        ApplyToObjects.append(self._connection.get_web_application(Site=cur_apply['siteName'], ServerGroup=cur_apply['serverGroupName'], WebService=cur_apply['webServiceName'], Name=cur_apply['webApplicationName']))
      elif type(cur_apply).__name__ == 'WebApplication':
        ApplyToObjects.append(cur_apply)
      else:
        raise MxException("Bad 'ApplyTo' parameter")

    # Check if we need to add anything
    for cur_apply in ApplyToObjects:
      if cur_apply not in self._ApplyTo:
        apply_dict = {
          'siteName': cur_apply._Site,
          'serverGroupName': cur_apply._ServerGroup,
          'webServiceName': cur_apply._WebService,
          'webApplicationName': cur_apply.Name,          
          'operation': 'add'
        }
        change.append(apply_dict)
    # Check if we need to remove anything
    for cur_apply in self._ApplyTo:
      if cur_apply not in ApplyToObjects:
        apply_dict = {
          'siteName': cur_apply._Site,
          'serverGroupName': cur_apply._ServerGroup,
          'webServiceName': cur_apply._WebService,
          'webApplicationName': cur_apply.Name,          
          'operation': 'remove'
        }
        change.append(apply_dict)

    if change:
      self._connection._update_web_application_custom_policy(Name=self._Name, Parameter='applyTo', Value=change)
      self._ApplyTo = MxList(ApplyToObjects)
    
  #
  # Web Application Custom Policy internal functions
  #
  @staticmethod
  def _get_all_web_application_custom_policies(connection):
    res = connection._mx_api('GET', '/conf/webApplicationCustomPolicies')
    try:
      policy_names = res['customWebPolicies']
    except:
      raise MxException("Failed getting Web Application Custom Policies")
    policy_objects = []
    for name in policy_names:
      # Bug - we have policies with '/' character that don't work with the API...
      if '/' in name:
        continue
      pol_obj = connection.get_web_application_custom_policy(Name=name)
      if pol_obj:
        policy_objects.append(pol_obj)
    return policy_objects
  @staticmethod
  def _get_web_application_custom_policy(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = WebApplicationCustomPolicy._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/webApplicationCustomPolicies/%s' % Name)
    except:
      return None
    if 'followedAction' not in res: res['followedAction'] = ''
    if 'oneAlertPerSession' not in res: res['oneAlertPerSession'] = None
    if 'sendToCD' not in res: res['sendToCD'] = None
    # Translate the ApplyTo dictionary to WebApplication objects
    ApplyToObjects = []
    for cur_apply in res['applyTo']:
      # Check if we already have the web service instance created, we can use it instead of creating a new one
      wa = connection.get_web_application(Site=cur_apply['siteName'], ServerGroup=cur_apply['serverGroupName'], WebService=cur_apply['webServiceName'], Name=cur_apply['webApplicationName'])
      if wa:
        ApplyToObjects.append(wa)
    # Fix None type bug in httpRequest matchCriteria
    for criteria in res['matchCriteria']:
      if 'type' in criteria:
        if criteria['type'] == 'httpRequest':
          if 'matchValues' in criteria:
            for match in criteria['matchValues']:
              if 'name' in match:
                if match['name'] == None:
                  match['name'] = '' 
    return WebApplicationCustomPolicy(connection=connection, Name=Name, Enabled=res['enabled'], Severity=res['severity'], Action=res['action'], FollowedAction=res['followedAction'], SendToCd=res['sendToCD'], DisplayResponsePage=res['displayResponsePage'], ApplyTo=ApplyToObjects, MatchCriteria=res['matchCriteria'], OneAlertPerSession=res['oneAlertPerSession'])
  @staticmethod
  def _create_web_application_custom_policy(connection, Name=None, Enabled=None, Severity=None, Action=None, FollowedAction=None, SendToCd=None, DisplayResponsePage=None, ApplyTo=None, MatchCriteria=None, OneAlertPerSession=None, update=False):
    validate_string(Name=Name)
    pol = connection.get_web_application_custom_policy(Name=Name)
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
        'enabled': Enabled,
        'oneAlertPerSession': OneAlertPerSession,
        'displayResponsePage': DisplayResponsePage
      }
      if Severity: body['severity'] = Severity
      if Action: body['action'] = Action
      if FollowedAction: body['followedAction'] = FollowedAction
      if MatchCriteria: body['matchCriteria'] = MatchCriteria
      # We want to support ApplyTo in dictionary (API) and WebService object formats
      ApplyToNames = []
      ApplyToObjects = []
      for cur_apply in ApplyTo:
        if type(cur_apply).__name__ == 'dict':
          ApplyToNames.append(cur_apply)
          ApplyToObjects.append(connection.get_web_application(Site=cur_apply['siteName'], ServerGroup=cur_apply['serverGroupName'], WebService=cur_apply['webServiceName'], Name=cur_apply['webApplicationName']))
        elif type(cur_apply).__name__ == 'WebApplication':
          ApplyToNames.append({u'siteName': cur_apply._Site, u'serverGroupName': cur_apply._ServerGroup, u'webServiceName': cur_apply._WebService, u'webApplicationName': cur_apply.Name})
          ApplyToObjects.append(cur_apply)
        else:
          raise MxException("Bad 'ApplyTo' parameter")
      if ApplyToNames: body['applyTo'] = ApplyToNames
      connection._mx_api('POST', '/conf/webApplicationCustomPolicies/%s' % Name, data=json.dumps(body))
      return WebApplicationCustomPolicy(connection=connection, Name=Name, Enabled=Enabled, Severity=Severity, Action=Action, FollowedAction=FollowedAction, SendToCd=None, DisplayResponsePage=DisplayResponsePage, ApplyTo=ApplyToObjects, MatchCriteria=MatchCriteria, OneAlertPerSession=OneAlertPerSession)
  @staticmethod
  def _delete_web_application_custom_policy(connection, Name=None):
    validate_string(Name=Name)
    pol = connection.get_web_application_custom_policy(Name=Name)
    if pol:
      connection._mx_api('DELETE', '/conf/webApplicationCustomPolicies/%s' % Name)
      connection._instances.remove(pol)
      del pol
    else:
      raise MxException("Policy does not exist")
    return True    
  @staticmethod
  def _update_web_application_custom_policy(connection, Name=None, Parameter=None, Value=None):
    if Parameter in ['enabled', 'sendToCD', 'displayResponsePage', 'oneAlertPerSession']:
      if Value != True and Value != False:
        raise MxException("Parameter '%s' must be True or False" % Parameter)
    elif Parameter == 'action':
      if Value not in ['block', 'none']:
        raise MxException("Parameter '%s' must be 'block' or 'none'" % Parameter)
    elif Parameter == 'severity':
      if Value not in ['high', 'medium', 'low', 'informative', 'noAlert']:
        raise MxException("Parameter '%s' must be one of %s" % (Parameter, str(['high', 'medium', 'low', 'informative', 'noAlert'])))
    body = { Parameter: Value }
    connection._mx_api('PUT', '/conf/webApplicationCustomPolicies/%s' % Name, data=json.dumps(body))
    return True

