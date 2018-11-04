# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class DbSecurityPolicy(MxObject):

  # Store created Policy objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = DbSecurityPolicy._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'DbServiceCustomPolicy':
        if cur_obj.Name == Name:
          return cur_obj
    return None
  
  def __init__(self, connection=None, Name=None, PolicyType=None, Enabled=None, Severity=None, Action=None, FollowedAction=None, ApplyTo=[], AutoApply=None, MatchCriteria=[]):
    super(DbSecurityPolicy, self).__init__(connection=connection, Name=Name)
    validate_string(Name=Name, Severity=Severity, Action=Action)
    self._PolicyType = PolicyType
    self._Enabled = Enabled
    self._Severity = Severity
    self._Action = Action
    self._FollowedAction = FollowedAction
    self._MatchCriteria = MxList(MatchCriteria)
    self._ApplyTo = MxList(ApplyTo)
    self._AutoApply = AutoApply

  # Override the MxObject __iter__ function to print ApplyTo WebService objects as dictionaries    
  def __iter__(self):
    iters = {}
    for field in dir(self):
      if is_parameter.match(field):
        variable_function = getattr(self, field)
        if field == 'ApplyTo':
          ApplyToNames = []
          for cur_apply in variable_function:
            ApplyToNames.append({u'siteName': cur_apply._Site, u'serverGroupName': cur_apply._ServerGroup, u'dbServiceName': cur_apply.Name})
          iters[field] = ApplyToNames
        else:
          iters[field] = variable_function
    for x,y in iters.items():
      yield x, y

  #
  # DB Service Custom Policy Parameters
  #
  @property
  def Name(self):
    ''' The name of the policy (string) '''
    return self._Name
  @property
  def PolicyType(self):
    ''' The type of the policy (string) '''
    return self._PolicyType
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
  def AutoApply(self):
    ''' Policy automatic apply to new services/applications (string - True/NotSet) '''
    return self._AutoApply
  @property
  def ApplyTo(self):
    '''
    DB Services that policy is applied to (list of :py:class:`imperva_sdk.DBService` objects). Can be in API JSON format or DBService objects

    >>> pol.ApplyTo = [{'siteName': 'site name', 'serverGroupName': 'server group name', 'dbServiceName': 'db service name'}]
    >>> pol.ApplyTo
    [<imperva_sdk 'DB Service' Object - 'db service name'>]

    * siteName - Name of the site (string)
    * serverGroupName - Name of the server group (string)
    * dbServiceName - Name of the db service (string)

    '''
    return self._ApplyTo
  @property
  def MatchCriteria(self):
    '''
    Policy Match Criteria in API JSON format. See the Open API documentation for a complete list of available match criteria parameters.

    >>> pol = mx.get_db_security_policy("PCI - Usage of default user accounts")
    >>> pol.MatchCriteria
    [{u'type': u'simple', u'name': u'Database User Name', u'operation': u'At least one', u'values': [{u'value': u'insert-actual-default-accounts-here'}]

    '''
    return self._MatchCriteria
  @Enabled.setter
  def Enabled(self, Enabled):
    if Enabled != self._Enabled:
      #self._connection._update_web_service_custom_policy(Name=self._Name, Parameter='enabled', Value=Enabled)
      self._Enabled = Enabled
  @PolicyType.setter
  def PolicyType(self, PolicyType):
    if PolicyType != self.PolicyType:
      #self._connection._update_web_service_custom_policy(Name=self._Name, Parameter='policy-type', Value=PolicyType)
      self.PolicyType = PolicyType
  @FollowedAction.setter
  def FollowedAction(self, FollowedAction):
    if FollowedAction != self._FollowedAction:
      #self._connection._update_web_service_custom_policy(Name=self._Name, Parameter='followed-action', Value=FollowedAction)
      self._FollowedAction = FollowedAction
  @Action.setter
  def Action(self, Action):
    if Action != self._Action:
      #self._connection._update_web_service_custom_policy(Name=self._Name, Parameter='immediate-action', Value=Action)
      self._Action = Action
  @Severity.setter
  def Severity(self, Severity):
    if Severity != self._Severity:
      #self._connection._update_web_service_custom_policy(Name=self._Name, Parameter='severity', Value=Severity)
      self._Severity = Severity
  @AutoApply.setter
  def AutoApply(self, AutoApply):
    if AutoApply != self.AutoApply:
      #self._connection._update_web_service_custom_policy(Name=self._Name, Parameter='automatic-apply', Value=AutoApply)
      self._AutoApply = AutoApply
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
      #self._connection._update_db_service_custom_policy(Name=self._Name, Parameter='matchCriteria', Value=MatchCriteria)
      self._MatchCriteria = MatchCriteria
  @ApplyTo.setter
  def ApplyTo(self, ApplyTo):
    self._ApplyTo = ApplyTo

    
  #
  # DB Security Policy internal functions
  #
  @staticmethod
  def _get_all_db_security_policies(connection):
    res = connection._mx_api('GET', '/conf/dbSecurityPolicies')
    #print(res)
    try:
      policies = res['db-security-policies']
    except:
      raise MxException("Failed getting DB Security Policies")
    policy_objects = []
    for policy in policies:
      name = policy['policy-name']
      # Bug - we have policies with '/' character that don't work with the API...
      if '/' in name:
        continue
      pol_obj = connection.get_db_security_policy(Name=name)
      if pol_obj:
        policy_objects.append(pol_obj)
    return policy_objects
  @staticmethod
  def _get_db_security_policy(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = DbSecurityPolicy._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/dbSecurityPolicies/%s' % Name)
    except:
      return None
    # Translate the ApplyTo dictionary to WebService objects
    if 'apply-to' not in res: res['apply-to'] = []
    if 'match-criteria' not in res: res['match-criteria'] = []
    if 'followed-action' not in res: res['followed-action'] = None
    if 'automatic-apply' not in res: res['automatic-apply'] = None
    if 'immediate-action' not in res: res['immediate-action'] = 'None'
    return DbSecurityPolicy(connection=connection, Name=Name, PolicyType=res['policy-type'],
                            Enabled=res['enabled'], Severity=res['severity'],
                            Action=res['immediate-action'], FollowedAction=res['followed-action'],
                            ApplyTo=res['apply-to'], AutoApply=res['automatic-apply'], MatchCriteria=res['match-criteria'])
  @staticmethod
  def _create_db_security_policy(connection, Name=None, PolicyType='db-service-custom',
                                       Enabled=None, Severity=None, Action=None,
                                       FollowedAction=None, ApplyTo=None, AutoApply=None,
                                       MatchCriteria=None, update=False):
    validate_string(Name=Name)
    pol = connection.get_db_security_policy(Name=Name)
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
        'policy-name': Name
      }
      if Severity: body['severity'] = Severity
      if Action: body['immediate-action'] = Action
      if FollowedAction: body['followed-action'] = FollowedAction
      if MatchCriteria: body['match-criteria'] = MatchCriteria
      if Enabled: body['enabled'] = Enabled
      if AutoApply: body['automatic-apply'] = AutoApply
      body['policy-type'] = PolicyType
      if ApplyTo: body['apply-to'] = ApplyTo
      connection._mx_api('POST', '/conf/dbSecurityPolicies/%s' % Name, data=json.dumps(body))
      return DbSecurityPolicy(connection=connection, Name=Name,
                              PolicyType=PolicyType, AutoApply=AutoApply,
                              Enabled=Enabled, Severity=Severity,
                              Action=Action, FollowedAction=FollowedAction,
                              ApplyTo=ApplyTo, MatchCriteria=MatchCriteria)

  @staticmethod
  def _delete_db_security_policy(connection, Name=None):
    validate_string(Name=Name)
    pol = connection.get_db_security_policy(Name=Name)
    if pol:
      connection._mx_api('DELETE', '/conf/dbSecurityPolicies/%s' % Name)
      connection._instances.remove(pol)
      del pol
    else:
      raise MxException("Policy does not exist")
    return True    
  @staticmethod
  def _update_db_security_policy(connection, Name=None, Parameter=None, Value=None):
    if Parameter in ['enabled']:
      if Value != True and Value != False:
        raise MxException("Parameter '%s' must be True or False" % Parameter)
    elif Parameter == 'action':
      if Value not in ['block', 'none']:
        raise MxException("Parameter '%s' must be 'block' or 'none'" % Parameter)
    elif Parameter == 'severity':
      if Value not in ['high', 'medium', 'low', 'informative', 'noAlert']:
        raise MxException("Parameter '%s' must be one of %s" % (Parameter, str(['high', 'medium', 'low', 'informative', 'noAlert'])))
    body = { Parameter: Value }
    connection._mx_api('PUT', '/conf/dbSecurityPolicies/%s' % Name, data=json.dumps(body))
    return True

