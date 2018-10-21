# Copyright 2018 Imperva. All rights reserved.

from imperva_sdk.core import *
import json

class AgentMonitoringRule(MxObject):
  '''
  MX agent monitoring rule Class

  >>> rule = mx.get_agent_monitoring_rule("testRuleFromSDK")
  >>> rule.PolicyType
  'db-agents-monitoring-rule'
  >>> rule.Action = 'Exclude'
  >>> rule.CustomPredicates
  [{'predicate-type': 'event-type', 'operation': 'different-than', 'values': ['logout', 'query', 'login']}, {'predicate-type': 'data-type', 'operation': 'exclude-all', 'values': ['Address']}]
  >>> # Create user defined copy of policy
  >>> rule_dict = dict(rule)
  >>> rule_dict['Name'] = 'user defined - %s' % rule_dict['Name']
  >>> mx.create_agent_monitoring_rules_global_object(**rule_dict)
  <imperva_sdk 'AgentMonitoringRule' Object - 'user defined - testRuleFromSDK'>

  '''

  # Store created Policy objects in_instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = AgentMonitoringRule._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'AgentMonitoringRule':
        if cur_obj.Name == Name:
          return cur_obj
    return None

  def __init__(self, connection=None, Name=None, PolicyType=None, Action=None, CustomPredicates=[]):
    super(AgentMonitoringRule, self).__init__(connection=connection, Name=Name)
    validate_string(Name=Name, PolicyType=PolicyType, Action=Action)
    self._PolicyType = PolicyType
    self._Action = Action
    self._CustomPredicates = MxList(CustomPredicates)


  #
  # Agent monitoring rules Parameters
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
  def Action(self):
    ''' The action of the policy (string) '''
    return self._Action

  @property
  def CustomPredicates(self):
    '''
    Policy Match Criteria in API JSON format.
    See the Open API documentation for a complete list of available match criteria parameters.

    >>> rule = mx.get_agent_monitoring_rule("Monitoring rule")
    >>> rule.MatchCriteria
    [{'predicate-type': 'event-type', 'operation': 'equals', 'values': ['query', 'login', 'logout']},
    {'operation': 'exclude-all', 'values': ['Address'], 'predicate-type': 'data-type'}]

    '''
    return self._CustomPredicates

  @Action.setter
  def Action(self, Action):
    if Action != self._Action:
      self._connection._update_agent_monitoring_rule(Name=self._Name, Parameter='Action', Value=Action)
      self._Action = Action

  @PolicyType.setter
  def PolicyType(self, PolicyType):
    if PolicyType != self._PolicyType:
      self._connection._update_agent_monitoring_rule(Name=self._Name, Parameter='PolicyType', Value=PolicyType)
      self._PolicyType = PolicyType

  @CustomPredicates.setter
  def CustomPredicates(self, CustomPredicates):
    # Because the lists in SecureSphere don't have order, we need to sort them so we can compare them
    tmp1 = []
    for cur_item in CustomPredicates:
      tmp1.append(''.join(sorted(str(cur_item))))
    tmp1 = sorted(tmp1)
    tmp2 = []
    for cur_item in self._CustomPredicates:
      tmp2.append(''.join(sorted(str(cur_item))))
    tmp2 = sorted(tmp2)
    if tmp1 != tmp2:
      self._connection._update_agent_monitoring_rule(Name=self._Name, Parameter='CustomPredicates', Value=CustomPredicates)
      self._CustomPredicates = CustomPredicates


  #
  # Agent monitoring rules internal functions
  #
  @staticmethod
  def _get_all_agent_monitoring_rules(connection):

    res = connection._mx_api('GET', '/conf/agentsMonitoringRules')
    try:
      rule_names = [rule['policy-name'] for rule in res['policies']]
    except:
      raise MxException("Failed getting all agent monitoring rules")
    rules_objects = []
    for name in rule_names:
      try:
        obj = connection.get_agent_monitoring_rule(Name=name)
      except:
        raise MxException("Failed getting all agent monitoring rules")
      if obj:
        rules_objects.append(obj)
    return rules_objects

  @staticmethod
  def _get_agent_monitoring_rules_by_name(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = AgentMonitoringRule._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/agentsMonitoringRules/%s' % Name)
    except:
      return None
    return AgentMonitoringRule(connection=connection, Name=Name, PolicyType=res['policy-type'], Action=res['action'],
                               CustomPredicates=res['custom-predicates'])

  @staticmethod
  def _create_agent_monitoring_rule(connection, Name=None, PolicyType=None, Action=None, CustomPredicates=[], update=False):
    validate_string(Name=Name)
    obj = connection.get_agent_monitoring_rule(Name=Name)
    if obj:
      if not update:
        raise MxException("Rule '%s' already exists" % Name)
      else:
        # Update existing policy
        parameters = locals()
        for cur_key in list(parameters):
          if is_parameter.match(cur_key) and cur_key != 'Name' and parameters[cur_key] != None:
            setattr(obj, cur_key, parameters[cur_key])
        return obj
    body = {}
    if Action: body['action'] = Action
    if Name: body['policy-name'] = Name
    if PolicyType: body['policy-type'] = PolicyType
    body['custom-predicates'] = CustomPredicates
    body['total-num-of-predicates'] = len(CustomPredicates)

    try:
      res = connection._mx_api('POST', '/conf/agentsMonitoringRules/%s' % Name, data=json.dumps(body))
    except Exception as e:
      raise MxException("Failed creating agent monitoring rule: %s" % e)

    return AgentMonitoringRule(connection=connection, Name=Name, PolicyType=PolicyType, Action=Action, CustomPredicates=CustomPredicates)

  @staticmethod
  def _update_agent_monitoring_rule(connection, Name=None, Parameter=None, Value=None):
    '''
        Note that this update is equivalent to full update in the open api.
        Assume that _update will be called ONLY within the class setters
    '''
    validate_string(Name=Name)
    # AgentMonitoringRule require full body in update request.
    obj = connection.get_agent_monitoring_rule(Name=Name)
    if not obj:
      raise MxException("Rule '%s' is not exists" % Name)
    if Parameter == 'Action':
      if Value not in ['MoveToSniffing', 'Exclude', 'MoveToInline']:
        raise MxException("Parameter '%s' must be 'MoveToSniffing', 'Exclude' or 'MoveToInline'" % Parameter)
    elif Parameter == 'PolicyType':
      if Value not in ['db-agents-monitoring-rule', 'file-agents-monitoring-rule', 'ds-agents-monitoring-rules',
                       'z-os-agents-monitoring-rules']:
        raise MxException("Parameter '%s' must be 'db-agents-monitoring-rule', 'file-agents-monitoring-rule', "
                          "'ds-agents-monitoring-rules' or 'z-os-agents-monitoring-rules'" % Parameter)
    elif Parameter != 'CustomPredicates':
      raise MxException("Parameter '%s' must be 'Action', 'PolicyType' or 'CustomPredicates'" % Name)

    # uses intern __iter__
    objDict = dict(obj)
    if Parameter in objDict:
      objDict[Parameter] = Value

    jsonObj = {}
    jsonObj['action'] = objDict['Action']
    jsonObj['policy-name'] = objDict['Name']
    jsonObj['policy-type'] = objDict['PolicyType']
    jsonObj['custom-predicates'] = objDict['CustomPredicates']
    jsonObj['total-num-of-predicates'] = len(objDict['CustomPredicates'])

    try:
      connection._mx_api('PUT', '/conf/agentsMonitoringRules/%s' % Name, data=json.dumps(jsonObj))
    except:
      raise MxException("Failed updating agent monitoring rule %s" % Name)
    return True
