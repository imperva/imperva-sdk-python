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
  >>> mx.create_agent_monitoring_rules_dam_global_object(**rule_dict)
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

  def __init__(self, connection=None, Name=None, PolicyType=None, Action=None, CustomPredicates=[], ApplyToAgent=[], ApplyToTag=[]):
    super(AgentMonitoringRule, self).__init__(connection=connection, Name=Name)
    validate_string(Name=Name, PolicyType=PolicyType, Action=Action)
    self._PolicyType = PolicyType
    self._Action = Action
    self._CustomPredicates = MxList(CustomPredicates)
    self._ApplyToAgent = MxList(ApplyToAgent)
    self._ApplyToTag = MxList(ApplyToTag)


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

  @property
  def ApplyToAgent(self):
     '''
     Agents that rule is applied to (list of Strings).
     '''
     return self._ApplyToAgent

  @property
  def ApplyToTag(self):
     '''
     Agents Tags that rule is applied to (list of Strings).
     '''
     return self._ApplyToTag



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


  @ApplyToAgent.setter
  def ApplyToAgent(self, ApplyToAgent):
    tmp1 = []
    for cur_item in ApplyToAgent:
        tmp1.append(''.join(sorted(str(cur_item))))
    tmp1 = sorted(tmp1)
    tmp2 = []
    for cur_item in self._ApplyToAgent:
        tmp2 = sorted(tmp2)
        tmp2.append(''.join(sorted(str(cur_item))))
    tmp2 = sorted(tmp2)
    if tmp1 != tmp2:
        self._connection._update_agent_monitoring_rule(Name=self._Name, Parameter='ApplyToAgent', Value=ApplyToAgent)
        self._ApplyToAgent = ApplyToAgent


  @ApplyToTag.setter
  def ApplyToTag(self, ApplyToTag):
      tmp1 = []
      for cur_item in ApplyToTag:
          tmp1.append(''.join(sorted(str(cur_item).replace('u', ''))))
      tmp1 = sorted(tmp1)
      tmp2 = []
      for cur_item in self._ApplyToTag:
          tmp2 = sorted(tmp2)
          tmp2.append(''.join(sorted(str(cur_item).replace('u', ''))))
      tmp2 = sorted(tmp2)
      if tmp1 != tmp2:
          self._connection._update_agent_monitoring_rule(Name=self._Name, Parameter='ApplyToTag', Value=ApplyToTag)
          self._ApplyToTag = ApplyToTag


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
                               CustomPredicates=res['custom-predicates'],
                               ApplyToAgent=res['apply-to-agent'], ApplyToTag=res['apply-to-tag'])

  @staticmethod
  def _create_agent_monitoring_rule(connection, Name=None, PolicyType=None, Action=None, CustomPredicates=[],
                                    ApplyToAgent=[], ApplyToTag=[], update=False):
    validate_string(Name=Name)
    obj = connection.get_agent_monitoring_rule(Name=Name)
    if obj:
      if not update:
        raise MxException("Rule '%s' already exists" % Name)
      else:
        # Update existing policy
        parameters = dict(locals())
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
    body['apply-to-agent'] = ApplyToAgent
    body['apply-to-tag'] = ApplyToTag

    # Check if tags exist. If not, create them
    known_tags = set([tag.Name for tag in connection.get_all_tags()])
    missing_tags = list(set(ApplyToTag) - known_tags)
    for tag in missing_tags:
      connection.create_tag(tag)

    try:
      res = connection._mx_api('POST', '/conf/agentsMonitoringRules/%s' % Name, data=json.dumps(body))
    except Exception as e:
      raise MxException("Failed creating agent monitoring rule: %s" % e)

    return AgentMonitoringRule(connection=connection, Name=Name, PolicyType=PolicyType, Action=Action,
                               CustomPredicates=CustomPredicates, ApplyToAgent=ApplyToAgent, ApplyToTag=ApplyToTag)

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
    elif Parameter == 'ApplyToTag':
      # Check if tags exist. If not, create them
      known_tags = set([tag.Name for tag in connection.get_all_tags()])
      missing_tags = list(set(Value) - known_tags)
      for tag in missing_tags:
        connection.create_tag(tag)
    elif Parameter != 'CustomPredicates' and Parameter != 'ApplyToAgent' and Parameter != 'ApplyToTag':
      raise MxException("Parameter '%s' must be 'Action', 'PolicyType', 'CustomPredicates', 'ApplyToAgent' or 'ApplyToTag'" % Name)

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
    jsonObj['apply-to-agent'] = objDict['ApplyToAgent']
    jsonObj['apply-to-tag'] = objDict['ApplyToTag']

    try:
      connection._mx_api('PUT', '/conf/agentsMonitoringRules/%s' % Name, data=json.dumps(jsonObj))
    except Exception as e:
      raise MxException("Failed updating agent monitoring rule %s: %s" % (Name, e))
    return True

  @staticmethod
  def _get_all_agent_monitoring_rules_by_agent(connection, AgentName=None, AgentTags=[]):
    '''
    return a list of all the agent monitoring rules that connected to a given agent
    '''
    validate_string(Name=AgentName)
    allRules = connection.get_all_agent_monitoring_rule_dam_global_objects()
    agentRules = list(filter(lambda rule:((set(AgentTags) & set(rule.ApplyToTag))
                                                or AgentName in rule.ApplyToAgent), allRules))
    return agentRules