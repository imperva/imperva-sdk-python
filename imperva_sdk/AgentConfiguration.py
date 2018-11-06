# Copyright 2018 Imperva. All rights reserved.

from imperva_sdk.core import *
import json

class AgentConfiguration(MxObject):
  '''
  MX agent configuration Class

  >>> agentConfig = mx.get_agent_configuration("agent1")
  >>> agentConfig.Ip
  '10.100.11.141'

  >>> agentConfig.DataInterfaces
  [{'id': '5088506452742197563', 'type': 'OracleBEQ', 'port': '', 'ignore': False},
  {'id': '4655394282992024501', 'type': 'OracleIPC', 'port': '', 'ignore': False},
  {'id': '-1415480154256812489', 'type': 'TCP', 'port': '1521', 'ignore': False},
  {'id': '1920263846107177725', 'type': 'TCP', 'port': '2484', 'ignore': False},
  {'id': '-7430847132580315645', 'type': 'TCPLocal', 'port': '1521', 'ignore': False},
  {'id': '4785307529015488446', 'type': 'TCPLocal', 'port': '2484', 'ignore': False}]

  >>> agentConfig.AdvancedConfig
  {'agent-config':
    {'files-dir': '.', 'quota': '8000'}
  }

  >>> # Create user defined copy of agent configuration
  >>> agentConfigDict = dict(agentConfig)
  >>> agentConfigDict['Name'] = 'user defined - %s' % agentConfigDict['Name']
  >>> agentConfigDict['update'] = True
  >>> mx._create_agent_configuration(**agentConfigDict)
  <imperva_sdk 'AgentConfiguration' Object - 'user defined -agent1'>

  '''

  # Store created objects in_instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = AgentConfiguration._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj

  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'AgentConfiguration':
        if cur_obj.Name == Name:
          return cur_obj
    return None

  def __init__(self, connection=None, Name=None, Ip=None, DataInterfaces=[], Tags=[], AdvancedConfig={},
               DiscoverySettings={}, CpuUsageRestraining={}, GeneralDetails={}):
    super(AgentConfiguration, self).__init__(connection=connection, Name=Name)
    self._Ip = Ip
    self._DataInterfaces = MxList(DataInterfaces)
    self._Tags = MxList(Tags)
    self._AdvancedConfig = AdvancedConfig
    self._DiscoverySettings = DiscoverySettings
    self._CpuUsageRestraining = CpuUsageRestraining
    self._GeneralDetails = GeneralDetails


  @property
  def Name(self):
    ''' The name of the agent (string) '''
    return self._Name

  @property
  def Ip(self):
    ''' The ip of the agent (string) '''
    return self._Ip

  @property
  def DataInterfaces(self):
    '''
    A data interfaces list of the agent.

    >>> agentConfig = mx.get_agent_configuration("agent1")
    >>> agentConfig.DataInterfaces
    [
        {
            "ignore": false,
            "port": "",
            "type": "OracleBEQ",
            "id": "5088506452742197563"
        },
        {
            "ignore": false,
            "port": "",
            "type": "OracleIPC",
            "id": "4655394282992024501"
        },
        {
            "ignore": false,
            "port": "1521",
            "type": "TCP",
            "id": "-1415480154256812489"
        }
    ]
    '''
    return self._DataInterfaces

  @property
  def Tags(self):
    '''
    A data interfaces list of the agent.

    >>> agentConfig = mx.get_agent_configuration("agent1")
    >>> agentConfig.Tags
    {
        "tags": [
            "tag1"
        ]
    }
    '''
    return self._Tags

  @property
  def AdvancedConfig(self):
    '''
    The advanced config of the agent
    >>> agentConfig = mx.get_agent_configuration("agent1")
    >>> agentConfig.AdvancedConfig
    {
        "agent-config": {
            "files-dir": ".",
            "quota": "8000"
        }
    }
    '''
    return self._AdvancedConfig

  @property
  def DiscoverySettings(self):
    '''
    The discovery settings of the agent
    >>> agentConfig = mx.get_agent_configuration("agent1")
    >>> agentConfig.DiscoverySettings
    {
        "enabled": true,
        "scan-interval": 120
    }
    '''
    return self._DiscoverySettings

  @property
  def CpuUsageRestraining(self):
    '''
    The cpu usage restraining of the agent
    >>> agentConfig = mx.get_agent_configuration("agent1")
    >>> agentConfig.CpuUsageRestraining
    {
        "enabled": false,
        "cpu-usage-limit": 15,
        "time-to-reactivate": 60
    }
    '''
    return self._CpuUsageRestraining

  @property
  def GeneralDetails(self):
    '''
    More details about the agent
    >>> agentConfig = mx.get_agent_configuration("agent1")
    >>> agentConfig.GeneralDetails
    {
        "status": {
            "general-status": "Disconnected",
            "start-time": "2018-09-12 09:23:46.0",
            "last-status-update": "Mon Oct 22 19:39:18 IDT 2018",
            "last-activity": "Never",
            "throughput-kb": "0",
            "connections-per-sec": "0",
            "hits-per-sec": "0",
            "cpu-utilization": "0"
        },
        "properties": {
            "Agent Version": "12.0.0.0151",
            "Platform": "x86_64",
            "Hostname": "rhel59dam1",
            "Operating System": "Linux 2.6.18-348.el5",
            "Kernel Patch": "#1 SMP Wed Nov 28 21:22:00 EST 2012"
        },
        "general-info": {
            "name": "141",
            "ip": "10.100.11.141",
            "creation-time": "2018-09-12 09:22:08.0",
            "manual-settings-activation": "Off"
        }
    }
    '''
    return self._GeneralDetails

  @Ip.setter
  def Ip(self, Ip):
    if Ip != self._Ip:
      self._connection._update_agent_configuration(Name=self._Name, Parameter='Ip', Value=Ip)
      self._Ip = Ip

  @GeneralDetails.setter
  def GeneralDetails(self, GeneralDetails):
    '''
    Assume GeneralDetails doesn't contain lists
    '''
    if GeneralDetails != self._GeneralDetails:
      self._connection._update_agent_configuration(Name=self._Name, Parameter='GeneralDetails', Value=GeneralDetails)
      self._GeneralDetails = GeneralDetails

  @AdvancedConfig.setter
  def AdvancedConfig(self, AdvancedConfig):
    '''
    Assume AdvancedConfig doesn't contain lists
    '''
    if AdvancedConfig != self._AdvancedConfig:
      self._connection._update_agent_configuration(Name=self._Name, Parameter='AdvancedConfiguration', Value=AdvancedConfig)
      self._AdvancedConfig = AdvancedConfig

  @DiscoverySettings.setter
  def DiscoverySettings(self, DiscoverySettings):
    '''
    Assume DiscoverySettings doesn't contain lists
    '''
    if DiscoverySettings != self._DiscoverySettings:
      self._connection._update_agent_configuration(Name=self._Name, Parameter='DiscoverySettings', Value=DiscoverySettings)
      self._DiscoverySettings = DiscoverySettings

  @CpuUsageRestraining.setter
  def CpuUsageRestraining(self, CpuUsageRestraining):
    '''
    Assume CpuUsageRestraining doesn't contain lists
    '''
    if CpuUsageRestraining != self._CpuUsageRestraining:
      self._connection._update_agent_configuration(Name=self._Name, Parameter='CPUUsageRestraining', Value=CpuUsageRestraining)
      self._CpuUsageRestraining = CpuUsageRestraining

  @DataInterfaces.setter
  def DataInterfaces(self, DataInterfaces):
    # Because the lists in SecureSphere don't have order, we need to sort them so we can compare them
    tmp1 = []
    for cur_item in DataInterfaces:
      tmp1.append(''.join(sorted(str(cur_item))))
    tmp1 = sorted(tmp1)
    tmp2 = []
    for cur_item in self._DataInterfaces:
      tmp2.append(''.join(sorted(str(cur_item))))
    tmp2 = sorted(tmp2)
    if tmp1 != tmp2:
      self._connection._update_agent_configuration(Name=self._Name, Parameter='DataInterfaces', Value=DataInterfaces)
      self._DataInterfaces = DataInterfaces

  @Tags.setter
  def Tags(self, Tags):
    # Because the lists in SecureSphere don't have order, we need to sort them so we can compare them
    tmp1 = []
    for cur_item in Tags:
      tmp1.append(''.join(sorted(str(cur_item))))
    tmp1 = sorted(tmp1)
    tmp2 = []
    for cur_item in self._Tags:
      tmp2.append(''.join(sorted(str(cur_item))))
    tmp2 = sorted(tmp2)
    if tmp1 != tmp2:
      self._connection._update_agent_configuration(Name=self._Name, Parameter='Tags', Value=Tags)
      self._Tags = Tags

  #
  # Agent configuration internal functions
  #

  @staticmethod
  def _get_all_agent_configurations(connection):
    res = connection._mx_api('GET', '/conf/agents')
    agent_objects = []
    for agent in res['agents']:
      try:
        obj = connection.get_agent_configuration(Name=agent['name'], Ip=agent['ip'])
      except:
        raise MxException("Failed getting all agents configurations")
      if obj:
        agent_objects.append(obj)
    return agent_objects

  @staticmethod
  def _get_agent_configuration_by_name(connection, Name=None, Ip=None):
    validate_string(Name=Name)
    obj_exists = AgentConfiguration._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      resTags = connection._mx_api('GET', '/conf/agents/%s/tags' % Name)
      resDataInterfaces = connection._mx_api('GET', '/conf/agents/%s/dataInterfaces' % Name)
      resAdvancedConfig = connection._mx_api('GET', '/conf/agents/%s/Settings/AdvancedConfiguration' % Name)
      resDiscovery = connection._mx_api('GET', '/conf/agents/%s/Settings/DiscoverySettings' % Name)
      resCPU = connection._mx_api('GET', '/conf/agents/%s/Settings/CPUUsageRestraining' % Name)
      resGeneral = connection._mx_api('GET', '/conf/agents/%s/GeneralDetails' % Name)
    except:
      return None
    return AgentConfiguration(connection=connection,
                              Name=Name,
                              Ip=Ip,
                              DataInterfaces=resDataInterfaces['data-interfaces'],
                              Tags=resTags['tags'],
                              AdvancedConfig=resAdvancedConfig,
                              DiscoverySettings=resDiscovery,
                              CpuUsageRestraining=resCPU,
                              GeneralDetails=resGeneral)


  @staticmethod
  def _create_agent_configuration(connection, Name=None, Ip=None, DataInterfaces=[], Tags=[], AdvancedConfig={},
                                  DiscoverySettings={}, CpuUsageRestraining={}, GeneralDetails={}, update=False):
    validate_string(Name=Name)
    obj = connection.get_agent_configuration(Name=Name)
    if obj:
      if not update:
        raise MxException("Agent configuration '%s' already exists" % Name)
      else:
        # Update existing agent configuration
        parameters = locals()
        for cur_key in list(parameters):
          if is_parameter.match(cur_key) and cur_key != 'Name' and parameters[cur_key] != None:
            setattr(obj, cur_key, parameters[cur_key])
        return obj

    raise MxException("Doesn't support creating a new agent configuration")

  @staticmethod
  def _update_agent_configuration(connection, Name=None, Parameter=None, Value=None):
    '''
        Assume that _update will be called ONLY within the class setters
    '''
    validate_string(Name=Name)
    if Parameter in ['Tags', 'AdvancedConfiguration', 'CPUUsageRestraining', 'DiscoverySettings']:
      if Parameter == 'Tags':
        # First, check if tags exist. If not, create them
        known_tags = set([tag.Name for tag in connection.get_all_tags()])
        missing_tags = list(set(Value) - known_tags)
        for tag in missing_tags:
          connection.create_tag(tag)
        # Second, replace the existing tags with the new ones
        connection._mx_api('POST', '/conf/agents/%s/tags' % Name, data=json.dumps({'tags': Value}))
      elif isinstance(Value, dict):
        if Parameter == 'AdvancedConfiguration':
          connection._mx_api('PUT', '/conf/agents/%s/Settings/AdvancedConfiguration' % Name, data=json.dumps(Value))
        elif Parameter == 'DiscoverySettings':
          connection._mx_api('PUT', '/conf/agents/%s/Settings/DiscoverySettings' % Name, data=json.dumps(Value))
        elif Parameter == 'CPUUsageRestraining':
          connection._mx_api('PUT', '/conf/agents/%s/Settings/CPUUsageRestraining' % Name, data=json.dumps(Value))
      else:
        raise MxException("Value of parameter '%s' must be from type dictionary" % Parameter)

    return True