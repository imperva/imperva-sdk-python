# Copyright 2018 Imperva. All rights reserved.

from imperva_sdk.core import *
import json

class LookupDataSet(MxObject):
  '''
  MX global object lookup dataset Class
  #TODO orf - update usage examples
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

  # Store created datasets objects in_instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = LookupDataSet._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj

  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'LookupDataSet':
        if cur_obj.Name == Name:
          return cur_obj
    return None

  def __init__(self, connection=None, Name=None, Records=[], Columns=[]):
    super(LookupDataSet, self).__init__(connection=connection, Name=Name)
    self._Records = MxList(Records)
    self._Columns = MxList(Columns)

    #
    # Lookup dataset Parameters
    #

  @property
  def Name(self):
    ''' The name of the dataset (string) '''
    return self._Name

  @property
  def Records(self):
    '''
    A dataset record in API JSON format.

    >>> rule = mx.get_Lookup_Data_Set("testSet")
    >>> rule.Record
    [
      {
          "DB Account": "account1",
          "Organizational Account": "org1"
      }
  ]
    '''
    return self._Records

  @property
  def Columns(self):
    '''
    A dataset Columns in API JSON format.

    >>> rule = mx.get_Lookup_Data_Set("testSet")
    >>> rule.Columns
    [
      {
          "name": "DB Account",
          "key": true
      },
      {
          "name": "Organizational Account",
          "key": false
      }
  ]
    '''
    return self._Columns

  @Records.setter
  def Records(self, Records):
    # Check if we need to add anything
    addRecords = []
    for record in Records:
      if record not in self._Records:
        addRecords.append(record)

    if addRecords:
      record_dict = {
        'action': "add",
        'records': addRecords
      }
      self._connection._update_lookup_data_set(Name=self._Name, Parameter='Records', Value=record_dict)

    # Check if we need to remove anything
    deleteRecords = []
    for record in self._Records:
      if record not in Records:
        deleteRecords.append(record)

    if deleteRecords:
      record_dict = {
        'action': "delete",
        'records': deleteRecords
      }
      self._connection._update_lookup_data_set(Name=self._Name, Parameter='Records', Value=record_dict)

    self._Records = Records

  @Columns.setter
  def Columns(self, Columns):
    # Because the lists in SecureSphere don't have order, we need to sort them so we can compare them
    tmp1 = []
    for cur_item in Columns:
      tmp1.append(''.join(sorted(str(cur_item))))
    tmp1 = sorted(tmp1)
    tmp2 = []
    for cur_item in self._Columns:
      tmp2.append(''.join(sorted(str(cur_item))))
    tmp2 = sorted(tmp2)
    if tmp1 != tmp2:
      self._connection._update_lookup_data_set(Name=self._Name, Parameter='Columns', Value=Columns)
      self._Columns = Columns

  #
  # Lookup data set internal functions
  #

  @staticmethod
  def _get_all_lookup_data_set(connection):
    res = connection._mx_api('GET', '/conf/dataSets')
    rules_objects = []
    for name in res:
      try:
        obj = connection.get_lookup_data_set(Name=name)
      except:
        raise MxException("Failed getting all DB audit reports")
      if obj:
        rules_objects.append(obj)
    return rules_objects

  @staticmethod
  def _get_lookup_data_set_by_name(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = LookupDataSet._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      resData = connection._mx_api('GET', '/conf/dataSets/%s/data' % Name)
      resColumns = connection._mx_api('GET', '/conf/dataSets/%s/columns' % Name)
    except:
      return None
    return LookupDataSet(connection=connection, Name=Name, Records=resData['records'], Columns=resColumns['columns'])

  @staticmethod
  def _create_lookup_data_set(connection, Name=None, Records=[], Columns=[], update=False, caseSensitive=False):
    validate_string(Name=Name)
    obj = connection.get_lookup_data_set(Name=Name)
    if obj:
      if not update:
        raise MxException("lookup data set '%s' already exists" % Name)
      else:
        # Update existing data set
        parameters = locals()
        for cur_key in list(parameters):
          if is_parameter.match(cur_key) and cur_key != 'Name' and parameters[cur_key] != None:
            setattr(obj, cur_key, parameters[cur_key])
        return obj

    # First, create an empty data set
    body = {}
    if Name: body['dataset-name'] = Name
    if Columns: body['columns'] = Columns
    body['number-of-columns'] = len(Columns)
    caseSensitiveStr = 'true' if caseSensitive else 'false'

    try:
      res = connection._mx_api('POST', '/conf/dataSets/createDataset?caseSensitive=%s' % caseSensitiveStr, data=json.dumps(body))
    except Exception as e:
      raise MxException("Failed creating lookup data set: %s" % e)

    # Second, update the newly created data set
    body = {}
    if Records: body['records'] = Records

    try:
      res = connection._mx_api('POST', '/conf/dataSets/%s/data' % Name , data=json.dumps(body))
    except Exception as e:
      raise MxException("Failed updating lookup data set: %s" % e)

    return LookupDataSet(connection=connection, Name=Name, Records=Records, Columns=Columns)

  @staticmethod
  def _update_lookup_data_set(connection, Name=None, Parameter=None, Value=None):
    if Parameter == 'Records':
      if Value:
        # Assume overwrite=true
        connection._mx_api('PUT', '/conf/dataSets/%s/data?overwrite=true' % Name, data=json.dumps(Value))
    elif Parameter == 'Columns':
      print("WARNING: lookup data set doesn't support update %s" % Parameter)

    return True