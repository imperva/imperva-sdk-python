# Copyright 2018 Imperva. All rights reserved.
import json

from imperva_sdk.core import *


class LookupDataType(MxObject):
  '''
  MX global object lookup data type Class
  Note that we don't support updating/setting

  >>> dataType = mx.get_lookup_data_type("testDataType")
  >>> dataType.rules
  [{'rules-details': [{'column-name-regex': 'regex.*', 'content-regex': 'regex.*', 'table-name-regex': 'regex.*'}, {'table-name-regex': 'fff*.[]'}], 'name': 'OrRule1'},
  {'rules-details': [{'table-name-regex': 'ggg.+'}], 'name': 'OrRule2'}])
  >>> dataType.rules
  '$SITE - $SERVERGROUP_NAME - $SERVICE_NAME - $DATA_TYPE'

  >>> # Create user defined copy of dataType
  >>> dataTypeDict = dict(dataType)
  >>> dataTypeDict['Name'] = 'user defined - %s' % dataTypeDict['Name']
  >>> dataTypeDict['update'] = True
  >>> mx._create_lookup_data_type(**dataTypeDict)
  <imperva_sdk 'LookupDataType' Object - 'user defined - testDataType'>

  '''


  # Store created datasets objects in_instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = LookupDataType._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj

  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'LookupDataType':
        if cur_obj.Name == Name:
          return cur_obj
    return None


  def __init__(self, connection=None, Name=None, IsSensitive=True, Rules=[], TargetTableGroupName=None):
    super(LookupDataType, self).__init__(connection=connection, Name=Name)
    self._IsSensitive = IsSensitive
    self._Rules = MxList(Rules)
    self._TargetTableGroupName = TargetTableGroupName

  #
  # Lookup data type Parameters
  #

  @property
  def Name(self):
    ''' The name of the data type (string) '''
    return self._Name

  @property
  def IsSensitive(self):
    ''' True if the data type is sensitive (boolean) '''
    return self._IsSensitive

  @property
  def Rules(self):
    '''
    A data type rules (list).

    >>> rule = mx.get_lookup_data_type("testDataType")
    >>> rule.Rules
    [
        {
            "name": "testRule1",
            "rules-details": [
                {
                    "table-name-regex": "regex.*",
                    "column-name-regex": "regex.*",
                    "content-regex": "regex.*"
                }
            ]
        }
    ]
    '''
    return self._Rules

  @property
  def TargetTableGroupName(self):
    ''' The name of the target table group (string) '''
    return self._TargetTableGroupName


  @IsSensitive.setter
  def IsSensitive(self, IsSensitive):
    if IsSensitive != self._IsSensitive:
      self._connection._update_lookup_data_type(Name=self._Name, Parameter='IsSensitive', Value=IsSensitive)
      self._IsSensitive = IsSensitive

  @Rules.setter
  def Rules(self, Rules):
    # Because the lists in SecureSphere don't have order, we need to sort them so we can compare them
    tmp1 = []
    for cur_item in Rules:
      tmp1.append(''.join(sorted(str(cur_item))))
    tmp1 = sorted(tmp1)
    tmp2 = []
    for cur_item in self._Columns:
      tmp2.append(''.join(sorted(str(cur_item))))
    tmp2 = sorted(tmp2)
    if tmp1 != tmp2:
      self._connection._update_lookup_data_type(Name=self._Name, Parameter='Rules', Value=Rules)
      self._Rules = Rules

  @TargetTableGroupName.setter
  def TargetTableGroupName(self, TargetTableGroupName):
    if TargetTableGroupName != self._TargetTableGroupName:
      self._connection._update_lookup_data_type(Name=self._Name, Parameter='TargetTableGroupName',
                                                Value=TargetTableGroupName)
      self._TargetTableGroupName = TargetTableGroupName


  #
  # Lookup data type internal functions
  #

  @staticmethod
  def _get_all_lookup_data_type(connection):
    res = connection._mx_api('GET', '/conf/dataTypes')
    rules_objects = []
    for name in res:
      try:
        obj = connection.get_lookup_data_type(Name=name)
      except:
        raise MxException("Failed getting all data types")
      if obj:
        rules_objects.append(obj)
    return rules_objects

  @staticmethod
  def _get_lookup_data_type_by_name(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = LookupDataType._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/dataTypes/%s' % Name)
    except:
      return None
    return LookupDataType(connection=connection, Name=Name, IsSensitive=res['sensitive'], Rules=res['rules'],
                          TargetTableGroupName=res['target-table-group-name'])

  @staticmethod
  def _create_lookup_data_type(connection, Name=None, IsSensitive=True, Rules=[], TargetTableGroupName=None, update=False):
    validate_string(Name=Name)
    obj = connection.get_lookup_data_type(Name=Name)
    if obj:
      if not update:
        raise MxException("lookup data type '%s' already exists" % Name)
      else:
        # Update existing data type
        parameters = locals()
        for cur_key in list(parameters):
          if is_parameter.match(cur_key) and cur_key != 'Name' and parameters[cur_key] != None:
            setattr(obj, cur_key, parameters[cur_key])
        return obj

    body = {}
    if Name: body['name'] = Name
    if TargetTableGroupName: body['target-table-group-name'] = TargetTableGroupName
    body['rules'] = Rules
    body['sensitive'] = 'true' if IsSensitive else 'false'

    try:
      res = connection._mx_api('POST', '/conf/dataTypes/%s' % Name, data=json.dumps(body))
    except Exception as e:
      raise MxException("Failed creating lookup data type: %s" % e)

    return LookupDataType(connection=connection, Name=Name, IsSensitive=IsSensitive, Rules=Rules,
                          TargetTableGroupName=TargetTableGroupName)

  @staticmethod
  def _update_lookup_data_type(connection, Name=None, Parameter=None, Value=None):
    # lookup data type doesn't support update
    if Parameter != 'IsSensitive' or Parameter != 'Rules' or Parameter != 'TargetTableGroupName':
      raise MxException("Parameter '%s' must be one of ['IsSensitive', 'Rules', 'TargetTableGroupName']" % Name)

    return True



