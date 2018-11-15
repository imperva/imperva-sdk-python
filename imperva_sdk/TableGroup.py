# Copyright 2018 Imperva. All rights reserved.
import json

from imperva_sdk.core import *

class TableGroup(MxObject):
  '''
  MX table group Class

  >>> tableGroup = mx.get_table_group("testTableGroup")
  >>> tableGroup.Records
  [{'Type': 'View', 'Name': 'a1'},
  {'Columns': ['c1', 'c2'], 'Type': 'Table', 'Name': 'a3'},
  {'Type': 'SystemTable', 'Name': 'a4'}, {'Type': 'Table', 'Name': 'a5'}]

  >>> tableGroup.records = [{"Name": "aa11", "Type": "View"}, {"Name": "aa22", "Type": "View"}]

  >>> tableGroup.ServiceTypes
  ['Oracle', 'Db2', 'MsSql', 'Sybase']

  Note that we don't support updating ServiceTypes/isSensitive/dataType - only in create new table group

  >>> # Create user defined copy of table group
  >>> tableGroupDict = dict(tableGroup)
  >>> tableGroupDict['Name'] = 'user defined - %s' % tableGroupDict['Name']
  >>> mx.create_table_groups_global_object(**tableGroupDict)
  <imperva_sdk 'TableGroup' Object - 'user defined - testTableGroup'>

  '''

  # Store created Policy objects in_instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = TableGroup._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'TableGroup':
        if cur_obj.Name == Name:
          return cur_obj
    return None

  def __init__(self, connection=None, Name=None, IsSensitive=None, DataType=None, ServiceTypes=[], Records=[]):
    super(TableGroup, self).__init__(connection=connection, Name=Name)
    self._IsSensitive = IsSensitive
    self._DataType = DataType
    self._ServiceTypes = MxList(ServiceTypes)
    self._Records = MxList(Records)

  #
  # Table group Parameters
  #

  @property
  def Name(self):
    ''' The name of the table group (string) '''
    return self._Name

  @property
  def IsSensitive(self):
    ''' True if the table group is sensitive (boolean) '''
    return self._IsSensitive

  @property
  def DataType(self):
    ''' The data type of the table group (string) '''
    return self._DataType

  @property
  def ServiceTypes(self):
    ''' The service types of the table group (list) '''
    return self._ServiceTypes

  @property
  def Records(self):
    ''' The service types of the table group (list) '''
    return self._Records

  @IsSensitive.setter
  def IsSensitive(self, IsSensitive):
    if IsSensitive != self._IsSensitive:
      self._connection._update_table_group(Name=self._Name, Parameter='IsSensitive', Value=IsSensitive)
      self._IsSensitive = IsSensitive

  @DataType.setter
  def DataType(self, DataType):
    if DataType != self._DataType:
      self._connection._update_table_group(Name=self._Name, Parameter='DataType', Value=DataType)
      self._DataType = DataType

  @ServiceTypes.setter
  def ServiceTypes(self, ServiceTypes):
    # Because the lists in SecureSphere don't have order, we need to sort them so we can compare them
    # ServiceTypes are list of strings
    tmp1 = sorted(ServiceTypes)
    tmp2 = sorted(self._ServiceTypes)
    if tmp1 != tmp2:
      self._connection._update_table_group(Name=self._Name, Parameter='ServiceTypes', Value=ServiceTypes)
      self._ServiceTypes = ServiceTypes

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
      self._connection._update_table_group(Name=self._Name, Parameter='Records', Value=record_dict)

    # Check if we need to remove anything
    deleteRecords = []
    for record in self._Records:
      if record not in Records:
        deleteRecords.append(record)

    # remove only records we didn't update before
    deleteKeys = set([record['Name'] for record in deleteRecords])
    addKeys = set([record['Name'] for record in addRecords])

    reallyDeleteRecordsKeys = deleteKeys - addKeys
    reallyDeleteRecords = [record for record in deleteRecords if record['Name'] in reallyDeleteRecordsKeys]

    if reallyDeleteRecords:
      record_dict = {
        'action': "delete",
        'records': reallyDeleteRecords
      }
      self._connection._update_table_group(Name=self._Name, Parameter='Records', Value=record_dict)

    self._Records = Records

  #
  # Table group internal functions
  #

  @staticmethod
  def _get_all_table_groups(connection):
    res = connection._mx_api('GET', '/conf/tableGroups')
    tg_objects = []
    for tg in res:
      # Bug - we have data types with '/' character that don't work with the API...
      if '/' in tg['displayName']:
        continue
      obj = connection.get_table_group(Name=tg['displayName'], IsSensitive=tg['isSensitive'],
                                       ServiceTypes=tg['serviceTypes'])
      if obj:
        tg_objects.append(obj)
    return tg_objects

  @staticmethod
  def _get_table_group_by_name(connection, Name=None, IsSensitive=None, ServiceTypes=[]):
    validate_string(Name=Name)
    obj_exists = TableGroup._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      resData = connection._mx_api('GET', '/conf/tableGroups/%s/data' % Name)
    except:
      return None
    return TableGroup(connection=connection, Name=Name, IsSensitive=IsSensitive, DataType=None,
                      ServiceTypes=ServiceTypes, Records=resData['records'])

  @staticmethod
  def _create_table_group(connection, Name=None, IsSensitive=None, DataType=None, ServiceTypes=[], Records=[],
                          update=False):
    validate_string(Name=Name)
    obj = connection.get_table_group(Name=Name)
    if obj:
      if not update:
        raise MxException("table group '%s' already exists" % Name)
      else:
        # Update existing data set
        parameters = dict(locals())
        for cur_key in list(parameters):
          if is_parameter.match(cur_key) and cur_key != 'Name' and parameters[cur_key] != None:
            setattr(obj, cur_key, parameters[cur_key])
        return obj

    # First, create an empty table group
    body = {}
    if Name: body['displayName'] = Name
    if DataType: body['dataType'] = DataType
    body['isSensitive'] = True if IsSensitive else False
    body['serviceTypes'] = ServiceTypes

    try:
      res = connection._mx_api('POST', '/conf/tableGroups', data=json.dumps(body))
    except Exception as e:
      raise MxException("Failed creating table group: %s" % e)

    # Second, update the newly created table group
    body = {}
    body['records'] = Records

    try:
      res = connection._mx_api('POST', '/conf/tableGroups/%s/data' % Name , data=json.dumps(body))
    except Exception as e:
      raise MxException("Failed updating table group: %s" % e)

    return TableGroup(connection=connection, Name=Name, IsSensitive=IsSensitive, DataType=DataType,
                      ServiceTypes=ServiceTypes, Records=Records)

  @staticmethod
  def _update_table_group(connection, Name=None, Parameter=None, Value=None):
    if Parameter == 'Records':
      if Value:
        # Assume overwrite=true
        connection._mx_api('PUT', '/conf/tableGroups/%s/data?overwrite=true' % Name, data=json.dumps(Value))

    # table group doesn't support update IsSensitive/DataType/ServiceTypes

    elif Parameter != 'IsSensitive' and Parameter != 'DataType' and Parameter != 'ServiceTypes':
      raise MxException("Parameter '%s' must be 'Records'" % Name)


    return True