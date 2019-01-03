# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class DbApplication(MxObject):
  ''' 
  MX DB Application Class 
  >>> dba = ws.get_db_application("Default DB Application")
  >>> dba.Name = "DB application name"                                                                  
  '''
  
  # Store created DbApplication objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = DbApplication._exists(connection=kwargs['connection'], Site=kwargs['Site'], ServerGroup=kwargs['ServerGroup'], DbService=kwargs['DbService'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj

  @staticmethod
  def _exists(connection=None, Name=None, Site=None, ServerGroup=None, DbService=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'DbApplication':
        if cur_obj.Name == Name and cur_obj._Site == Site and cur_obj._ServerGroup == ServerGroup and cur_obj._DbService == DbService:
          return cur_obj
    return None
  
  def __init__(self, connection=None, DbService=None, Name=None, ServerGroup=None, Site=None, TableGroupValues=[]):
    super(DbApplication, self).__init__(connection=connection, Name=Name)
    validate_string(DbService=DbService, Site=Site, ServerGroup=ServerGroup, Name=Name)
    self._Name = Name
    self._Site = Site
    self._ServerGroup = ServerGroup
    self._DbService = DbService
    self._TableGroupValues = TableGroupValues

  # Overriding iter (dict) function to handle profile and mappings properly
  def __iter__(self):
    iters = {}
    for field in dir(self):
      # Only variables should start with a capital letter
      if is_parameter.match(field):
        variable_function = getattr(self, field)
        iters[field] = variable_function
      # If the object has a "get_all" function, we need to build the child objects
      elif field.startswith('get_all_'):
        child_title = field.replace('get_all_', '')
        iters[child_title] = []
        get_all_function = getattr(self, field)
        children = get_all_function()
        for child in children:
          iters[child_title].append(dict(child))
#    try:
#      iters["Profile"] = self.get_profile()
#    except MxExceptionNotFound:
#      # Probably working with old version of MX that doesn't have profile APIs
#      pass
    for x,y in iters.items():
      yield x, y

  #
  # DB Application parameters
  # 
  @property
  def Name(self):
    ''' DB Application name (string) '''
    return self._Name

  @property
  def TableGroupValues(self):
    return self._TableGroupValues

  @Name.setter
  def Name(self, Name):
    if Name != self._Name:
      self._connection._update_db_application(Name=self._Name, Site=self._Site, ServerGroup=self._ServerGroup, DbService=self._DbService, Parameter='appName', Value=Name)
      self._Name = Name

  # Note - this should be fixed after I know the exact URLs and the exact mapping
  @TableGroupValues.setter
  def TableGroupValues(self, TableGroupValues):
    # This is not implemented. It should be later.
    self._TableGroupValues = TableGroupValues
      
  #
  # DB Application internal functions
  #
  @staticmethod
  def _get_all_db_applications(connection, ServerGroup=None, Site=None, DbService=None):
    validate_string(Site=Site, ServerGroup=ServerGroup, DbService=DbService)
    res = connection._mx_api('GET', '/conf/dbApplications/%s/%s/%s' % (Site, ServerGroup, DbService))
    try:
      dba_names = res['applications']
    except:
      raise MxException("Failed getting DB Applications")
    dba_objects = []
    for dba in dba_names:
      dba_objects.append(connection.get_db_application(Site=Site, ServerGroup=ServerGroup, DbService=DbService, Name=dba))
    return dba_objects

  @staticmethod
  def _get_db_application(connection, Name=None, ServerGroup=None, Site=None, DbService=None):
    validate_string(Site=Site, ServerGroup=ServerGroup, DbService=DbService, Name=Name)
    obj_exists = DbApplication._exists(connection=connection, Name=Name, Site=Site, ServerGroup=ServerGroup, DbService=DbService)
    if obj_exists:
      return obj_exists
    try:
      dba_json = connection._mx_api('GET', '/conf/dbApplications/%s/%s/%s/%s' % (Site, ServerGroup, DbService, Name))
    except: 
      return None
    TableGroupValues = dba_json['tableGroupValues']
    return DbApplication(connection=connection, Name=Name, DbService=DbService, ServerGroup=ServerGroup, Site=Site, TableGroupValues=TableGroupValues)

  @staticmethod
  def _create_db_application(connection, Name=None, DbService=None, ServerGroup=None, Site=None, TableGroupValues=None, update=False):
    validate_string(Site=Site, ServerGroup=ServerGroup, DbService=DbService, Name=Name)
    dba = connection.get_db_application(Site=Site, ServerGroup=ServerGroup, DbService=DbService, Name=Name)
    if dba:
      if update:
        parameters = dict(locals())
        for cur_key in parameters:
          if is_parameter.match(cur_key) and cur_key not in ['Name', 'Site', 'ServerGroup', 'DbService', 'Profile'] and parameters[cur_key] != None:
            setattr(dba, cur_key, parameters[cur_key])
        return dba
      else:
        raise MxException("DB Application '%s' already exists" % Name)
    body = {}
    if TableGroupValues: body['tableGroupValues'] = TableGroupValues
    connection._mx_api('POST', '/conf/dbApplications/%s/%s/%s/%s' % (Site, ServerGroup, DbService, Name), data=json.dumps(body))
    dba = DbApplication(connection=connection, Name=Name, DbService=DbService, ServerGroup=ServerGroup, Site=Site, TableGroupValues=TableGroupValues)
    return dba

  @staticmethod
  def _delete_db_application(connection, Name=None, DbService=None, ServerGroup=None, Site=None):
    validate_string(DbService=DbService, ServerGroup=ServerGroup, Site=Site, Name=Name)
    dba = connection.get_db_application(Site=Site, ServerGroup=ServerGroup, DbService=DbService, Name=Name)
    if dba:
      connection._mx_api('DELETE', '/conf/dbApplications/%s/%s/%s/%s' % (Site, ServerGroup, DbService, Name))
      connection._instances.remove(dba)
      del dba
    else:
      raise MxException("DB Application does not exist")
    return True    

  @staticmethod
  def _update_db_application(connection, DbService=None, ServerGroup=None, Site=None, Name=None, Parameter=None, Value=None):
    body = { Parameter: Value }
    connection._mx_api('PUT', '/conf/dbApplications/%s/%s/%s/%s' % (Site, ServerGroup, DbService, Name), data=json.dumps(body))
    return True

#  When we support profile, goto WebApplication and copy and modify the part from _get_profile onwards, as it is all about profile
