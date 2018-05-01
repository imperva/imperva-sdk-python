# Copyright 2018 Imperva. All rights reserved.

import json
from imperva-sdk.core import *

class ParameterTypeGlobalObject(MxObject):
  ''' 
  Parameter Type Configuration Global Object Class 

  '''

  # Store created Parameter Type Global Object objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = ParameterTypeGlobalObject._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'ParameterTypeGlobalObject':
        if cur_obj.Name == Name:
          return cur_obj
    return None
  
  def __init__(self, connection=None, Name=None, Regex=None):
    super(ParameterTypeGlobalObject, self).__init__(connection=connection, Name=Name)
    validate_string(Name=Name)
    self._Regex = Regex

  #
  # Parameter Type Global Object Parameters
  #
  @property
  def Name(self):
    ''' The name of the global object (string) '''
    return self._Name
  @property
  def Regex(self):
    ''' Parameter Type Configuration regular expression '''
    return self._Regex

  @Regex.setter
  def Regex(self, Regex):
    if Regex != self._Regex:
      self._connection._update_parameter_type_global_object(Name=self._Name, Parameter='regularExpression', Value=Regex)
      self._Regex = Regex

    
  #
  # Parameter Type Configuration internal functions
  #
  @staticmethod
  def _get_all_parameter_type_global_objects(connection):
    res = connection._mx_api('GET', '/conf/globalObjects/parameterTypeConfiguration')
    try:
      names = res['parameterTypeConfigurationName']
    except:
      raise MxException("Failed getting Parameter Type Configurations")
    objects = []
    for name in names:
      obj = connection.get_parameter_type_global_object(Name=name)
      if obj:
        objects.append(obj)
    return objects
  @staticmethod
  def _get_parameter_type_global_object(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = ParameterTypeGlobalObject._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/globalObjects/parameterTypeConfiguration/%s' % Name)
    except:
      return None
    return ParameterTypeGlobalObject(connection=connection, Name=Name, Regex=res['regularExpression'])
  @staticmethod
  def _create_parameter_type_global_object(connection, Name=None, Regex=None, update=False):
    validate_string(Name=Name)
    obj = connection.get_parameter_type_global_object(Name=Name)
    if obj:
      if not update:
        raise MxException("Parameter Type Configuration '%s' already exists" % Name)
      else:
        # Update existing global object
        parameters = locals()
        for cur_key in parameters:
          if is_parameter.match(cur_key) and cur_key != 'Name' and parameters[cur_key] != None:
            setattr(obj, cur_key, parameters[cur_key])
      return obj
    else:
      # Create new global object
      body = {
        'regularExpression': Regex
      }
      connection._mx_api('POST', '/conf/globalObjects/parameterTypeConfiguration/%s' % Name, data=json.dumps(body))
      return ParameterTypeGlobalObject(connection=connection, Name=Name, Regex=Regex)
  @staticmethod
  def _delete_parameter_type_global_object(connection, Name=None):
    validate_string(Name=Name)
    obj = connection.get_parameter_type_global_object(Name=Name)
    if obj:
      connection._mx_api('DELETE', '/conf/globalObjects/parameterTypeConfiguration/%s' % Name)
      connection._instances.remove(obj)
      del obj
    else:
      raise MxException("Parameter Type Configuration does not exist")
    return True    
  @staticmethod
  def _update_parameter_type_global_object(connection, Name=None, Parameter=None, Value=None):
    body = { Parameter: Value }
    connection._mx_api('PUT', '/conf/globalObjects/parameterTypeConfiguration/%s' % Name, data=json.dumps(body))
    return True

