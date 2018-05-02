# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class ActionSet(MxObject):
  '''
  MX Action Set Class
  '''
  # Store created Action Set objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = ActionSet._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'ActionSet':
        if cur_obj.Name == Name:
          return cur_obj
    return None

  def __init__(self, connection=None, Name=None, AsType=None):
    super(ActionSet, self).__init__(connection=connection, Name=Name)
    validate_string(Name=Name)
    self._AsType = AsType

  #
  # Action Set Parameters
  #
  @property
  def Name(self):
    ''' The name of the Action Set (string) '''
    return self._Name
  @property
  def AsType(self):
    ''' The type of the Action Set (security / any) '''
    return self._AsType

  #
  # Action Set internal functions
  #
  @staticmethod
  def _get_all_action_sets(connection):
    res = connection._mx_api('GET', '/conf/actionSets')
    try:
      action_sets = res['actionSets']
    except:
      raise MxException("Failed getting Action Sets")
    as_objects = []
    for as_name in action_sets:
      get_as = connection.get_action_set(Name=as_name)
      # we only support a limited number of Action Set types
      if get_as:
        as_objects.append(get_as)
    return as_objects
  @staticmethod
  def _get_action_set(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = ActionSet._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/actionSets/%s' % Name)
    except:
      return None
    return ActionSet(connection=connection, Name=Name, AsType=res['type'])
  @staticmethod
  def _create_action_set(connection, Name=None, AsType=None, update=False):
    validate_string(Name=Name)
    action_set = connection.get_action_set(Name=Name)
    if action_set:
      if not update:
        raise MxException("Action Set '%s' already exists" % Name)
      else:
        # Update existing
        pass
      return action_set
    body = {'type': AsType}
    connection._mx_api('POST', '/conf/actionSets/%s' % (Name), data=json.dumps(body))
    return ActionSet(connection=connection, Name=Name, AsType=AsType)
  @staticmethod
  def _delete_action_set(connection, Name=None):
    validate_string(Name=Name)
    action_set = connection.get_action_set(Name=Name)
    if action_set:
      connection._mx_api('DELETE', '/conf/actionSets/%s' % Name)
      connection._instances.remove(action_set)
      del action_set
    else:
      raise MxException("Action Set does not exist")
    return True    
    
  def get_all_actions(self):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_all_actions`. '''
    return self._connection.get_all_actions(ActionSet=self.Name)
  def create_action(self, Name=None, ActionType=None, Protocol=None, SyslogFacility=None, Host=None, SyslogLogLevel=None, SecondaryPort=None, ActionInterface=None, SecondaryHost=None, Message=None, Port=None, update=False):
    ''' See :py:meth:`imperva_sdk.MxConnection.create_action`. '''
    return self._connection.create_action(Name=Name, ActionSet=self.Name, ActionType=ActionType, Protocol=Protocol, SyslogFacility=SyslogFacility, Host=Host, SyslogLogLevel=SyslogLogLevel, SecondaryPort=SecondaryPort, ActionInterface=ActionInterface, SecondaryHost=SecondaryHost, Message=Message, Port=Port, update=update)

