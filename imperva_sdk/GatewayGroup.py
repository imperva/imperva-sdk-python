
import json
from imperva_sdk.core import *

class GatewayGroup(MxObject):
  '''
  Gateway Group Object 
  '''

  # Store created site objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = GatewayGroup._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'GatewayGroup':
        if cur_obj.Name == Name:
          return cur_obj
    return None

  def __init__(self, connection=None, Name=None, GWSettings=None):
    super(GatewayGroup, self).__init__(connection=connection, Name=Name)
    validate_string(Name=Name)
    self._GWSettings = GWSettings

  #
  # Site parameters
  #
  @property
  def Name(self):
    ''' GatewayGroup Name '''
    return self._Name

  @property
  def GWSettings(self):
    ''' Gateway Group Dictionary settings '''
    return self._GWSettings

  @GWSettings.setter
  def GWSettings(self, GWSettings):
    self._GWSettings = GWSettings

  @staticmethod
  def _get_all_gateways(connection, gatewayGroup=None):
    try:
      res = connection._mx_api('GET', '/conf/gatewayGroups/%s/gateways' % gatewayGroup)
      if res != None:
          return res['gateways']
      else:
          return None
    except:
      return None

  @staticmethod
  def _get_all_gatewaygroups(connection):
    res = connection._mx_api('GET', '/conf/gatewayGroups')
    try:
      gatewaygroup_names = []
      for value in res.values():
          if type(value) is list:
            gatewaygroup_names = gatewaygroup_names + value
          else:
            gatewaygroup_names.append(value)      
    except:
      raise MxException("Failed getting gatewayGroups")
    gatewaygroups = []
    for gatewaygroup_name in gatewaygroup_names:
      gatewaygroups.append(GatewayGroup._get_gatewaygroup(connection=connection, Name=gatewaygroup_name))
    return gatewaygroups

  @staticmethod
  def _get_gatewaygroup(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = GatewayGroup._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/gatewayGroups/%s' % Name)
      gatewaygroup_name = res['gatewayGroupName']
      return GatewayGroup(connection=connection, Name=gatewaygroup_name, GWSettings=res)
    except:
      return None
  @staticmethod

  def _create_gatewaygroup(connection, Name=None, gatewayPlatform=None, gatewayMode=None, failMode=None, overloadPolicy=None, Overwrite=None):
    validate_string(Name=Name)
    validate_string(Name=gatewayPlatform)
    validate_string(Name=gatewayMode)
    validate_string(Name=failMode)
    gatewaygroup_exists = connection.get_gatewaygroup(Name=Name)
    if gatewaygroup_exists:
      if Overwrite:
          GatewayGroup._delete_gatewaygroup(connection, Name=Name)
      else:
          return gatewaygroup_exists
    else:
      body = {
        'gatewayPlatform': gatewayPlatform,
        'gatewayMode': gatewayMode,
        'failMode': failMode
      }
      if overloadPolicy != None:
          body['overloadPolicy']= overloadPolicy
      connection._mx_api('POST', '/conf/gatewayGroups/%s' % Name, data=json.dumps(body))
      return GatewayGroup._get_gatewaygroup(connection=connection, Name=Name)
  @staticmethod

  def _delete_gatewaygroup(connection, Name=None):
    validate_string(Name=Name)
    gatewaygroup_exists = connection.get_gatewaygroup(Name=Name)
    if gatewaygroup_exists:
      connection._mx_api('DELETE', '/conf/gatewayGroups/%s' % Name)
      connection._instances.remove(gatewaygroup_exists)
      del gatewaygroup_exists
    else:
      raise MxException("Gateway group '%s' does not exist" % Name)
    return True