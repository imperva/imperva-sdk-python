# Copyright 2018 Imperva. All rights reserved.

from imperva_sdk.IpEntry import *

class IpGroup(MxObject):
  '''
  MX Ip Group Class
  '''
  
  # Store created Ip group objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = IpGroup._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  
  @staticmethod
  def _exists(connection=None, Name=None):
    for curr_obj in connection._instances:
      if type(curr_obj).__name__ == 'IpGroup':
        if curr_obj.Name == Name:
          return curr_obj
    return None

  def __init__(self, connection=None, Name=None, Entries=[]):
  
    super(IpGroup, self).__init__(connection=connection, Name=Name)
    self._Name = Name
    self._Entries = MxList(Entries)
  
  # Ip group Parameter getters
  #-----------------------------------------------------------------------------------------------------
  # Description: properties for all Ip group parameters
  #-----------------------------------------------------------------------------------------------------
  #
  @property
  def Name(self):   return self._Name
  @property
  def Entries(self):   return self._Entries

  #
  # Ip group internal functions
  #
  @staticmethod
  def _get_all_ip_groups(connection):
    ipGroupsObj = connection._mx_api('GET', '/conf/ipGroups')
    if 'names' in ipGroupsObj:
      ipGroupsObjs = []
      for ipGroupName in ipGroupsObj['names']:
        # Bug - we have accounts with '/' character that don't work with the API...
        if '/' in ipGroupName:
          continue
        try:
          obj = connection.get_ip_group(Name=ipGroupName)
        except:
          raise MxException("Failed getting ip group '%s'" % ipGroupName)
        ipGroupsObjs.append(obj)
      return ipGroupsObjs
  
  @staticmethod
  def _get_ip_group(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = IpGroup._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      ipGroup = connection._mx_api('GET', '/conf/ipGroups/' + Name)
    except:
      return None

    return IpGroup(connection=connection, Name=Name, Entries=ipGroup['entries'])
    
    
  @staticmethod
  def _create_ip_group(connection, Name=None, Entries=[], update=False):
    validate_string(Name=Name)
    body = {}
    body['entries'] = Entries

    connection._mx_api('POST', '/conf/ipGroups/%s' % Name, data=json.dumps(body))
    return IpGroup(connection=connection, Name=Name, Entries=Entries)
  
  
  @staticmethod
  def _update_ip_group(connection, Name=None, GroupType=None,
                      IpAddressFrom=None, IpAddressTo=None,
                      NetworkAddress=None, CidrMask=None, Operation=None):
    raise MxException("Ip Group Update API currently not supported")
  
  @staticmethod
  def _delete_ip_group(connection, Name=None):
    raise MxException("Ip Group Delete API currently not supported")
