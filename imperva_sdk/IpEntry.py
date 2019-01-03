# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class IpEntry(MxObject):
  '''
  MX Ip Entry Class
  '''
  
  # Store created Ip entry objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj = super(MxObject, Type).__new__(Type)
    kwargs['connection']._instances.append(obj)
    return obj
  
  @staticmethod
  def _exists(connection=None, Name=None):
    for curr_obj in connection._instances:
      if type(curr_obj).__name__ == 'IpEntry':
        if curr_obj.Name == Name:
          return curr_obj
    return None

  def __init__(self, connection=None, Name=None, EntryType=None,
                      IpAddressFrom=None, IpAddressTo=None,
                      NetworkAddress=None, CidrMask=None,
                      Operation=None):
  
    super(IpEntry, self).__init__(connection=connection, Name=Name)
    self._Name = Name
    self._EntryType = EntryType
    self._IpAddressFrom = IpAddressFrom
    self._IpAddressTo = IpAddressTo
    self._NetworkAddress = NetworkAddress
    self._CidrMask = CidrMask
    self._Operation = Operation
  
  # Ip entry Parameter getters
  #-----------------------------------------------------------------------------------------------------
  # Description: properties for all Ip entry parameters
  #-----------------------------------------------------------------------------------------------------
  #
  @property
  def Name(self):    return self._Name
  @property
  def EntryType(self):   return self._EntryType
  @property
  def IpAddressFrom(self):    return self._IpAddressFrom
  @property
  def IpAddressTo(self):    return self._IpAddressTo
  @property
  def NetworkAddress(self):   return self._NetworkAddress
  @property
  def CidrMask(self):   return self._CidrMask
  @property
  def Operation(self):   return self._Operation

  @staticmethod
  def toDict(entryObj):
    if entryObj.__class__.__name__ == 'IpEntry':
      dict = {}
      dict['type'] = entryObj.EntryType
      dict['ipAddressFrom'] = entryObj.IpAddressFrom
      dict['ipAddressTo'] = entryObj.IpAddressTo
      dict['networkAddress'] = entryObj.NetworkAddress
      dict['cidrMask'] = entryObj.CidrMask
      dict['operation'] = entryObj.Operation

      return dict

  @staticmethod
  def validateEmptyIndices(ipEntry):
    if type(ipEntry) is not dict:
      return ipEntry

    if 'type' not in ipEntry:
      ipEntry['type'] = None
    if 'ipAddressFrom' not in ipEntry:
      ipEntry['ipAddressFrom'] = None
    if 'ipAddressTo' not in ipEntry:
      ipEntry['ipAddressTo'] = None
    if 'networkAddress' not in ipEntry:
      ipEntry['networkAddress'] = None
    if 'cidrMask' not in ipEntry:
      ipEntry['cidrMask'] = None
    if 'operation' not in ipEntry:
      ipEntry['operation'] = None

    return ipEntry
