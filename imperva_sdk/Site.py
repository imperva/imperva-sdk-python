# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class Site(MxObject):
  ''' 
  MX Site Object

  >>> site = mx.create_site("my site")
  >>> site.Name = "new name"

  '''

  # Store created site objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = Site._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'Site':
        if cur_obj.Name == Name:
          return cur_obj
    return None

  def __init__(self, connection=None, Name=None):
    super(Site, self).__init__(connection=connection, Name=Name)
    validate_string(Name=Name)

  #
  # Site parameters
  #
  @property
  def Name(self):
    ''' Site Name '''
    return self._Name

  @Name.setter
  def Name(self, Name):
    validate_string(Name=Name)
    Site._update_site(connection=self._connection, Name=self.Name, Parameter='name', Value=Name)
    self._Name = Name

  #	
  # Site functions (should be called from other objects like MxConnection)
  #
  @staticmethod
  def _get_all_sites(connection):
    res = connection._mx_api('GET', '/conf/sites')
    try:
      site_names = res['sites']
    except:
      raise MxException("Failed getting sites")
    sites = []
    for site_name in site_names:
      sites.append(Site(connection=connection, Name=site_name))
    return sites
  @staticmethod
  def _get_site(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = Site._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    res = connection._mx_api('GET', '/conf/sites')
    try:
      site_names = res['sites']
    except:
      raise MxException("Failed getting sites")
    for site_name in site_names:
      if site_name == Name:
        return Site(connection=connection, Name=site_name)
    return None
  @staticmethod
  def _create_site(connection, Name=None, update=False):
    validate_string(Name=Name)
    site_exists = connection.get_site(Name=Name)
    if site_exists:
      if update:
        return site_exists
      else:
        raise MxException("Site already exists")
    else:
      connection._mx_api('POST', '/conf/sites/%s' % Name)
      return Site(connection=connection, Name=Name)
  @staticmethod
  def _delete_site(connection, Name=None):
    validate_string(Name=Name)
    site_exists = connection.get_site(Name=Name)
    if site_exists:
      sgs = connection.get_all_server_groups(Site=site_exists.Name)
      if len(sgs) != 0:
        for sg in sgs:
          connection.delete_server_group(Name=sg.Name,Site=site_exists.Name)
      connection._mx_api('DELETE', '/conf/sites/%s' % Name)
      connection._instances.remove(site_exists)
      del site_exists
    else:
      raise MxException("Site '%s' does not exist" % Name)
    return True
  @staticmethod
  def _delete_all_sites(connection, Name=None):
    # except the default one which cannot be deleted
    for site in connection.get_all_sites():
      if site.Name != 'Default Site':
        connection.delete_site(Name=site.Name)
    return True
  @staticmethod
  def _update_site(connection, Name=None, Parameter=None, Value=None):
    body = { Parameter: Value }
    connection._mx_api('PUT', '/conf/sites/%s' % Name, data=json.dumps(body))
    return True
        
  #
  # Site child (server group) functions
  #
  def create_server_group(self, Name=None, OperationMode=None, ProtectedIps=[], ServerIps=[], update=False):
    ''' See :py:meth:`imperva_sdk.MxConnection.create_server_group`. '''
    return self._connection.create_server_group(Name=Name, Site=self.Name, OperationMode=OperationMode, ProtectedIps=ProtectedIps, ServerIps=ServerIps, update=update)
  def delete_server_group(self, Name=None):
    ''' See :py:meth:`imperva_sdk.MxConnection.delete_server_group`. '''
    return self._connection.delete_server_group(Name=Name, Site=self.Name)
  def get_server_group(self, Name=None):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_server_group`. '''
    return self._connection.get_server_group(Name=Name, Site=self.Name)
  def get_all_server_groups(self):
    ''' See :py:meth:`imperva_sdk.MxConnection.get_all_server_groups`. '''
    return self._connection.get_all_server_groups(Site=self.Name)

