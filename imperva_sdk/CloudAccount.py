# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class CloudAccount(MxObject):
  '''
  MX Cloud Account Class
  '''
  
  # Store created Cloud account objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = CloudAccount._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  
  @staticmethod
  def _exists(connection=None, Name=None):
    for curr_obj in connection._instances:
      if type(curr_obj).__name__ == 'CloudAccount':
        if curr_obj.Name == Name:
          return curr_obj
    return None

  def __init__(self, connection=None, Name=None, PrivateKey=None, AccessKey=None, AwsRegion=None, AzureTenant=None, CloudProvider=None):
  
    super(CloudAccount, self).__init__(connection=connection, Name=Name)
    self._Name = Name
    self._PrivateKey = PrivateKey
    self._AccessKey = AccessKey
    self._AwsRegion = AwsRegion
    self._AzureTenant = AzureTenant
    self._CloudProvider = CloudProvider
  
  
  # Cloud Account Parameter getters
  #-----------------------------------------------------------------------------------------------------
  # Description: properties for all cloud account parameters
  #-----------------------------------------------------------------------------------------------------
  #
  @property
  def Name(self):   return self._Name

  @property
  def PrivateKey(self):     return self._PrivateKey

  @property
  def AccessKey(self):      return self._AccessKey

  @property
  def AwsRegion(self):      return self._AwsRegion

  @property
  def AzureTenant(self):        return self._AzureTenant

  @property
  def CloudProvider(self):      return self._CloudProvider
  
  #
  # Cloud Account internal functions
  #
  @staticmethod
  def _get_all_cloud_accounts(connection):
    accountNamesObj = connection._mx_api('GET', '/conf/cloudAccounts')
    if 'names' in accountNamesObj:
      accountObjects = []
      for accountName in accountNamesObj['names']:
        # Bug - we have accounts with '/' character that don't work with the API...
        if '/' in accountName:
          continue
        try:
          obj = connection.get_cloud_account(accountName)
        except:
          raise MxException("Failed getting cloud account '%s'" % accountName)
        accountObjects.append(obj)
      return accountObjects
  
  @staticmethod
  def _get_cloud_account(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = CloudAccount._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      account = connection._mx_api('GET', '/conf/cloudAccounts/' + Name)
    except:
      return None
    account = CloudAccount.validateEmptyIndices(account)
    return CloudAccount(connection=connection, Name=Name, PrivateKey=account['privateKey'], AccessKey=account['accessKey'],
                        AwsRegion=account['awsRegion'], AzureTenant=account['azureTenant'],
                        CloudProvider=account['cloudProvider'])
    
    
  @staticmethod
  def _create_cloud_account(connection, Name=None, PrivateKey=None, AccessKey=None, AwsRegion=None, AzureTenant=None, CloudProvider=None, update=False):
    validate_string(Name=Name)
    body = {}
    body['privateKey'] = PrivateKey
    body['accessKey'] = AccessKey
    body['awsRegion'] = AwsRegion
    body['azureTenant'] = AzureTenant
    body['cloudProvider'] = CloudProvider

    try:
      connection._mx_api('POST', '/conf/cloudAccounts/%s' % Name, data=json.dumps(body))
    except Exception as e:
      raise MxException("Failed creating cloud account: %s" % e)
    return CloudAccount(connection=connection, Name=Name, PrivateKey=PrivateKey, AccessKey=AccessKey,
                        AwsRegion=AwsRegion, AzureTenant=AzureTenant, CloudProvider=CloudProvider)
  
  
  @staticmethod
  def _update_cloud_account(connection, Name=None, PrivateKey=None, AccessKey=None, AwsRegion=None, AzureTenant=None, CloudProvider=None):
    raise MxException("Cloud Account Update API currently not supported")
  
  @staticmethod
  def _delete_data_cloud_account(connection, Name=None):
    raise MxException("Cloud Account Delete API currently not supported")

  @staticmethod
  def validateEmptyIndices(account):
    if type(account) is not dict:
      return account

    if 'name' not in account:
      account['name'] = None
    if 'privateKey' not in account:
      account['privateKey'] = 'defaultPassword'
    if 'accessKey' not in account:
      account['accessKey'] = None
    if 'awsRegion' not in account:
      account['awsRegion'] = None
    if 'azureTenant' not in account:
      account['azureTenant'] = None
    if 'cloudProvider' not in account:
      account['cloudProvider'] = None

    return account
