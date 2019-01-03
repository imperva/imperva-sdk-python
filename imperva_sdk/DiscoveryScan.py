# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class DiscoveryScan(MxObject):
  '''
  MX Discovery Scan Class
  '''

  # Store created Discovery Scan objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = DiscoveryScan._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj

  @staticmethod
  def _exists(connection=None, Name=None):
    for curr_obj in connection._instances:
      if type(curr_obj).__name__ == 'DiscoveryScan':
        if curr_obj.Name == Name:
          return curr_obj
    return None

  def __init__(self, connection=None, Name=None, ExistingSiteName=None, AutoAccept=None,
               ScanExistingServerGroups=None, ScanIpGroup=None, IpGroups=[], ScanCloudAccount=None,
               CloudAccounts=[], ServiceTypes=[], ResolveDns=None, ResolveVersions=None, EnhancedScanning=None,
               DiscoveryTimeout=None, GlobalPortConfiguration=None, ServerGroupNamingTemplate=None,
               ServiceNamingTemplate=None, CredentialsEnabled=None, OsCredentials=[], DbCredentials=[],
               Scheduling=None):

    super(DiscoveryScan, self).__init__(connection=connection, Name=Name)

    self._Name = Name
    self._ExistingSiteName = ExistingSiteName
    self._AutoAccept = AutoAccept
    self._ScanExistingServerGroups = ScanExistingServerGroups
    self._ScanIpGroup = ScanIpGroup
    self._IpGroups = IpGroups
    self._ScanCloudAccount = ScanCloudAccount
    self._CloudAccounts = CloudAccounts
    self._ServiceTypes = ServiceTypes
    self._ResolveDns = ResolveDns
    self._ResolveVersions = ResolveVersions
    self._EnhancedScanning = EnhancedScanning
    self._DiscoveryTimeout = DiscoveryTimeout
    self._GlobalPortConfiguration = GlobalPortConfiguration
    self._ServerGroupNamingTemplate = ServerGroupNamingTemplate
    self._ServiceNamingTemplate = ServiceNamingTemplate
    self._CredentialsEnabled = CredentialsEnabled
    self._OsCredentials = OsCredentials
    self._DbCredentials = DbCredentials
    self._Scheduling = Scheduling

  # Method: __iter__
  #-----------------------------------------------------------------------------------------------------
  # Description: Override the MxObject __iter__ function to print ApplyTo objects as dictionaries
  #-----------------------------------------------------------------------------------------------------
  #
  def __iter__(self):
    iters = {}
    for field in dir(self):
      if is_parameter.match(field):
        variable_function = getattr(self, field)
        iters[field] = variable_function
    for x, y in iters.items():
      yield x, y

  # Discovery Scan Parameter getters
  #-----------------------------------------------------------------------------------------------------
  # Description: properties for all scan parameters
  #-----------------------------------------------------------------------------------------------------
  #
  @property
  def Name(self):                  return self._Name
  @property
  def ExistingSiteName(self):      return self._ExistingSiteName
  @property
  def AutoAccept(self):            return self._AutoAccept
  @property
  def ScanExistingServerGroups(self):		return self._ScanExistingServerGroups
  @property
  def ScanIpGroup(self):           return self._ScanIpGroup
  @property
  def IpGroups(self):              return self._IpGroups
  @property
  def ScanCloudAccount(self):      return self._ScanCloudAccount
  @property
  def CloudAccounts(self):         return self._CloudAccounts
  @property
  def ServiceTypes(self):          return self._ServiceTypes
  @property
  def ResolveDns(self):            return self._ResolveDns
  @property
  def ResolveVersions(self):       return self._ResolveVersions
  @property
  def EnhancedScanning(self):      return self._EnhancedScanning
  @property
  def DiscoveryTimeout(self):      return self._DiscoveryTimeout
  @property
  def GlobalPortConfiguration(self):		return self._GlobalPortConfiguration
  @property
  def ServerGroupNamingTemplate(self):	return self._ServerGroupNamingTemplate
  @property
  def ServiceNamingTemplate(self):		return self._ServiceNamingTemplate
  @property
  def CredentialsEnabled(self):			return self._CredentialsEnabled
  @property
  def OsCredentials(self):				return self._OsCredentials
  @property
  def DbCredentials(self):				return self._DbCredentials
  @property
  def Scheduling(self):					return self._Scheduling

  #
  # Discovery Scan internal functions
  #
  @staticmethod
  def _get_all_discovery_scans(connection):
    discoveryScanNames = connection._mx_api('GET', '/conf/discovery/scans/')
    discoveryScans = []
    for discoveryScanName in discoveryScanNames:
      if '/' in discoveryScanName:
        continue
      try:
        discoveryScan = connection._mx_api('GET', '/conf/discovery/scans/' + discoveryScanName)
      except:
        raise MxException("Failed getting Discovery scan '%s'" % discoveryScanName)

      discoveryScan = DiscoveryScan.validateEmptyIndices(discoveryScan)
      discoveryScanObj = DiscoveryScan(connection=connection, Name=discoveryScan['name'], ExistingSiteName=discoveryScan['existing-site-name'],
                                       AutoAccept=discoveryScan['auto-accept'], ScanExistingServerGroups=discoveryScan['scan-existing-server-groups'],
                                       ScanIpGroup=discoveryScan['scan-ip-group'], IpGroups=discoveryScan['ip-groups'],
                                       ScanCloudAccount=discoveryScan['scan-cloud-account'], CloudAccounts=discoveryScan['cloud-accounts'],
                                       ServiceTypes=discoveryScan['service-types'], ResolveDns=discoveryScan['resolve-dns'],
                                       ResolveVersions=discoveryScan['resolve-versions'], EnhancedScanning=discoveryScan['enhanced-scanning'],
                                       DiscoveryTimeout=discoveryScan['discovery-timeout'], GlobalPortConfiguration=discoveryScan['global-port-configuration'],
                                       ServerGroupNamingTemplate=discoveryScan['server-group-naming-template'],
                                       ServiceNamingTemplate=discoveryScan['service-naming-template'], CredentialsEnabled=discoveryScan['credentials-enabled'],
                                       OsCredentials=discoveryScan['os-credentials'], DbCredentials=discoveryScan['db-credentials'],
                                       Scheduling=discoveryScan['scheduling'])
      discoveryScans.append(discoveryScanObj)
    return discoveryScans

  @staticmethod
  def _get_discovery_scan(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = DiscoveryScan._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      discoveryScan = connection._mx_api('GET', '/conf/discovery/scans/' + Name)
    except:
      return None

    discoveryScan = DiscoveryScan.validateEmptyIndices(discoveryScan)
    return DiscoveryScan(connection=connection, Name=discoveryScan['name'], ExistingSiteName=discoveryScan['existing-site-name'],
                         AutoAccept=discoveryScan['auto-accept'], ScanExistingServerGroups=discoveryScan['scan-existing-server-groups'],
                         ScanIpGroup=discoveryScan['scan-ip-group'], IpGroups=discoveryScan['ip-groups'],
                         ScanCloudAccount=discoveryScan['scan-cloud-account'], CloudAccounts=discoveryScan['cloud-accounts'],
                         ServiceTypes=discoveryScan['service-types'], ResolveDns=discoveryScan['resolve-dns'],
                         ResolveVersions=discoveryScan['resolve-versions'], EnhancedScanning=discoveryScan['enhanced-scanning'],
                         DiscoveryTimeout=discoveryScan['discovery-timeout'], GlobalPortConfiguration=discoveryScan['global-port-configuration'],
                         ServerGroupNamingTemplate=discoveryScan['server-group-naming-template'],
                         ServiceNamingTemplate=discoveryScan['service-naming-template'], CredentialsEnabled=discoveryScan['credentials-enabled'],
                         OsCredentials=discoveryScan['os-credentials'], DbCredentials=discoveryScan['db-credentials'],
                         Scheduling=discoveryScan['scheduling'])

  @staticmethod
  def _create_discovery_scan(connection,Name=None, ExistingSiteName=None, AutoAccept=None,
                             ScanExistingServerGroups=None, ScanIpGroup=None, IpGroups=[], ScanCloudAccount=None,
                             CloudAccounts=[], ServiceTypes=[], ResolveDns=None, ResolveVersions=None, EnhancedScanning=None,
                             DiscoveryTimeout=None, GlobalPortConfiguration=None, ServerGroupNamingTemplate=None,
                             ServiceNamingTemplate=None, CredentialsEnabled=None, OsCredentials=[], DbCredentials=[],
                             Scheduling=None, update=False):
    validate_string(Name=Name)
    body = {}
    body['name'] =Name
    body['existing-site-name'] = ExistingSiteName
    body['auto-accept'] = AutoAccept
    body['scan-existing-server-groups'] = ScanExistingServerGroups
    body['scan-ip-group'] = ScanIpGroup
    body['ip-groups'] = IpGroups
    body['scan-cloud-account'] = ScanCloudAccount
    body['cloud-accounts'] = CloudAccounts
    body['service-types'] = ServiceTypes
    body['resolve-dns'] = ResolveDns
    body['resolve-versions'] = ResolveVersions
    body['enhanced-scanning'] = EnhancedScanning
    body['discovery-timeout'] = DiscoveryTimeout
    body['global-port-configuration'] = GlobalPortConfiguration
    body['server-group-naming-template'] = ServerGroupNamingTemplate
    body['service-naming-template'] = ServiceNamingTemplate
    body['credentials-enabled'] = CredentialsEnabled
    body['os-credentials'] = OsCredentials
    body['db-credentials'] = DbCredentials
    body['scheduling'] = Scheduling

    try:
      connection._mx_api('POST', '/conf/discovery/scans/%s' % Name, data=json.dumps(body))
    except Exception as e:
      raise MxException("Failed creating Discovery scan: '%s'" % e)

    return DiscoveryScan(connection=connection, Name=Name, ExistingSiteName=ExistingSiteName, AutoAccept=AutoAccept,
                         ScanExistingServerGroups=ScanExistingServerGroups, ScanIpGroup=ScanIpGroup, IpGroups=IpGroups, ScanCloudAccount=ScanCloudAccount,
                         CloudAccounts=CloudAccounts, ServiceTypes=ServiceTypes, ResolveDns=ResolveDns, ResolveVersions=ResolveVersions,
                         EnhancedScanning=EnhancedScanning,DiscoveryTimeout=DiscoveryTimeout,
                         GlobalPortConfiguration=GlobalPortConfiguration, ServerGroupNamingTemplate=ServerGroupNamingTemplate,
                         ServiceNamingTemplate=ServiceNamingTemplate, CredentialsEnabled=CredentialsEnabled, OsCredentials=OsCredentials,
                         DbCredentials=DbCredentials, Scheduling=Scheduling)

  @staticmethod
  def _update_discovery_scan(connection, Name=None, ExistingSiteName=None, AutoAccept=None,
                             ScanExistingServerGroups=None, ScanIpGroup=None, IpGroups=[], ScanCloudAccount=None,
                             CloudAccounts=[], ServiceTypes=[], ResolveDns=None, ResolveVersions=None, EnhancedScanning=None,
                             DiscoveryTimeout=None, GlobalPortConfiguration=None, ServerGroupNamingTemplate=None,
                             ServiceNamingTemplate=None, CredentialsEnabled=None, OsCredentials=[], DbCredentials=[],
                             Scheduling=None):
    raise MxException("Discovery scan Update API currently not supported")

  @staticmethod
  def _delete_discovery_scan(connection, Name=None):
    raise MxException("Discovery scan API currently not supported")

  @staticmethod
  def validateEmptyIndices(discoveryScan):
    if type(discoveryScan) is not dict:
      return discoveryScan

    if 'name' not in discoveryScan:
      discoveryScan['name'] = None
    if 'existing-site-name' not in discoveryScan:
      discoveryScan['existing-site-name'] = None
    if 'auto-accept' not in discoveryScan:
      discoveryScan['auto-accept'] = None
    if 'scan-existing-server-groups' not in discoveryScan:
      discoveryScan['scan-existing-server-groups'] = None
    if 'scan-ip-group' not in discoveryScan:
      discoveryScan['scan-ip-group'] = None
    if 'ip-groups' not in discoveryScan:
      discoveryScan['ip-groups'] = []
    if 'scan-cloud-account' not in discoveryScan:
      discoveryScan['scan-cloud-account'] = None
    if 'cloud-accounts' not in discoveryScan:
      discoveryScan['cloud-accounts'] = []
    if 'service-types' not in discoveryScan:
      discoveryScan['service-types'] = []
    if 'resolve-dns' not in discoveryScan:
      discoveryScan['resolve-dns'] = None
    if 'resolve-versions' not in discoveryScan:
      discoveryScan['resolve-versions'] = None
    if 'enhanced-scanning' not in discoveryScan:
      discoveryScan['enhanced-scanning'] = None
    if 'discovery-timeout' not in discoveryScan:
      discoveryScan['discovery-timeout'] = None
    if 'global-port-configuration' not in discoveryScan:
      discoveryScan['global-port-configuration'] = None
    if 'server-group-naming-template' not in discoveryScan:
      discoveryScan['server-group-naming-template'] = None
    if 'service-naming-template' not in discoveryScan:
      discoveryScan['service-naming-template'] = None
    if 'credentials-enabled' not in discoveryScan:
      discoveryScan['credentials-enabled'] = None
    if 'os-credentials' not in discoveryScan:
      discoveryScan['os-credentials'] = []
    if 'db-credentials' not in discoveryScan:
      discoveryScan['db-credentials'] = []
    if 'scheduling' not in discoveryScan:
      discoveryScan['scheduling'] = None

    return discoveryScan
  