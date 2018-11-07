# Copyright 2018 Imperva. All rights reserved.

import json
import copy
from imperva_sdk.core import *

class DbService(MxObject):
  ''' 
  MX DB Service Class 

  >>> ws = sg.create_db_service("DB service name")
  >>> {
  >>>  'text-replacement': [],
  >>>  'db-mappings': [],
  >>>  'name': 'Ora121dv',
  >>>  'db-service-type': 'Oracle',
  >>>  'ports': [],
  >>>  'default-application': 'Default Oracle Application'
  >>> }
  >>>
  '''
  
  # Store created DB service objects in _instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = DbService._exists(connection=kwargs['connection'], Site=kwargs['Site'], ServerGroup=kwargs['ServerGroup'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj

  @staticmethod
  def _exists(connection=None, Site=None, ServerGroup=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'DbService':
        if cur_obj.Name == Name and cur_obj._ServerGroup == ServerGroup and cur_obj._Site == Site:
          return cur_obj
    return None

  def __init__(self, connection=None, Name=None, ServerGroup=None, Site=None, Ports=[], DefaultApp=None, DbMappings=[], TextReplacement=[], LogCollectors=[], DbConnections=[], DbServiceType=None):
    super(DbService, self).__init__(connection=connection, Name=Name)
    validate_string(Site=Site, ServerGroup=ServerGroup)
    self._Site = Site
    self._ServerGroup = ServerGroup
    self._Ports = Ports
    self._DbServiceType = DbServiceType
    self._LogCollectors = LogCollectors
    self._DbConnections = DbConnections
    self._DefaultApp = DefaultApp
    self._DbMappings = DbMappings
    self._TextReplacement = TextReplacement

  #
  # DB Service Parameters
  #
  @property
  def Name(self):
    ''' DB Service Name (string) '''
    return self._Name

  @property
  def Ports(self):
    ''' DB Service Ports (list of int). Edit not implemented. '''
    return self._Ports

  @property
  def DbServiceType(self):
    ''' DB Service Type (e.g. Oracle, MySQL)'''
    return self._DbServiceType

  @property
  def LogCollectors(self):
    return self._LogCollectors

  @property
  def DbConnections(self):
    return self._DbConnections

  @property
  def DefaultApp(self):
    return self._DefaultApp

  @property
  def DbMappings(self):
    return self._DbMappings

  @property
  def TextReplacement(self):
    return self._TextReplacement

  @Name.setter
  def Name(self, Name):
    validate_string(Name=Name)
    body = json.dumps({'name': Name})
    self._connection._mx_api('PUT', '/conf/dbServices/%s/%s/%s' % (self._Site, self._ServerGroup, self._Name), data=body)
    self._Name = Name

  #    
  # DB Service internal functions
  #
  @staticmethod  
  def _get_all_db_services(connection, ServerGroup=None, Site=None):
    validate_string(Site=Site, ServerGroup=ServerGroup)
    res = connection._mx_api('GET', '/conf/dbServices/%s/%s' % (Site, ServerGroup))
    try:
      names = res['db-services']
    except:
      raise MxException("Failed getting DB services")
    dbss = []
    for name in names:
      dbss.append(connection.get_db_service(Name=name, Site=Site, ServerGroup=ServerGroup))
    return dbss

  @staticmethod
  def _get_db_service(connection, Name=None, ServerGroup=None, Site=None):
    validate_string(Name=Name, ServerGroup=ServerGroup, Site=Site)
    obj_exists = DbService._exists(connection=connection, Name=Name, ServerGroup=ServerGroup, Site=Site)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/dbServices/%s/%s/%s' % (Site, ServerGroup, Name))
    except:
      return None

    if 'name' in res:
      DbServiceType = None
      if 'db-service-type' in res: DbServiceType = res['db-service-type']
      DefaultApp = None
      if 'default-application' in res: DefaultApp = res['default-application']
      Ports = []
      if 'ports' in res: Ports = res['ports']
      DbMappings = []
      if 'db-mappings' in res: DbMappings = res['db-mappings']
      TextReplacement = []
      if 'text-replacement' in res: TextReplacement = res['text-replacement']
      # Get DB service Log Collectors and DB Connections
      LogCollectors = connection._mx_api('GET', '/conf/dbServices/%s/%s/%s/logCollectors' % (Site, ServerGroup, Name))
      LogCollectors = LogCollectors['connectors']
      DbConnections = connection._mx_api('GET', '/conf/dbServices/%s/%s/%s/dbConnections' % (Site, ServerGroup, Name))
      DbConnections = DbConnections['connections']

      # Do not get all security policies and audit policies attached to this service - they will be handled by the policies
      # sps = connection._mx_api('GET', '/conf/dbServices/%s/%s/%s/dbSecurityPolicies' % (Site, ServerGroup, Name))
      # SecurityPolicies = [p['policy-name'] for p in sps['db-security-policies']]
      # aps = connection._mx_api('GET', '/conf/dbServices/%s/%s/%s/auditPolicies' % (Site, ServerGroup, Name))
      # AuditPolicies = [p['policy-name'] for p in aps['audit-policies']]

      return DbService(
          connection=connection, Name=Name, ServerGroup=ServerGroup, Site=Site, Ports=Ports, 
          DefaultApp=DefaultApp, DbMappings=DbMappings, TextReplacement=TextReplacement,
          LogCollectors=LogCollectors, DbConnections=DbConnections,
          DbServiceType=DbServiceType)
    else:
      return None

  @staticmethod    
  def _create_db_service(connection, Name=None, ServerGroup=None, Site=None, Ports=[], DefaultApp=None, DbMappings=[], TextReplacement=[], LogCollectors=[], DbConnections=[], DbServiceType=None, update=False):
    validate_string(Name=Name, Site=Site, ServerGroup=ServerGroup)
    dbs = connection.get_db_service(Name=Name, Site=Site, ServerGroup=ServerGroup)
    if dbs:
      if update:
        if Ports:
          pass
        if LogCollectors:
          pass
        if DbConnections:
          pass
        if DefaultApp:
          pass
        if DbMappings:
          pass
        if TextReplacement:
          pass
        return dbs
      else:
        raise MxException("DB Service already exists")
    #---------------------------------------------------------------------------
    # Problem: the CREATE function only accepts the service type and ports.
    #   So for the time being, we need two calls: one POST to create the service
    #   and one PUT to update it with the rest of the parameters.
    body = {}
    if DbServiceType: body['db-service-type'] = DbServiceType
    if Ports: body['ports'] = Ports
    connection._mx_api('POST', '/conf/dbServices/%s/%s/%s' % (Site, ServerGroup, Name), data=json.dumps(body))
    if DefaultApp: body['default-application'] = DefaultApp

    # Unfortunately, this cannot be done now - if we create a service, then the DB Applications do not yet
    # exist and so we must defer the creation to a later function, see _create_db_service_pc below
    # if DbMappings: body['db-mappings'] = DbMappings

    if TextReplacement: body['text-replacement'] = TextReplacement
    # Must remove the database service type for this to succeed
    if 'db-service-type' in body: del body['db-service-type']
    connection._mx_api('PUT', '/conf/dbServices/%s/%s/%s' % (Site, ServerGroup, Name), data=json.dumps(body))

    # store the log collectors
    for logColl in LogCollectors:
      # Add dummy passwords:
      if 'user-name' in logColl:
        logColl['password'] = 'ChangeMe'
      if 'access-key' in logColl:
        logColl['secret-key'] = 'ChangeMe'
      connection._mx_api('POST', '/conf/dbServices/%s/%s/%s/logCollectors' % (Site, ServerGroup, Name), data=json.dumps(logColl))

    # Store the DB Connections
    for dbC in DbConnections:
      # We need the display name in the URL and not in the JSON body, so we use a copy
      dbConn = copy.deepcopy(dbC)
      # Take the name for the URL
      connName = dbConn['display-name']
      # And remove it from the JSON
      del dbConn['display-name']
      # Add dummy password:
      if 'user-name' in dbConn:
        dbConn['password'] = 'ChangeMe'
      connection._mx_api('POST', '/conf/dbServices/%s/%s/%s/dbConnections/%s' % (Site, ServerGroup, Name, connName), data=json.dumps(dbConn))

    return DbService(connection=connection, Name=Name, ServerGroup=ServerGroup, Site=Site, Ports=Ports, LogCollectors=LogCollectors, DbConnections=DbConnections, DbServiceType=DbServiceType)

  # Function: _create_db_service_pc
  #-----------------------------------------------------------------------------
  # Purpose: update a DB service after its children were created.
  # Here, we may assume that the service already exists because it was created
  # during the call to the function above this one - _create_db_service, and now
  # all we need to do is update the DB Mappings item.
  #-----------------------------------------------------------------------------

  @staticmethod
  def _create_db_service_pc(connection, Name=None, ServerGroup=None, Site=None, Ports=[], DefaultApp=None, DbMappings=[], TextReplacement=[], LogCollectors=[], DbConnections=[], DbServiceType=None, update=False):
    validate_string(Name=Name, Site=Site, ServerGroup=ServerGroup)
    if DbMappings:
      body = {}
      body['db-mappings'] = DbMappings
      connection._mx_api('PUT', '/conf/dbServices/%s/%s/%s' % (Site, ServerGroup, Name), data=json.dumps(body))
    return DbService(connection=connection, Name=Name, ServerGroup=ServerGroup, Site=Site, Ports=Ports, LogCollectors=LogCollectors, DbConnections=DbConnections, DbServiceType=DbServiceType)

  @staticmethod
  def _delete_db_service(connection, Name=None, ServerGroup=None, Site=None):
    validate_string(Name=Name, ServerGroup=ServerGroup, Site=Site)
    dbs = connection.get_db_service(Name=Name, Site=Site, ServerGroup=ServerGroup)
    if dbs:
      connection._mx_api('DELETE', '/conf/dbServices/%s/%s/%s' % (Site, ServerGroup, Name))
      connection._instances.remove(dbs)
      del dbs
    else:
      raise MxException("DB Service '%s' does not exist" % Name)
    return True

  #
  # DB Service child functions
  #
  def get_db_application(self, Name=None):
    return self._connection.get_db_application(DbService=self.Name, Site=self._Site, ServerGroup=self._ServerGroup, Name=Name)
  def get_all_db_applications(self):
    return self._connection.get_all_db_applications(Site=self._Site, ServerGroup=self._ServerGroup, DbService=self.Name)
  def create_db_application(self, Name=None, TableGroupValues=None, update=False):
    return self._connection.create_db_application(DbService=self.Name, Site=self._Site, ServerGroup=self._ServerGroup, Name=Name, TableGroupValues=TableGroupValues, update=update)
  def delete_db_application(self, Name=None):
    return self._connection.delete_db_application(DbService=self.Name, Site=self._Site, ServerGroup=self._ServerGroup, Name=Name)


  #
  # DB connection child functions
  #
  def get_db_connection(self, Name=None):
    return self._connection.get_db_connection(ServiceName=self.Name, SiteName=self._Site, ServerGroupName=self._ServerGroup, Name=Name)

  def get_all_db_connections(self):
    return self._connection.get_all_db_connections(SiteName=self._Site, ServerGroupName=self._ServerGroup, ServiceName=self.Name)

  def create_db_connection(self, ConnectionName=None, UserName=None, Password=None, Port=None, IpAddress=None, DbName=None,
                              ServerName=None, UserMapping=None, ConnectionString=None, ServiceDirectory=None,
                              TnsAdmin=None, HomeDirectory=None, Instance=None, HostName=None, update=False):
    return self._connection.create_db_connection(ServiceName=self.Name, SiteName=self._Site, ServerGroupName=self._ServerGroup,
                                                 ConnectionName=ConnectionName, UserName=UserName, Password=Password,
                                                 Port=Port, IpAddress=IpAddress, DbName=DbName, ServerName=ServerName,
                                                 UserMapping=UserMapping, ConnectionString=ConnectionString,
                                                 ServiceDirectory=ServiceDirectory, TnsAdmin=TnsAdmin,
                                                 HomeDirectory=HomeDirectory, Instance=Instance, HostName=HostName, update=update)

  def delete_db_connection(self, Name=None):
    return self._connection.delete_db_connection(ServiceName=self.Name, SiteName=self._Site, ServerGroupName=self._ServerGroup, Name=Name)



