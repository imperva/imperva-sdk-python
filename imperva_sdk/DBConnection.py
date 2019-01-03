# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class DBConnection(MxObject):

    # Store created DB Audit Policy objects in _instances to prevent duplicate instances and redundant API calls
    def __new__(Type, *args, **kwargs):
        obj_exists = DBConnection._exists(connection=kwargs['connection'], Name=kwargs['Name'])
        if obj_exists:
            return obj_exists
        else:
            obj = super(MxObject, Type).__new__(Type)
            kwargs['connection']._instances.append(obj)
            return obj

    @staticmethod
    def _exists(connection=None, Name=None):
        for curr_obj in connection._instances:
            if type(curr_obj).__name__ == 'DBConnection':
                if curr_obj.Name == Name:
                    return curr_obj
        return None

    def __init__(self, connection=None, Name=None, SiteName=None, ServerGroupName = None, ServiceName = None,
        UserName = None, Password = None, Port = None, IpAddress = None, DbName = None,
        ServerName = None, UserMapping = None, ConnectionString = None, ServiceDirectory = None,
        TnsAdmin = None, HomeDirectory = None, Instance = None, HostName = None):

        super(DBConnection, self).__init__(connection=connection, Name=Name)
        self._Name = Name
        self._Site = SiteName
        self._ServerGroup = ServerGroupName
        self._ServiceName = ServiceName
        self._UserName = UserName
        self._Password = Password
        self._Port = Port
        self._IpAddress = IpAddress
        self._DbName = DbName
        self._ServerName = ServerName
        self._UserMapping = UserMapping
        self._ConnectionString = ConnectionString
        self._ServiceDirectory = ServiceDirectory
        self._TnsAdmin = TnsAdmin
        self._HomeDirectory = HomeDirectory
        self._Instance = Instance
        self._HostName = HostName

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

    # getters
    # -----------------------------------------------------------------------------------------------------
    # Description: properties for all parameters
    # -----------------------------------------------------------------------------------------------------
    #
    @property
    def Name(self):    return self._Name

    @property
    def UserName(self):    return self._UserName

    @property
    def Password(self):    return self._Password

    @property
    def Port(self):    return self._Port

    @property
    def IpAddress(self):    return self._IpAddress

    @property
    def DbName(self):    return self._DbName

    @property
    def ServerName(self):    return self._ServerName

    @property
    def UserMapping(self):    return self._UserMapping

    @property
    def ConnectionString(self):    return self._ConnectionString

    @property
    def ServiceDirectory(self):    return self._ServiceDirectory

    @property
    def TnsAdmin(self):    return self._TnsAdmin

    @property
    def HomeDirectory(self):    return self._HomeDirectory

    @property
    def Instance(self):    return self._Instance

    @property
    def HostName(self):    return self._HostName

    @staticmethod
    def _get_all_db_connections(Connection, SiteName=None, ServerGroupName=None, ServiceName=None):
        if SiteName is None or ServerGroupName is None or ServiceName is None:
            raise MxException("missing DB connection path")

        servicePath = SiteName + "/" + ServerGroupName + "/" + ServiceName + "/dbConnections/"

        try:
            dbConnectionDicts = Connection._mx_api('GET', '/conf/dbServices/%s' % servicePath)
        except:
            raise MxException("Failed getting db connections")
        dbConnectionObjects = []
        for dbConnectionDict in dbConnectionDicts['connections']:
            dbConnectionDict = DBConnection.checkDbConnectionEmptyKeys(dbConnectionDict)
            dbConnectionObj = DBConnection(connection=Connection, Name=dbConnectionDict['display-name'], SiteName=dbConnectionDict['site-name'],
                                            ServerGroupName=dbConnectionDict['server-group-name'], ServiceName=dbConnectionDict['service-name'],
                                            UserName=dbConnectionDict['user-name'], Password=dbConnectionDict['password'], Port=dbConnectionDict['port'],
                                            IpAddress = dbConnectionDict['ip-address'], DbName=dbConnectionDict['db-name'],
                                            ServerName=dbConnectionDict['server-name'], UserMapping=dbConnectionDict['user-mapping'],
                                            ConnectionString=dbConnectionDict['connection-string'], ServiceDirectory=dbConnectionDict['service-directory'],
                                            TnsAdmin=dbConnectionDict['tns-admin'], HomeDirectory=dbConnectionDict['home-directory'],
                                            Instance=dbConnectionDict['instance'], HostName=dbConnectionDict['host-name'])
            dbConnectionObjects.append(dbConnectionObj)
        return dbConnectionObjects


    @staticmethod
    def _get_db_connection(connection, SiteName=None, ServerGroupName=None, ServiceName=None, ConnectionName=None):
        if SiteName is None or ServerGroupName is None or ServiceName is None or ConnectionName is None:
            raise MxException("missing DB connection path")

        fullPath = SiteName + "/" + ServerGroupName + "/" + ServiceName + "/dbConnections/" + ConnectionName

        try:
            dbConnection = connection._mx_api('GET', '/conf/dbServices/%s' % fullPath)
        except:
            raise MxException("Failed getting DB connection")

        dbConnection = DBConnection.checkDbConnectionEmptyKeys(dbConnection)

        return DBConnection(connection=connection,Name=dbConnection['display-name'], SiteName=dbConnection['site-name'], ServerGroupName=dbConnection['server-group-name'],
                            ServiceName=dbConnection['service-name'], UserName=dbConnection['user-name'], Password=dbConnection['password'],
                            Port=dbConnection['port'], IpAddress = dbConnection['ip-address'], DbName=dbConnection['db-name'],
                            ServerName=dbConnection['server-name'], UserMapping=dbConnection['user-mapping'], ConnectionString=dbConnection['connection-string'],
                            ServiceDirectory=dbConnection['service-directory'],TnsAdmin=dbConnection['tns-admin'], HomeDirectory=dbConnection['home-directory'],
                            Instance=dbConnection['instance'], HostName=dbConnection['host-name'])

    @staticmethod
    def _create_db_connection(connection, SiteName=None, ServerGroupName=None, ServiceName=None, ConnectionName=None,
                              UserName=None, Password=None, Port=None, IpAddress=None, DbName=None,
                              ServerName=None, UserMapping=None, ConnectionString=None, ServiceDirectory=None,
                              TnsAdmin=None, HomeDirectory=None, Instance=None, HostName=None, update=False):
        if SiteName is None or ServerGroupName is None or ServiceName is None or ConnectionName is None:
            raise MxException("missing DB connection path")

        fullPath = SiteName + "/" + ServerGroupName + "/" + ServiceName + "/dbConnections/" + ConnectionName

        body = {}
        body['display-name'] = ConnectionName;
        body['site-name'] = SiteName;
        body['server-group-name'] = ServerGroupName;
        body['service-name'] = ServiceName;
        body['user-name'] = UserName;
        body['password'] = Password;
        body['port'] = Port;
        body['db-name'] = DbName;
        body['server-name'] = ServerName;
        body['ip-address'] = IpAddress;
        body['user-mapping'] = UserMapping;
        body['connection-string'] = ConnectionString;
        body['service-directory'] = ServiceDirectory;
        body['tns-admin'] = TnsAdmin;
        body['home-directory'] = HomeDirectory;
        body['instance'] = Instance;
        body['host-name'] = HostName;

        try:
            connection._mx_api('POST', '/conf/dbServices/%s' % fullPath, data=json.dumps(body))
        except Exception as e:
            raise MxException("Failed creating DB connection - " + str(e))

        return DBConnection(connection=connection, Name=ConnectionName, SiteName=SiteName, ServerGroupName=ServerGroupName, ServiceName=ServiceName,
                            UserName=UserName, Password=Password, Port=Port, IpAddress=IpAddress,
                            DbName=DbName, ServerName=ServerName, UserMapping=UserMapping, ConnectionString=ConnectionString,
                            ServiceDirectory=ServiceDirectory, TnsAdmin=TnsAdmin, HomeDirectory=HomeDirectory, Instance=Instance,
                            HostName=HostName)

    @staticmethod
    def _update_db_connection(connection, SiteName=None, ServerGroupName=None, ServiceName=None, ConnectionName=None,
                              UserName=None, Password=None, Port=None, IpAddress=None, DbName=None,
                              ServerName=None, UserMapping=None, ConnectionString=None, ServiceDirectory=None,
                              TnsAdmin=None, HomeDirectory=None, Instance=None, HostName=None):
        if SiteName is None or ServerGroupName is None or ServiceName is None or ConnectionName is None:
            raise MxException("missing DB connection path")

        fullPath = SiteName + "/" + ServerGroupName + "/" + ServiceName + "/dbConnections/" + ConnectionName

        try:
            dbConnection = connection._mx_api('GET', '/conf/dbServices/%s' % fullPath)
        except:
            raise MxException("Failed creating DB connection")

        body = {}
        if ConnectionName is not None:
            body['display-name'] = ConnectionName

        if SiteName is not None:
            body['site-name'] = SiteName

        if ServerGroupName is not None:
            body['server-group-name'] = ServerGroupName

        if ServiceName is not None:
            body['service-name'] = ServiceName

        if UserName is not None:
            body['user-name'] = UserName

        if Password is not None:
            body['password'] = Password

        if Port is not None:
            body['port'] = Port

        if DbName is not None:
            body['db-name'] = DbName

        if ServerName is not None:
            body['server-name'] = ServerName

        if IpAddress is not None:
            body['ip-address'] = IpAddress

        if UserMapping is not None:
            body['user-mapping'] = UserMapping

        if ConnectionString is not None:
            body['connection-string'] = ConnectionString

        if ServiceDirectory is not None:
            body['service-directory'] = ServiceDirectory

        if TnsAdmin is not None:
            body['tns-admin'] = TnsAdmin

        if HomeDirectory is not None:
            body['home-directory'] = HomeDirectory

        if Instance is not None:
            body['instance'] = Instance

        if HostName is not None:
            body['host-name'] = HostName

        try:
            connection._mx_api('PUT', '/conf/dbServices/%s' % fullPath, data=json.dumps(body))
        except:
            raise MxException("Failed updating DB connection")

        try:
            dbConnection = connection._mx_api('GET', '/conf/dbServices/%s' % fullPath)
        except:
            raise MxException("Failed getting DB connection")

        dbConnection = DBConnection.checkDbConnectionEmptyKeys(dbConnection)

        return DBConnection(connection=connection,Name=dbConnection['display-name'], SiteName=dbConnection['site-name'], ServerGroupName=dbConnection['server-group-name'],
                            ServiceName=dbConnection['service-name'], UserName=dbConnection['user-name'], Password=dbConnection['password'],
                            Port=dbConnection['port'], IpAddress = dbConnection['ip-address'], DbName=dbConnection['db-name'],
                            ServerName=dbConnection['server-name'], UserMapping=dbConnection['user-mapping'], ConnectionString=dbConnection['connection-string'],
                            ServiceDirectory=dbConnection['service-directory'],TnsAdmin=dbConnection['tns-admin'], HomeDirectory=dbConnection['home-directory'],
                            Instance=dbConnection['instance'], HostName=dbConnection['host-name'])

    @staticmethod
    def checkDbConnectionEmptyKeys(dbConnection):
        if type(dbConnection) is not dict:
            return dbConnection

        if 'display-name' not in dbConnection:
            dbConnection['display-name'] = None
        if 'site-name' not in dbConnection:
            dbConnection['site-name'] = None
        if 'server-group-name' not in dbConnection:
            dbConnection['server-group-name'] = None
        if 'server-group-name' not in dbConnection:
            dbConnection['server-group-name'] = None
        if 'service-name' not in dbConnection:
            dbConnection['service-name'] = None
        if 'user-name' not in dbConnection:
            dbConnection['user-name'] = None
        if 'password' not in dbConnection:
            dbConnection['password'] = 'changeMe'
        if 'port' not in dbConnection:
            dbConnection['port'] = None
        if 'ip-address' not in dbConnection:
            dbConnection['ip-address'] = None
        if 'port' not in dbConnection:
            dbConnection['port'] = None
        if 'ip-address' not in dbConnection:
            dbConnection['ip-address'] = None
        if 'db-name' not in dbConnection:
            dbConnection['db-name'] = None
        if 'server-name' not in dbConnection:
            dbConnection['server-name'] = None
        if 'user-mapping' not in dbConnection:
            dbConnection['user-mapping'] = None
        if 'connection-string' not in dbConnection:
            dbConnection['connection-string'] = None
        if 'service-directory' not in dbConnection:
            dbConnection['service-directory'] = None
        if 'tns-admin' not in dbConnection:
            dbConnection['tns-admin'] = None
        if 'home-directory' not in dbConnection:
            dbConnection['home-directory'] = None
        if 'instance' not in dbConnection:
            dbConnection['instance'] = None
        if 'host-name' not in dbConnection:
            dbConnection['host-name'] = None
        return dbConnection

    @staticmethod
    def _delete_db_connection(connection, site=None, serverGroup=None, serviceName=None, connectionName=None):
        raise MxException("DB Connection Delete API currently not supported")