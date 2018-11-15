# Copyright 2018 Imperva. All rights reserved.

import json
import base64
import requests
import time

from imperva_sdk.core                           import *
from imperva_sdk.Site                           import *
from imperva_sdk.ServerGroup                    import *
from imperva_sdk.WebService                     import *
from imperva_sdk.WebApplication                 import *
from imperva_sdk.DbService                      import *
from imperva_sdk.DbApplication                  import *
from imperva_sdk.KrpRule                        import *
from imperva_sdk.TrpRule                        import *
from imperva_sdk.ActionSet                      import *
from imperva_sdk.Action                         import *
from imperva_sdk.WebServiceCustomPolicy         import *
from imperva_sdk.WebApplicationCustomPolicy     import *
from imperva_sdk.WebProfilePolicy               import *
from imperva_sdk.HttpProtocolSignaturesPolicy   import *
from imperva_sdk.ParameterTypeGlobalObject      import *
from imperva_sdk.ADCUploader                    import *
from imperva_sdk.DbAuditPolicy                  import *
from imperva_sdk.AgentMonitoringRule            import *
from imperva_sdk.DataEnrichmentPolicy           import *
from imperva_sdk.DBAuditReport                  import *
from imperva_sdk.AssessmentScan                 import *
from imperva_sdk.LookupDataSet                  import *
from imperva_sdk.DataType                       import *
from imperva_sdk.DBConnection                   import *
from imperva_sdk.TableGroup                     import *
from imperva_sdk.AssessmentPolicy               import *
from imperva_sdk.AssessmentTest                 import *
from imperva_sdk.DbSecurityPolicy               import *
from imperva_sdk.ClassificationScan             import *
from imperva_sdk.ClassificationProfile          import *
from imperva_sdk.AgentConfiguration             import *
from imperva_sdk.Tag                            import *
from imperva_sdk.DiscoveryScan					        import *
from imperva_sdk.CloudAccount					          import *
from imperva_sdk.IpGroup    					          import *

ApiVersion = "v1"
DefaultMxPort = 8083
DefaultMxUsername = "admin"
DefaultMxPassword = "password"
ConnectionTimeout = 300

#
# Disable requests library SSL warnings (self signed certificate)
#
try:
  from requests.packages.urllib3.exceptions import InsecureRequestWarning
  requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
  pass
try:
  from requests.packages.urllib3.exceptions import InsecurePlatformWarning
  requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
except:
  pass
try:
  from requests.packages.urllib3.exceptions import SNIMissingWarning
  requests.packages.urllib3.disable_warnings(SNIMissingWarning)
except:
  pass
try:
  import urllib3
  urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
  pass


class MxConnection(object):
  ''' 
  Opens a connection (session) handler to the SecureSphere MX.
  This is your starting point for using imperva_sdk.

    >>> import imperva_sdk
    >>> mx = imperva_sdk.MxConnection(Host="192.168.0.1", Username="admin", Password="password")

  :type Host: string
  :param Host: MX server IP Address or Host name
  :type Port: int
  :param Port: MX server port number (default=8083)
  :type Username: string
  :param Username: MX server UI user name (default='admin')
  :type Password: string
  :param Password: MX server UI user password (default='password')
  :type FirstTime: boolean
  :param FirstTime: Set to True if 'admin' password is not set (First Time Password). Not available on physical appliances. (default=False)
  :type Unlicensed: boolean
  :param Unlicensed: Set to True if the MX did not apply a license yet (default=False)
  :type Debug: boolean
  :param Debug: Print API HTTP debug information (default=False)
  :rtype: imperva_sdk.MxConnection
  :return: MX connection instance

  .. note:: All of the MX objects that are retrieved using the API are stored in the context of the MxConnection instance to prevent redundant API calls.
  '''

  def __init__(self, Host=None, Port=DefaultMxPort, Username=DefaultMxUsername, Password=DefaultMxPassword, FirstTime=False, Unlicensed=False, Debug=False):
    # 
    # We store all of the MX objects in '_instances' to prevent duplicate objects and redundant API calls.
    # Because the ID of the object is inconsistent (e.g. can have the same server group names under different sites),
    # we override the __new__ function in each child class.
    #
    self._instances = []

    #
    # Authenticate to MX and save session cookie
    #
    self.Host = Host
    self.__Port = Port
    self.__Debug = Debug
    self.__IsAuthenticated = False
    auth_string = '%s:%s' % (Username, Password)
    self.__Headers = {
      "Authorization": 'Basic %s' % base64.b64encode(auth_string.encode('utf-8')).decode('utf-8'),
      "Content-Type": "application/json"
    }
    # If first time we set the password and create a new login
    if FirstTime:
      auth_url = '/administration/user/password/firsttime'
      try:
        response = self._mx_api('POST', auth_url)
      except:
        # Bypass some API problems with first time password
        pass
    auth_url = '/auth/session'
    response = self._mx_api('POST', auth_url)
    if not response:
      raise MxException("Failed connecting to MX")
    try:
      self.__Headers['Cookie'] = response['session-id']
    except:
      try:
        self.__Headers['Cookie'] = response['sessionId']
      except:
        raise MxException("Failed authenticating to MX")
    del self.__Headers['Authorization']
    if Unlicensed:
      self.__Version = "Unknown"
      self.__Challenge = "Unknown"
    else:
      try:
        response = self._mx_api('GET', '/administration/version')
        self.__Version = response['serverVersion']
      except:
        self.__Version = "Unknown"
      try:
        response = self._mx_api('GET', '/administration/challenge')
        self.__Challenge = response['challenge']
      except:
        self.__Challenge = "Unknown"
    self.__IsAuthenticated = True


  def Debug(self, value):
    self.__Debug = value

  #
  # MX Connection Parameters
  #  
  @property
  def Version(self):
    ''' 
    MX SecureSphere Version (read only) 

    >>> mx.Version
    u'12.0.0.41'
    '''
    return self.__Version
  @property
  def Challenge(self):
    ''' MX Challenge that was generated for the appliance (read only) '''
    return self.__Challenge
  @property
  def IsAuthenticated(self):
    ''' MX connection authentication status (read only) '''
    return self.__IsAuthenticated

  def logout(self):
    ''' Close connection to MX '''
    if self.IsAuthenticated:
      try:
        self._mx_api('DELETE', '/auth/session')
      except:
        pass
    self.__IsAuthenticated = False
    for mx_object in self._instances:
      del mx_object
    self._instances = []

  def __del__(self):
    self.logout()

  def _mx_api(self, method, path, **kwargs):
    if "headers" not in kwargs: kwargs["headers"] = self.__Headers
    if "timeout" not in kwargs: kwargs["timeout"] = ConnectionTimeout
    if "verify" not in kwargs: kwargs["verify"] = False
    if "Prefix" in kwargs:
      prefix = kwargs["Prefix"]
      del kwargs["Prefix"]
    else:
      prefix = "/SecureSphere/api"
    if "ApiVersion" in kwargs:
      api_version = kwargs["ApiVersion"]
      del kwargs["ApiVersion"]
    else:
      api_version = ApiVersion

    url = "https://%s:%d%s/%s%s" % (self.Host, self.__Port, prefix, api_version, path)
    
    if self.__Debug:
      print ("%s %s" % (method, url))
      for header in kwargs["headers"]:
        print ("  header - %s: %s" % (header, kwargs["headers"][header]))
      if "data" in kwargs:
        print ("  body - %s" % kwargs["data"])

    if method == 'POST':
      try:
        response = requests.post(url, **kwargs)
      except Exception as e:
        raise MxException("MX Connection Error - %s" % str(e))
    elif method == 'GET':
      try:
        response = requests.get(url, **kwargs)
      except:
        raise MxException("MX Connection Error")
    elif method == 'DELETE':
      try:
        response = requests.delete(url, **kwargs)
      except:
        raise MxException("MX Connection Error")
    elif method == 'PUT':
      try:
        response = requests.put(url, **kwargs)
      except:
        raise MxException("MX Connection Error")
    else:
      raise MxException("Unhandled HTTP method '%s'" % method)
    if response.status_code == 200:
      try:
        return json.loads(response.text)
      except:
        return None
    elif response.status_code == 404:
      raise MxExceptionNotFound("404 - API URL not found")
    else:
      error_message = "Unknown Error (response code = %d)" % response.status_code
      try:
        response_json = json.loads(response.text)
        error_message = response_json['errors']
      except:
        pass
      raise MxException("MX returned errors - %s" % str(error_message))
	
  def get_all_sites(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.Site.Site`
    :return: List of all sites in MX
    '''
    return Site._get_all_sites(connection=self)

  def get_site(self, Name=None):
    '''
    :type Name: string
    :param Name: Site name
    :rtype: imperva_sdk.Site.Site
    :return: Site instance of site with specified name. (:obj:`None` if site does not exist)
    '''
    return Site._get_site(connection=self, Name=Name)

  def create_site(self, Name=None, update=False):
    '''
    :type Name: string
    :param Name: Site name
    :type update: boolean
    :param update: If `update=True` and the resource already exists, update and return the existing resource. If `update=False` (default) and the resource exists, an exception will be raised.
    :rtype: imperva_sdk.Site.Site
    :return: Site instance of site with specified name.
    '''
    return Site._create_site(connection=self, Name=Name, update=update)

  def delete_site(self, Name=None):
    '''
    Deletes the entire site, including all resources under that site.

    If site does not exist, an exception will be raised.

    :type Name: string
    :param Name: Site name
    '''
    return Site._delete_site(connection=self, Name=Name)

  def get_all_server_groups(self, Site=None):
    '''
    :type Site: string
    :param Site: Site name
    :rtype: `list` of :obj:`imperva_sdk.Servergroup.ServerGroup`
    :return: List of all server groups in MX under a given site
    '''
    return ServerGroup._get_all_server_groups(connection=self, Site=Site)

  def get_server_group(self, Name=None, Site=None):
    '''
    :type Name: string
    :param Name: Server Group name
    :type Site: string
    :param Site: Site name
    :rtype: imperva_sdk.Servergroup.ServerGroup
    :return: ServerGroup instance of server group with specified name and site. (:obj:`None` if server group does not exist)
    '''
    return ServerGroup._get_server_group(connection=self, Name=Name, Site=Site)
      
  def create_server_group(self, Name=None, Site=None, OperationMode=None, ProtectedIps=[], ServerIps=[], update=False):
    '''
    :type Name: string
    :param Name: Server group name
    :type Site: string
    :param Site: Site name
    :type OperationMode: 'active', 'simulation' or 'disabled'
    :param OperationMode: See :py:attr:`imperva_sdk.Servergroup.ServerGroup.OperationMode`
    :param ProtectedIps: See :py:attr:`imperva_sdk.Servergroup.ServerGroup.ProtectedIps`
    :param ServerIps: IPs String list`
    :type update: boolean
    :param update: If `update=True` and the resource already exists, update and return the existing resource. If `update=False` (default) and the resource exists, an exception will be raised.
    :rtype: imperva_sdk.Servergroup.ServerGroup
    :return: Created ServerGroup instance.
    '''
    return ServerGroup._create_server_group(connection=self, Name=Name, Site=Site, OperationMode=OperationMode, ProtectedIps=ProtectedIps, ServerIps=ServerIps, update=update)

  def delete_server_group(self, Name=None, Site=None):
    '''
    Deletes the server group, including all resources under it.

    If server group does not exist, an exception will be raised.

    :type Name: string
    :param Name: Server group name
    :type Site: string
    :param Site: Site name
    '''
    return ServerGroup._delete_server_group(connection=self, Name=Name, Site=Site)

  def get_all_web_services(self, ServerGroup=None, Site=None):
    '''
    :type ServerGroup: string
    :param ServerGroup: Server group name
    :type Site: string
    :param Site: Site name
    :rtype: `list` of :obj:`imperva_sdk.WebService.WebService`
    :return: List of all web services in MX under a given site and server group
    '''
    return WebService._get_all_web_services(connection=self, ServerGroup=ServerGroup, Site=Site)

  def get_web_service(self, Name=None, ServerGroup=None, Site=None):
    '''
    :type Name: string
    :param Name: Web Service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    :rtype: imperva_sdk.WebService.WebService
    :return: WebService instance of web service with specified name, server group and site. (:obj:`None` if web service does not exist)
    '''
    return WebService._get_web_service(connection=self, Name=Name, ServerGroup=ServerGroup, Site=Site)
    
  def create_web_service(self, Name=None, ServerGroup=None, Site=None, Ports=[], SslPorts=[], ForwardedConnections={}, ForwardedClientIp={}, SslKeys=[], TrpMode=None, update=False):
    '''
    Creates a web (HTTP) service under specified server group and site.

    .. note:: The WebService object contains additional attributes that are not part of the webService API like SSL Certficates and Forwarded Connections.

    >>> # Create Web Service with default options
    >>> ws1 = mx.create_web_service(Name="simple web service", ServerGroup="server group name", Site="site name")
    >>>
    >>> # Create Web Service with XFF enabled and an SSL Certificate
    >>> with open('/tmp/mycert.pem', 'r') as fd:
    >>>   key_data = fd.read()
    >>> ws2 = mx.create_web_service(Name="advanced web service", ServerGroup="server group name", Site="site name", Ports=[8080], SslPorts=[8443], ForwardedConnections={"useHttpForwardingHeader": True, "forwardedConnections": [{"headerName": "X-Forwarded-For", "proxyIpGroup": ""}]}, ForwardedClientIp={"forwardHeaderName": "X-Forwarded-For", "forwardClientIP": True}, SslKeys=[{"certificate": key_data, "format": "pem", "private": key_data, "hsm": False, "sslKeyName": "key name", "password": ""}])

    :type Name: string
    :param Name: Web Service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    :param Ports: See :py:attr:`imperva_sdk.WebService.WebService.Ports`
    :param SslPorts: See :py:attr:`imperva_sdk.WebService.WebService.SslPorts`
    :param ForwardedConnections: See :py:attr:`imperva_sdk.WebService.WebService.ForwardedConnections`
    :param ForwardedClientIp: See :py:attr:`imperva_sdk.WebService.WebService.ForwardedClientIp`
    :param SslKeys: See :py:attr:`imperva_sdk.WebService.WebService.SslKeys`
    :param TrpMode: See :py:attr:`imperva_sdk.WebService.WebService.TrpMode`
    :type update: boolean
    :param update: If `update=True` and the resource already exists, update and return the existing resource. If `update=False` (default) and the resource exists, an exception will be raised.
    :rtype: imperva_sdk.WebService.WebService
    :return: Created WebService instance.

    '''
    return WebService._create_web_service(connection=self, Name=Name, ServerGroup=ServerGroup, Site=Site, Ports=Ports, SslPorts=SslPorts, ForwardedConnections=ForwardedConnections, ForwardedClientIp=ForwardedClientIp, SslKeys=SslKeys, TrpMode=TrpMode, update=update)

  def delete_web_service(self, Name=None, ServerGroup=None, Site=None):
    '''
    Deletes the web service, including all resources under it.

    If web service does not exist, an exception will be raised.

    :type Name: string
    :param Name: Web service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    '''
    return WebService._delete_web_service(connection=self, Name=Name, ServerGroup=ServerGroup, Site=Site)

  def get_all_db_services(self, ServerGroup=None, Site=None):
    return DbService._get_all_db_services(connection=self, ServerGroup=ServerGroup, Site=Site)

  def get_db_service(self, Name=None, ServerGroup=None, Site=None):
    return DbService._get_db_service(connection=self, Name=Name, ServerGroup=ServerGroup, Site=Site)

  def create_db_service(self, Name=None, ServerGroup=None, Site=None, Ports=[], DefaultApp=None, DbMappings=[], TextReplacement=[], LogCollectors=[], DbServiceType=None, update=False):
    return DbService._create_db_service(connection=self, Name=Name, ServerGroup=ServerGroup, Site=Site, Ports=Ports, DefaultApp=DefaultApp, DbMappings=DbMappings, TextReplacement=TextReplacement, LogCollectors=LogCollectors, DbServiceType=DbServiceType, update=update)

  # Create - the part of post children. It's only needed to create the db mappings, but I leave the parameters the same for simplicity
  def create_db_service_pc(self, Name=None, ServerGroup=None, Site=None, Ports=[], DefaultApp=None, DbMappings=[], TextReplacement=[], LogCollectors=[], DbServiceType=None, update=False):
    return DbService._create_db_service_pc(connection=self, Name=Name, ServerGroup=ServerGroup, Site=Site, Ports=Ports, DefaultApp=DefaultApp, DbMappings=DbMappings, TextReplacement=TextReplacement, LogCollectors=LogCollectors, DbServiceType=DbServiceType, update=update)

  def delete_db_service(self, Name=None, ServerGroup=None, Site=None):
    return DbService._delete_db_service(connection=self, Name=Name, ServerGroup=ServerGroup, Site=Site)

  def get_all_db_applications(self, ServerGroup=None, Site=None, DbService=None):
    return DbApplication._get_all_db_applications(connection=self, ServerGroup=ServerGroup, Site=Site, DbService=DbService)

  def get_db_application(self, Name=None, ServerGroup=None, Site=None, DbService=None):
    return DbApplication._get_db_application(connection=self, ServerGroup=ServerGroup, Site=Site, DbService=DbService, Name=Name)

  def create_db_application(self, Name=None, DbService=None, ServerGroup=None, Site=None, TableGroupValues=None, update=False):
    return DbApplication._create_db_application(connection=self, ServerGroup=ServerGroup, Site=Site, DbService=DbService, Name=Name, TableGroupValues=TableGroupValues, update=update)

  def delete_db_application(self, Name=None, DbService=None, ServerGroup=None, Site=None):
    return DbApplication._delete_db_application(connection=self, ServerGroup=ServerGroup, Site=Site, DbService=DbService, Name=Name)

#  def _update_db_application(self, DbService=None, ServerGroup=None, Site=None, Name=None, Parameter=None, Value=None):
#    return DbApplication._update_db_application(connection=self, DbService=DbService, ServerGroup=ServerGroup, Site=Site, Name=Name, Parameter=Parameter, Value=Value)

  def get_all_web_applications(self, ServerGroup=None, Site=None, WebService=None):
    '''
    :type WebService: string
    :param WebService: Web Service name
    :type ServerGroup: string
    :param ServerGroup: Server group name
    :type Site: string
    :param Site: Site name
    :rtype: `list` of :obj:`imperva_sdk.WebApplication.WebApplication`
    :return: List of all web applications in MX under a given site, server group and web service
    '''
    return WebApplication._get_all_web_applications(connection=self, ServerGroup=ServerGroup, Site=Site, WebService=WebService)
    
  def get_web_application(self, Name=None, ServerGroup=None, Site=None, WebService=None):
    '''
    :type Name: string
    :param Name: Web Application name
    :type WebService: string
    :param WebService: Web Service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    :rtype: imperva_sdk.WebApplication.WebApplication
    :return: WebApplication instance of web application with specified name, web service, server group and site. (:obj:`None` if web service does not exist)
    '''
    return WebApplication._get_web_application(connection=self, ServerGroup=ServerGroup, Site=Site, WebService=WebService, Name=Name)
    
  def create_web_application(self, Name=None, WebService=None, ServerGroup=None, Site=None, LearnSettings=None, ParseOcspRequests=None, RestrictMonitoringToUrls=None, IgnoreUrlsDirectories=None, Profile=None, Mappings=None, update=False):
    '''
    :type Name: string
    :param Name: Web Application name
    :type WebService: string
    :param WebService: Web Service name
    :type ServerGroup: string
    :param ServerGroup: Server group name
    :type Site: string
    :param Site: Site name
    :param LearnSettings: See :py:attr:`imperva_sdk.WebApplication.WebApplication.LearnSettings`
    :param ParseOcspRequests: See :py:attr:`imperva_sdk.WebApplication.WebApplication.ParseOcspRequests`
    :param RestrictMonitoringToUrls: See :py:attr:`imperva_sdk.WebApplication.WebApplication.RestrictMonitoringToUrls`
    :param IgnoreUrlsDirectories: See :py:attr:`imperva_sdk.WebApplication.WebApplication.IgnoreUrlsDirectories`
    :param Mappings: See :py:attr:`imperva_sdk.WebApplication.WebApplication.Mappings`
    :param Profile: See :py:meth:`imperva_sdk.MxConnection.get_profile`
    :type update: boolean
    :param update: If `update=True` and the resource already exists, update and return the existing resource. If `update=False` (default) and the resource exists, an exception will be raised.
    :rtype: imperva_sdk.WebApplication.WebApplication
    :return: Created WebApplication instance.
    '''
    return WebApplication._create_web_application(connection=self, ServerGroup=ServerGroup, Site=Site, WebService=WebService, Name=Name, LearnSettings=LearnSettings, ParseOcspRequests=ParseOcspRequests, RestrictMonitoringToUrls=RestrictMonitoringToUrls, IgnoreUrlsDirectories=IgnoreUrlsDirectories, Profile=Profile, Mappings=Mappings, update=update)

  def delete_web_application(self, Name=None, WebService=None, ServerGroup=None, Site=None):
    '''
    Deletes the web application.

    If web application does not exist, an exception will be raised.

    :type Name: string
    :param Name: Web application name
    :type WebService: string
    :param WebService: Web service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    '''
    return WebApplication._delete_web_application(connection=self, ServerGroup=ServerGroup, Site=Site, WebService=WebService, Name=Name)

  def delete_profile_url(self, Application=None, WebService=None, ServerGroup=None, Site=None, UrlName=None):
    '''
    Deletes an application profile URL.

    .. note:: Uses APIs that were introduced in v12.3.

    :type Application: string
    :param Application: Web application name
    :type WebService: string
    :param WebService: Web service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    :type UrlName: string
    :param UrlName: Url Name (Path)
    '''
    return WebApplication._delete_profile_url(connection=self, Application=Application, ServerGroup=ServerGroup, Site=Site, WebService=WebService, UrlName=UrlName)

  def get_profile_url(self, Application=None, WebService=None, ServerGroup=None, Site=None, UrlName=None):
    '''
    Returns a JSON representation of the application profile URL.

    .. note:: Uses APIs that were introduced in v12.3.

    :type Application: string
    :param Application: Web application name
    :type WebService: string
    :param WebService: Web service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    :type UrlName: string
    :param UrlName: Url Name (Path)
    '''
    return WebApplication._get_profile_url(connection=self, Application=Application, ServerGroup=ServerGroup, Site=Site, WebService=WebService, UrlName=UrlName)

  def update_profile_url(self, Application=None, WebService=None, ServerGroup=None, Site=None, UrlProfile=None, UrlName=None):
    '''
    Updates (overwrites) a URL profile settings with a given URL profile. Run a get_profile_url() on the MX to see the format.

    .. note:: Uses APIs that were introduced in v12.3.

    :param UrlProfile: imperva_sdk URL profile JSON object (dictionary)
    :type Application: string
    :param Application: Web application name
    :type WebService: string
    :param WebService: Web service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    :type UrlName: string
    :param UrlName: Url Name (Path)
    '''
    return WebApplication._update_profile_url(connection=self, Application=Application, ServerGroup=ServerGroup, Site=Site, WebService=WebService, UrlProfile=UrlProfile, UrlName=UrlName)

  def get_profile(self, Application=None, WebService=None, ServerGroup=None, Site=None):
    '''
    Returns a JSON representation of the application profile (all screens).

    .. note:: Uses APIs that were introduced in v12.3.

    :type Application: string
    :param Application: Web application name
    :type WebService: string
    :param WebService: Web service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    '''
    return WebApplication._get_profile(connection=self, Application=Application, ServerGroup=ServerGroup, Site=Site, WebService=WebService)

  def update_profile(self, Application=None, WebService=None, ServerGroup=None, Site=None, Profile=None, SwaggerJson=None):
    '''
    Updates (overwrites) the entire application profile with a given profile or swagger JSON. Run a get_profile() on the MX to see the format.

    .. note:: Uses APIs that were introduced in v12.3.

    :param Profile: imperva_sdk profile JSON object (dictionary)
    :param SwaggerJSON: Swagger JSON (dictionary) to be converted to profile JSON and used for profile update
    :type Application: string
    :param Application: Web application name
    :type WebService: string
    :param WebService: Web service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    '''
    return WebApplication._update_profile(connection=self, Application=Application, ServerGroup=ServerGroup, Site=Site, WebService=WebService, Profile=Profile, SwaggerJson=SwaggerJson)
    
  def _update_web_application(self, WebService=None, ServerGroup=None, Site=None, Name=None, Parameter=None, Value=None):
    return WebApplication._update_web_application(connection=self, WebService=WebService, ServerGroup=ServerGroup, Site=Site, Name=Name, Parameter=Parameter, Value=Value)
    
  def get_all_krp_rules(self, ServerGroup=None, Site=None, WebService=None):
    '''
    :type WebService: string
    :param WebService: Web Service name
    :type ServerGroup: string
    :param ServerGroup: Server group name
    :type Site: string
    :param Site: Site name
    :rtype: `list` of :obj:`imperva_sdk.KrpRule.KrpRule`
    :return: List of all KRP rules (inbound and outbound) under specified web service.
    '''
    return KrpRule._get_all_krp_rules(connection=self, ServerGroup=ServerGroup, Site=Site, WebService=WebService)
    
  def get_krp_rule(self, ServerGroup=None, Site=None, WebService=None, GatewayGroup=None, Alias=None, GatewayPorts=None):
    '''
    :type WebService: string
    :param WebService: Web Service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    :param GatewayGroup: See :py:attr:`imperva_sdk.KrpRule.KrpRule.GatewayGroup`
    :param Alias: See :py:attr:`imperva_sdk.KrpRule.KrpRule.Alias`
    :param GatewayPorts: See :py:attr:`imperva_sdk.KrpRule.KrpRule.GatewayPorts`. Can be only one of the inbound ports but needs to be a list type `[]`.
    :rtype: imperva_sdk.KrpRule.KrpRule
    :return: KrpRule instance of a krp (reverse proxy) rule under web service with specified gateway group, alias and gateway port.
    '''
    return KrpRule._get_krp_rule(connection=self, ServerGroup=ServerGroup, Site=Site, WebService=WebService, GatewayGroup=GatewayGroup, Alias=Alias, GatewayPorts=GatewayPorts)
    
  def create_krp_rule(self, WebService=None, ServerGroup=None, Site=None, GatewayGroup=None, Alias=None, GatewayPorts=[], ServerCertificate=None, ClientAuthenticationAuthorities=None, OutboundRules=[], Name=None, update=False):
    '''
    Creates KRP (reverse proxy) rule. Must specify at least one outbound rule on creation.

    >>> krp = mx.create_krp_rule(WebService="advanced web service", ServerGroup="server group name", Site="site name", Alias="alias name", GatewayGroup="gg name", GatewayPorts=[8443], ServerCertificate="key name", OutboundRules=[{'priority': 1, 'internalIpHost': '192.168.0.1', 'serverPort': 443}])

    :type Name: string
    :param Name: This is a stub parameter - don't need to specify anythin.
    :type WebService: string
    :param WebService: Web Service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    :param GatewayGroup: See :py:attr:`imperva_sdk.KrpRule.KrpRule.GatewayGroup`
    :param Alias: See :py:attr:`imperva_sdk.KrpRule.KrpRule.Alias`
    :param GatewayPorts: See :py:attr:`imperva_sdk.KrpRule.KrpRule.GatewayPorts`. 
    :param ServerCertificate: See :py:attr:`imperva_sdk.KrpRule.KrpRule.ServerCertificate`. 
    :param ClientAuthenticationAuthorities: See :py:attr:`imperva_sdk.KrpRule.KrpRule.ClientAuthenticationAuthorities`. 
    :param OutboundRules: See :py:attr:`imperva_sdk.KrpRule.KrpRule.OutboundRules`. 
    :type update: boolean
    :param update: If `update=True` and the resource already exists, update and return the existing resource. If `update=False` (default) and the resource exists, an exception will be raised.
    :rtype: imperva_sdk.KrpRule.KrpRule
    :return: Created KrpRule instance.
    '''
    return KrpRule._create_krp_rule(connection=self, ServerGroup=ServerGroup, Site=Site, WebService=WebService, GatewayGroup=GatewayGroup, Alias=Alias, GatewayPorts=GatewayPorts, ServerCertificate=ServerCertificate, ClientAuthenticationAuthorities=ClientAuthenticationAuthorities, OutboundRules=OutboundRules, Name=None, update=update)

  def delete_krp_rule(self, WebService=None, ServerGroup=None, Site=None, GatewayGroup=None, Alias=None, GatewayPorts=[]):
    '''
    Deletes KRP rule.

    If krp rule does not exist, an exception will be raised.

    :type WebService: string
    :param WebService: Web service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    :param GatewayGroup: See :py:attr:`imperva_sdk.KrpRule.KrpRule.GatewayGroup`
    :param Alias: See :py:attr:`imperva_sdk.KrpRule.KrpRule.Alias`
    :param GatewayPorts: See :py:attr:`imperva_sdk.KrpRule.KrpRule.GatewayPorts`. Can be only one of the inbound ports but needs to be a list type `[]`.
    '''
    return KrpRule._delete_krp_rule(connection=self, ServerGroup=ServerGroup, Site=Site, WebService=WebService, GatewayGroup=GatewayGroup, Alias=Alias, GatewayPorts=GatewayPorts)
    
  def get_all_trp_rules(self, ServerGroup=None, Site=None, WebService=None):
    '''
    :type WebService: string
    :param WebService: Web Service name
    :type ServerGroup: string
    :param ServerGroup: Server group name
    :type Site: string
    :param Site: Site name
    :rtype: `list` of :obj:`imperva_sdk.TrpRule.TrpRule`
    :return: List of all TRP rules under specified web service.
    '''
    return TrpRule._get_all_trp_rules(connection=self, ServerGroup=ServerGroup, Site=Site, WebService=WebService)
    
  def get_trp_rule(self, ServerGroup=None, Site=None, WebService=None, ServerIp=None, ListenerPorts=None):
    '''
    :type WebService: string
    :param WebService: Web Service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    :param ServerIp: See :py:attr:`imperva_sdk.TrpRule.TrpRule.ServerIp`
    :param ListenerPorts: See :py:attr:`imperva_sdk.TrpRule.TrpRule.ListenerPorts`. Can be only one of the ports but needs to be a list type `[]`.
    :rtype: imperva_sdk.TrpRule.TrpRule
    :return: TrpRule instance of a trp rule under web service with specified server IP and listener port.
    '''
    return TrpRule._get_trp_rule(connection=self, ServerGroup=ServerGroup, Site=Site, WebService=WebService, ServerIp=ServerIp, ListenerPorts=ListenerPorts)
    
  def create_trp_rule(self, WebService=None, ServerGroup=None, Site=None, ServerIp=None, ListenerPorts=[], ServerSidePort=None, EncryptServerConnection=None, Certificate=None, Name=None, update=False):
    '''
    Creates TRP (transparent reverse proxy) rule. 

    :type Name: string
    :param Name: This is a stub parameter - don't need to specify anythin.
    :type WebService: string
    :param WebService: Web Service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    :param ListenerPorts: See :py:attr:`imperva_sdk.TrpRule.TrpRule.ListenerPorts`
    :param ServerIp: See :py:attr:`imperva_sdk.TrpRule.TrpRule.ServerIp`
    :param ServerSidePort: See :py:attr:`imperva_sdk.TrpRule.TrpRule.ServerSidePort`. 
    :param Certificate: See :py:attr:`imperva_sdk.TrpRule.TrpRule.Certificate`. 
    :param EncryptServerConnection: See :py:attr:`imperva_sdk.TrpRule.TrpRule.EncryptServerConnection`. 
    :type update: boolean
    :param update: If `update=True` and the resource already exists, update and return the existing resource. If `update=False` (default) and the resource exists, an exception will be raised.
    :rtype: imperva_sdk.TrpRule.TrpRule
    :return: Created TrpRule instance.
    '''
    return TrpRule._create_trp_rule(connection=self, ServerGroup=ServerGroup, Site=Site, WebService=WebService, ServerIp=ServerIp, ListenerPorts=ListenerPorts, ServerSidePort=ServerSidePort, EncryptServerConnection=EncryptServerConnection, Certificate=Certificate, Name=None, update=update)

  def delete_trp_rule(self, WebService=None, ServerGroup=None, Site=None, ServerIp=None, ListenerPorts=[]):
    '''
    Deletes TRP rule.

    If trp rule does not exist, an exception will be raised.

    :type WebService: string
    :param WebService: Web service name
    :type ServerGroup: string
    :param ServerGroup: Server Group name
    :type Site: string
    :param Site: Site name
    :param ServerIp: See :py:attr:`imperva_sdk.TrpRule.TrpRule.ServerIp`
    :param ListenerPorts: See :py:attr:`imperva_sdk.TrpRule.TrpRule.ListenerPorts`. Can be only one of the ports but needs to be a list type `[]`.
    '''
    return TrpRule._delete_trp_rule(connection=self, ServerGroup=ServerGroup, Site=Site, WebService=WebService, ServerIp=ServerIp, ListenerPorts=ListenerPorts)


  # ====================================== DAM action sets ===============================================
  #
  #-----------------------------------------------------------------------------
  # Action set
  #-----------------------------------------------------------------------------
  #
  def get_all_action_sets(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.ActionSet.ActionSet`
    :return: List of all "action sets".
    '''
    return ActionSet._get_all_action_sets(connection=self)


  def get_action_set(self, Name=None):
    '''
    :type Name: string
    :param Name: Action Set Name
    :rtype: imperva_sdk.ActionSet.ActionSet
    :return: ActionSet instance of specified action set.
    '''
    return ActionSet._get_action_set(connection=self, Name=Name)
    
  def delete_action_set(self, Name=None):
    '''
    :type Name: string
    :param Name: Action Set Name
    '''
    return ActionSet._delete_action_set(connection=self, Name=Name)
    
  def create_action_set(self, Name=None, AsType=None, update=False):
    '''
    Create (or update) an "action set"

    >>> action_set = mx.create_action_set(Name="Send GW violations to Syslog", AsType="security")
    
    :type Name: string
    :param Name: Action Set Name
    :type AsType: string
    :param AsType: Action Set Type (security / any)
    :rtype: imperva_sdk.ActionSet.ActionSet
    :return: ActionSet instance of created action set.
    '''
    return ActionSet._create_action_set(connection=self, Name=Name, AsType=AsType, update=update)


  def _export_action_sets(self):
    actionSetDict = {
      'metadata': {
        'Host': self.Host,
        'Version': self.Version,
        'Challenge': self.Challenge,
        'SdkVersion': imperva_sdk_version(),
        'ExportTime': time.strftime("%Y-%m-%d %H:%M:%S")
      }
    }

    actionSetDict['action_sets'] = []
    try:
      action_sets = self.get_all_action_sets()
      for action_set in action_sets:
        as_dict = dict(action_set)
        actionSetDict['action_sets'].append(as_dict)
    except:
      # Previous versions didn't have action set APIs
      pass

    return actionSetDict

  def export_action_sets(self):
    """
    Export all the action sets in the MX

    >>> specificExport = srcMx.export_action_sets()
    >>> pSpecificExport = json.loads(specificExport)

    :return json object
    """
    return json.dumps(self._export_action_sets())

  def import_action_sets(self, Json=None, update=True):
    """
    Import only the dam action sets from valid JSON string.

    >>> targetMx.import_action_sets(specificExport)

    :param Json (string): valid imperva_sdk JSON export
    :param update (boolean): Set to `True` to update existing resources (default in import function).
                             If set to `False`, existing resources will cause import operations to fail.
    :return: (list of dict) Log with details of all import events and their outcome.
    """
    try:
      json_config = json.loads(Json)
    except:
      raise MxException("Invalid JSON configuration")

    return self._create_tree_from_json(Dict={'action_sets': json_config['action_sets']}, ParentObject=self, update=update)

  # ===================================== END DAM action sets ============================================

  def get_all_actions(self, ActionSet=None):
    '''
    :rtype: `list` of :obj:`imperva_sdk.Action.Action`
    :return: List of all actions in an action set.
    '''
    return Action._get_all_actions(connection=self, ActionSet=ActionSet)

  def get_action(self, Name=None, ActionSet=None):
    '''
    :type Name: string
    :param Name: Action Name
    :type ActionSet: string
    :param ActionSet: Action Set Name
    :rtype: imperva_sdk.Action.Action
    :return: Action instance of specified action in Action Set.
    '''
    return Action._get_action(connection=self, Name=Name, ActionSet=ActionSet)

  def delete_action(self, Name=None, ActionSet=None):
    '''
    :type Name: string
    :param Name: Action Name
    :type ActionSet: string
    :param ActionSet: Action Set Name
    '''
    return Action._delete_action(connection=self, Name=Name, ActionSet=ActionSet)

    
  def create_action(self, Name=None, ActionSet=None, ActionType=None, Protocol=None, SyslogFacility=None, Host=None, SyslogLogLevel=None, SecondaryPort=None, ActionInterface=None, SecondaryHost=None, Message=None, Port=None, update=False):
    '''
    Create (or update) an "action set" action.

    >>> action_set.create_action(Name="GW Syslog", ActionType="GWSyslog", Port=514, Host="syslog-server", Protocol="TCP", SyslogLogLevel="DEBUG", SyslogFacility="LOCAL0", ActionInterface="Gateway Log - Security Event - System Log (syslog) - JSON format (Extended)")

    :type Name: string
    :param Name: Action Name
    :type ActionSet: string
    :param ActionSet: Action Set Name
    :param ActionType: See :py:attr:`imperva_sdk.Action.Action.ActionType`
    :param Protocol: See :py:attr:`imperva_sdk.Action.Action.Protocol`
    :param SyslogFacility: See :py:attr:`imperva_sdk.Action.Action.SyslogFacility`
    :param Host: See :py:attr:`imperva_sdk.Action.Action.Host`
    :param SyslogLogLevel: See :py:attr:`imperva_sdk.Action.Action.SyslogLogLevel`
    :param SecondaryPort: See :py:attr:`imperva_sdk.Action.Action.SecondaryPort`
    :param ActionInterface: See :py:attr:`imperva_sdk.Action.Action.ActionInterface`
    :param SecondaryHost: See :py:attr:`imperva_sdk.Action.Action.SecondaryHost`
    :param Message: See :py:attr:`imperva_sdk.Action.Action.Message`
    :param Port: See :py:attr:`imperva_sdk.Action.Action.Port`
    :type update: boolean
    :param update: If `update=True` and the resource already exists, update and return the existing resource. If `update=False` (default) and the resource exists, an exception will be raised.
  
    :rtype: imperva_sdk.Action.Action
    :return: Created Action instance.
    '''
  
    return Action._create_action(connection=self, Name=Name, ActionSet=ActionSet, ActionType=ActionType, Protocol=Protocol, SyslogFacility=SyslogFacility, Host=Host, SyslogLogLevel=SyslogLogLevel, SecondaryPort=SecondaryPort, ActionInterface=ActionInterface, SecondaryHost=SecondaryHost, Message=Message, Port=Port, update=update)

  def _update_action(self, ActionSet=None, Name=None, Parameter=None, Value=None):
    return Action._update_action(connection=self, ActionSet=ActionSet, Name=Name, Parameter=Parameter, Value=Value)

  def get_all_web_service_custom_policies(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.WebServiceCustomPolicy.WebServiceCustomPolicy`
    :return: List of all "web service custom" policies.
    '''
    return WebServiceCustomPolicy._get_all_web_service_custom_policies(connection=self)

  def get_web_service_custom_policy(self, Name=None):
    '''
    .. note:: Policies with the / character in their name cannot be fetched.

    :type Name: string
    :param Name: Policy Name
    :rtype: imperva_sdk.WebServiceCustomPolicy.WebServiceCustomPolicy
    :return: WebServiceCustomPolicy instance of specified policy.
    '''
    return WebServiceCustomPolicy._get_web_service_custom_policy(connection=self, Name=Name)

  def create_web_service_custom_policy(self, Name=None, Enabled=None, Severity=None, Action=None, FollowedAction=None, SendToCd=None, DisplayResponsePage=None, ApplyTo=None, MatchCriteria=None, OneAlertPerSession=None, update=False):
    '''
    Create (or update) a "web service custom" policy.

    >>> policy = mx.create_web_service_custom_policy(Name="new custom policy", Enabled=True, Severity="High", Action='block', FollowedAction="Short IP Block", DisplayResponsePage=False, SendToCd=False, ApplyTo=[{'siteName': 'site name', 'webServiceName': 'advanced web service', 'serverGroupName': 'server group name'}], OneAlertPerSession=False, MatchCriteria=[{'type': 'httpRequestHeaderValue', 'operation': 'atLeastOne', 'values': ['516', '2560'], 'name': 'Content-Length'}, {'type': 'violations', 'operation': 'atLeastOne', 'values': ['Post Request - Missing Content Type']}])

    :type Name: string
    :param Name: Policy Name
    :param Enabled: See :py:attr:`imperva_sdk.WebServiceCustomPolicy.WebServiceCustomPolicy.Enabled`
    :param Severity: See :py:attr:`imperva_sdk.WebServiceCustomPolicy.WebServiceCustomPolicy.Severity`
    :param Action: See :py:attr:`imperva_sdk.WebServiceCustomPolicy.WebServiceCustomPolicy.Action`
    :param FollowedAction: See :py:attr:`imperva_sdk.WebServiceCustomPolicy.WebServiceCustomPolicy.FollowedAction`
    :param SendToCd: See :py:attr:`imperva_sdk.WebServiceCustomPolicy.WebServiceCustomPolicy.SendToCd`
    :param DisplayResponsePage: See :py:attr:`imperva_sdk.WebServiceCustomPolicy.WebServiceCustomPolicy.DisplayResponsePage`
    :param ApplyTo: See :py:attr:`imperva_sdk.WebServiceCustomPolicy.WebServiceCustomPolicy.ApplyTo`
    :param MatchCriteria: See :py:attr:`imperva_sdk.WebServiceCustomPolicy.WebServiceCustomPolicy.MatchCriteria`
    :param OneAlertPerSession: See :py:attr:`imperva_sdk.WebServiceCustomPolicy.WebServiceCustomPolicy.OneAlertPerSession`
    :type update: boolean
    :param update: If `update=True` and the resource already exists, update and return the existing resource. If `update=False` (default) and the resource exists, an exception will be raised.
  
    :rtype: imperva_sdk.WebServiceCustomPolicy.WebServiceCustomPolicy
    :return: Created WebServiceCustomPolicy instance.
    '''
    return WebServiceCustomPolicy._create_web_service_custom_policy(connection=self, Name=Name, Enabled=Enabled, Severity=Severity, Action=Action, FollowedAction=FollowedAction, SendToCd=SendToCd, DisplayResponsePage=DisplayResponsePage, ApplyTo=ApplyTo, MatchCriteria=MatchCriteria, OneAlertPerSession=OneAlertPerSession, update=update)

  def delete_web_service_custom_policy(self, Name=None):
    '''
    Deletes policy.

    If policy does not exist, an exception will be raised. Cannot delete ADC predefined policies.

    :type Name: string
    :param Name: Policy name.
    '''
    return WebServiceCustomPolicy._delete_web_service_custom_policy(connection=self, Name=Name)
    
  def _update_web_service_custom_policy(self, Name=None, Parameter=None, Value=None):
    return WebServiceCustomPolicy._update_web_service_custom_policy(connection=self, Name=Name, Parameter=Parameter, Value=Value)
    
  def get_all_web_application_custom_policies(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.WebApplicationCustomPolicy.WebApplicationCustomPolicy`
    :return: List of all "web application custom" policies.
    '''
    return WebApplicationCustomPolicy._get_all_web_application_custom_policies(connection=self)

  def get_web_application_custom_policy(self, Name=None):
    '''
    .. note:: Policies with the / character in their name cannot be fetched.

    :type Name: string
    :param Name: Policy Name
    :rtype: imperva_sdk.WebApplicationCustomPolicy.WebApplicationCustomPolicy
    :return: WebApplicationCustomPolicy instance of specified policy.
    '''
    return WebApplicationCustomPolicy._get_web_application_custom_policy(connection=self, Name=Name)

  def create_web_application_custom_policy(self, Name=None, Enabled=None, Severity=None, Action=None, FollowedAction=None, SendToCd=None, DisplayResponsePage=None, ApplyTo=None, MatchCriteria=None, OneAlertPerSession=None, update=False):
    '''
    Create (or update) a "web application custom" policy.

    >>> policy = mx.create_web_application_custom_policy(Name="new custom policy", Enabled=True, Severity="High", Action='block', FollowedAction="Short IP Block", DisplayResponsePage=False, SendToCd=False, ApplyTo=[{'siteName': 'site name', 'webServiceName': 'advanced web service', 'serverGroupName': 'server group name'}], OneAlertPerSession=False, MatchCriteria=[{'type': 'httpRequestHeaderValue', 'operation': 'atLeastOne', 'values': ['516', '2560'], 'name': 'Content-Length'}, {'type': 'violations', 'operation': 'atLeastOne', 'values': ['Post Request - Missing Content Type']}])

    :type Name: string
    :param Name: Policy Name
    :param Enabled: See :py:attr:`imperva_sdk.WebApplicationCustomPolicy.WebApplicationCustomPolicy.Enabled`
    :param Severity: See :py:attr:`imperva_sdk.WebApplicationCustomPolicy.WebApplicationCustomPolicy.Severity`
    :param Action: See :py:attr:`imperva_sdk.WebApplicationCustomPolicy.WebApplicationCustomPolicy.Action`
    :param FollowedAction: See :py:attr:`imperva_sdk.WebApplicationCustomPolicy.WebApplicationCustomPolicy.FollowedAction`
    :param SendToCd: See :py:attr:`imperva_sdk.WebApplicationCustomPolicy.WebApplicationCustomPolicy.SendToCd`
    :param DisplayResponsePage: See :py:attr:`imperva_sdk.WebApplicationCustomPolicy.WebApplicationCustomPolicy.DisplayResponsePage`
    :param ApplyTo: See :py:attr:`imperva_sdk.WebApplicationCustomPolicy.WebApplicationCustomPolicy.ApplyTo`
    :param MatchCriteria: See :py:attr:`imperva_sdk.WebApplicationCustomPolicy.WebApplicationCustomPolicy.MatchCriteria`
    :param OneAlertPerSession: See :py:attr:`imperva_sdk.WebApplicationCustomPolicy.WebApplicationCustomPolicy.OneAlertPerSession`
    :type update: boolean
    :param update: If `update=True` and the resource already exists, update and return the existing resource. If `update=False` (default) and the resource exists, an exception will be raised.
  
    :rtype: imperva_sdk.WebApplicationCustomPolicy.WebApplicationCustomPolicy
    :return: Created WebApplicationCustomPolicy instance.
    '''
    return WebApplicationCustomPolicy._create_web_application_custom_policy(connection=self, Name=Name, Enabled=Enabled, Severity=Severity, Action=Action, FollowedAction=FollowedAction, SendToCd=SendToCd, DisplayResponsePage=DisplayResponsePage, ApplyTo=ApplyTo, MatchCriteria=MatchCriteria, OneAlertPerSession=OneAlertPerSession, update=update)

  def delete_web_application_custom_policy(self, Name=None):
    '''
    Deletes policy.

    If policy does not exist, an exception will be raised. Cannot delete ADC predefined policies.

    :type Name: string
    :param Name: Policy name.
    '''
    return WebApplicationCustomPolicy._delete_web_application_custom_policy(connection=self, Name=Name)
    
  def _update_web_application_custom_policy(self, Name=None, Parameter=None, Value=None):
    return WebApplicationCustomPolicy._update_web_application_custom_policy(connection=self, Name=Name, Parameter=Parameter, Value=Value)


  def get_all_web_profile_policies(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.WebProfilePolicy.WebProfilePolicy`
    :return: List of all "web profile" policies.
    '''
    return WebProfilePolicy._get_all_web_profile_policies(connection=self)

  def get_web_profile_policy(self, Name=None):
    '''
    .. note:: Policies with the / character in their name cannot be fetched.

    :type Name: string
    :param Name: Policy Name
    :rtype: imperva_sdk.WebProfilePolicy.WebProfilePolicy
    :return: WebProfilePolicy instance of specified policy.
    '''
    return WebProfilePolicy._get_web_profile_policy(connection=self, Name=Name)

  def create_web_profile_policy(self, Name=None, SendToCd=None, DisplayResponsePage=None, DisableLearning=None,
                                ApplyTo=[], Rules=[], Exceptions=[], ApuConfig={}, update=False):
    '''
    Create (or update) a "web Progile" policy.

    >>> policy = mx.create_web_profile_policy(Name="New web profile policy", SendToCd=True, DisplayResponsePage=True, DisableLearning=False, ApplyTo=[{'siteName': 'site name', 'webServiceName': 'advanced web service', 'serverGroupName': 'server group name'}], Rules=[{u'action': u'block', u'enabled': False, u'name': u'Cookie Injection', u'severity': u'medium'}], Exceptions=[{u'comment': u'exception comment', u'predicates': [{u'type': u'httpRequestUrl', u'operation': u'atLeastOne', u'values': [u'/login'], u'match': u'prefix'}], u'ruleName': u'Cookie Injection'}], ApuConfig={'SOAP Element Value Length Violation': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Parameter Read Only Violation': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, "Reuse of Expired Session's Cookie": {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'SOAP Element Value Type Violation': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Required Parameter Not Found': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Unauthorized Method for Known URL': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Unknown Parameter': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Parameter Type Violation': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Unauthorized SOAP Action': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Unknown SOAP Element': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Required XML Element Not Found': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Parameter Value Length Violation': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Cookie Injection': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Cookie Tampering': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}}, update=False)

    :type Name: string
    :param Name: Policy Name
    :param SendToCd: See :py:attr:`imperva_sdk.WebProfilePolicy.WebProfilePolicy.SendToCd`
    :param DisplayResponsePage: See :py:attr:`imperva_sdk.WebProfilePolicy.WebProfilePolicy.DisplayResponsePage`
    :param DisableLearning: See :py:attr:`imperva_sdk.WebProfilePolicy.WebProfilePolicy.DisableLearning`
    :param ApplyTo: See :py:attr:`imperva_sdk.WebProfilePolicy.WebProfilePolicy.ApplyTo`
    :param Rules: See :py:attr:`imperva_sdk.WebProfilePolicy.WebProfilePolicy.Rules`
    :param Exceptions: See :py:attr:`imperva_sdk.WebProfilePolicy.WebProfilePolicy.Exceptions`
    :param ApuConfig: See :py:attr:`imperva_sdk.WebProfilePolicy.WebProfilePolicy.ApuConfig`
    :type update: boolean
    :param update: If `update=True` and the resource already exists, update and return the existing resource. If `update=False` (default) and the resource exists, an exception will be raised.

    :rtype: imperva_sdk.WebProfilePolicy.WebProfilePolicy
    :return: Created WebProfilePolicy instance.
    '''
    return WebProfilePolicy._create_web_profile_policy(connection=self, Name=Name, SendToCd=SendToCd,
                                                       DisplayResponsePage=DisplayResponsePage, DisableLearning=DisableLearning, ApplyTo=ApplyTo,
                                                       Rules=Rules, Exceptions=Exceptions, ApuConfig=ApuConfig, update=update)

  def delete_web_profile_policy(self, Name=None):
    '''
    Deletes policy.

    If policy does not exist, an exception will be raised. Cannot delete ADC predefined policies.

    :type Name: string
    :param Name: Policy name.
    '''
    return WebProfilePolicy._delete_web_profile_policy(connection=self, Name=Name)

  def _update_web_profile_policy(self, Name=None, Parameter=None, Value=None):
    return WebProfilePolicy._update_web_profile_policy(connection=self, Name=Name, Parameter=Parameter, Value=Value)


  # ====================================== DAM policies ===============================================
  #
  #-----------------------------------------------------------------------------
  # DB Security Policies
  #-----------------------------------------------------------------------------
  #
  def get_all_db_security_dam_policies(self):
    return DbSecurityPolicy._get_all_db_security_policies(connection=self)

  def get_db_security_policy(self, Name=None):
    return DbSecurityPolicy._get_db_security_policy(connection=self, Name=Name)

  def create_db_security_dam_policy(self, Name=None, PolicyType=None, Enabled=None, Severity=None, Action=None,
                                    FollowedAction=None, ApplyTo=None, AutoApply=None, MatchCriteria=None, update=False):

    return DbSecurityPolicy._create_db_security_policy(connection=self, Name=Name, PolicyType=PolicyType, Enabled=Enabled,
                                                       Severity=Severity, Action=Action, FollowedAction=FollowedAction,
                                                       ApplyTo=ApplyTo, AutoApply=AutoApply, MatchCriteria=MatchCriteria, update=update)

  def delete_db_security_policy(self, Name=None):
    return DbSecurityPolicy._delete_db_security_policy(connection=self, Name=Name)

  def _update_db_security_policy(self, Name=None, Parameter=None, Value=None):
    return DbSecurityPolicy._update_db_security_policy(connection=self, Name=Name, Parameter=Parameter, Value=Value)

  #
  # -----------------------------------------------------------------------------
  # Data Enrichment Policies
  # -----------------------------------------------------------------------------
  #
  def get_all_data_enrichment_dam_policies(self):
    return DataEnrichmentPolicy._get_all_data_enrichment_policies(connection=self)
  def get_data_enrichment_policy(self, Name=None):
    return DataEnrichmentPolicy._get_data_enrichment_policy(connection=self, Name=Name)
  def create_data_enrichment_dam_policy(self, Name=None, PolicyType=None,Rules=[], MatchCriteria=[], ApplyTo=[], update=False):
    return DataEnrichmentPolicy._create_data_enrichment_policy(connection=self, Name=Name, PolicyType=PolicyType, Rules=Rules,
                                                               MatchCriteria=MatchCriteria, ApplyTo=ApplyTo, update=update)
  def update_data_enrichment_policy(self, Name=None, Rules=[], MatchCriteria=[], ApplyTo=[]):
    return DataEnrichmentPolicy._update_data_enrichment_policy(connection=self, Name=Name, Rules=Rules,
                                                               MatchCriteria=MatchCriteria, ApplyTo=ApplyTo)
  def delete_data_enrichment_policy(self, Name=None):
    return DataEnrichmentPolicy._delete_data_enrichment_policy(connection=self, Name=Name)

  #
  #-----------------------------------------------------------------------------
  # DB Audit Policies
  #-----------------------------------------------------------------------------
  #
  def get_all_db_audit_dam_policies(self):
    return DbAuditPolicy._get_all_db_audit_policies(connection=self)
  def get_db_audit_policy(self, Name=None):
    return DbAuditPolicy._get_db_audit_policy(connection=self, Name=Name)
  def create_db_audit_dam_policy(self, Name=None, Parameters=[], update=False):
    return DbAuditPolicy._create_db_audit_policy(connection=self, Name=Name, Parameters=Parameters, update=update)
  def delete_db_audit_policy(self, Name=None):
    return DbAuditPolicy._delete_db_audit_policy(connection=self, Name=Name)
  def _update_db_audit_policy(self, Name=None, Parameter=None, Value=None):
    return DbAuditPolicy._update_db_audit_policy(connection=self, Name=Name, Parameter=Parameter, Value=Value)


  def export_dam_policies(self):
    """
    Export all the dam policies in the MX

    >>> specificExport = srcMx.export_dam_policies()
    >>> pSpecificExport = json.loads(specificExport)

    :return a dictionary in a json like format
    """
    policiesDict = {
      'metadata': {
        'Host': self.Host,
        'Version': self.Version,
        'Challenge': self.Challenge,
        'SdkVersion': imperva_sdk_version(),
        'ExportTime': time.strftime("%Y-%m-%d %H:%M:%S")
      }
    }
    policiesDict.update(self._export_objects_to_dict('policies', 'dam'))
    return json.dumps(policiesDict)

  def import_dam_policies(self, Json=None, update=True):
    """
    Import only the dam policies from valid JSON string.

    >>> targetMx.import_dam_policies(specificExport)

    :param Json (string): valid imperva_sdk JSON export
    :param update (boolean): Set to `True` to update existing resources (default in import function).
                             If set to `False`, existing resources will cause import operations to fail.
    :return: (list of dict) Log with details of all import events and their outcome.
    """
    return self._import_object_from_json(Json, 'policies', 'dam', 'policy', update)

  # ==================================== END DAM policies =============================================

  #
  # -----------------------------------------------------------------------------
  # DB connection
  # -----------------------------------------------------------------------------
  #
  def get_db_connection(self, SiteName=None, ServerGroupName=None, ServiceName=None, ConnectionName=None):
    return DBConnection._get_db_connection(connection=self, SiteName=SiteName,
                                           ServerGroupName=ServerGroupName, ServiceName=ServiceName, ConnectionName=ConnectionName)
  def get_all_db_connections(self, Site=None, ServerGroup=None, ServiceName=None):
    return DBConnection._get_all_db_connections(Connection=self, SiteName=Site,
                                                ServerGroupName=ServerGroup, ServiceName=ServiceName)

  def create_db_connection(self, SiteName=None, ServerGroupName=None, ServiceName=None, ConnectionName=None,
                              UserName=None, Password=None, Port=None, IpAddress=None, DbName=None,
                              ServerName=None, UserMapping=None, ConnectionString=None, ServiceDirectory=None,
                              TnsAdmin=None, HomeDirectory=None, Instance=None, HostName=None, update=False):
    return DBConnection._create_db_connection(connection=self, SiteName=SiteName, ServerGroupName=ServerGroupName, ServiceName=ServiceName, ConnectionName=ConnectionName,
                              UserName=UserName, Password=Password, Port=Port, IpAddress=IpAddress, DbName=DbName,
                              ServerName=ServerName, UserMapping=UserMapping, ConnectionString=ConnectionString, ServiceDirectory=ServiceDirectory,
                              TnsAdmin=TnsAdmin, HomeDirectory=HomeDirectory, Instance=Instance, HostName=HostName, update=update)
  def update_db_connection(self, SiteName=None, ServerGroupName=None, ServiceName=None, ConnectionName=None,
                              UserName=None, Password=None, Port=None, IpAddress=None, DbName=None,
                              ServerName=None, UserMapping=None, ConnectionString=None, ServiceDirectory=None,
                              TnsAdmin=None, HomeDirectory=None, Instance=None, HostName=None):
    return DBConnection._update_db_connection(connection=self, SiteName=SiteName, ServerGroupName=ServerGroupName, ServiceName=ServiceName, ConnectionName=ConnectionName,
                              UserName=UserName, Password=Password, Port=Port, IpAddress=IpAddress, DbName=DbName,
                              ServerName=ServerName, UserMapping=UserMapping, ConnectionString=ConnectionString, ServiceDirectory=ServiceDirectory,
                              TnsAdmin=TnsAdmin, HomeDirectory=HomeDirectory, Instance=Instance, HostName=HostName)
  def delete_db_connection(self):
    return DBConnection._delete_db_connection(connection=self, siteName=None, serverGroupName=None, serviceName=None, connectionName=None)

  def get_all_parameter_type_global_objects(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.ParameterTypeGlobalObject.ParameterTypeGlobalObject`
    :return: List of all "parameter type configuration" global objects.
    '''
    return ParameterTypeGlobalObject._get_all_parameter_type_global_objects(connection=self)

  def get_parameter_type_global_object(self, Name=None):
    '''
    :type Name: string
    :param Name: Parameter Type Configuration Name
    :rtype: imperva_sdk.ParameterTypeGlobalObject.ParameterTypeGlobalObject
    :return: ParameterTypeGlobalObject instance of specified global object.
    '''
    return ParameterTypeGlobalObject._get_parameter_type_global_object(connection=self, Name=Name)


  def create_parameter_type_global_object(self, Name=None, Regex=None, update=False):
    '''
    Create (or update) a "parameter type" global object.

    :type Name: string
    :param Name: Global Object Name
    :param Regex: See :py:attr:`imperva_sdk.ParameterTypeGlobalObject.ParameterTypeGlobalObject.Regex`
    :type update: boolean
    :param update: If `update=True` and the resource already exists, update and return the existing resource. If `update=False` (default) and the resource exists, an exception will be raised.
  
    :rtype: imperva_sdk.ParameterTypeGlobalObject.ParameterTypeGlobalObject
    :return: Created ParameterTypeGlobalObject instance.
    '''
    return ParameterTypeGlobalObject._create_parameter_type_global_object(connection=self, Name=Name, Regex=Regex, update=update)

  def delete_parameter_type_global_object(self, Name=None):
    '''
    Deletes global object.

    :type Name: string
    :param Name: Global Object name.
    '''
    return ParameterTypeGlobalObject._delete_parameter_type_global_object(connection=self, Name=Name)

  def _update_parameter_type_global_object(self, Name=None, Parameter=None, Value=None):
    return ParameterTypeGlobalObject._update_parameter_type_global_object(connection=self, Name=Name, Parameter=Parameter, Value=Value)
    
  def get_all_http_protocol_signatures_policies(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.HttpProtocolSignaturesPolicy.HttpProtocolSignaturesPolicy`
    :return: List of all "http protocol signatures" policies.
    '''
    return HttpProtocolSignaturesPolicy._get_all_http_protocol_signatures_policies(connection=self)

  def get_http_protocol_signatures_policy(self, Name=None):
    '''
    .. note:: Policies with the / character in their name cannot be fetched.

    :type Name: string
    :param Name: Policy Name
    :rtype: imperva_sdk.HttpProtocolSignaturesPolicy.HttpProtocolSignaturesPolicy
    :return: HttpProtocolSignaturesPolicy instance of specified policy.
    '''
    return HttpProtocolSignaturesPolicy._get_http_protocol_signatures_policy(connection=self, Name=Name)

  def create_http_protocol_signatures_policy(self, Name=None, SendToCd=None, DisplayResponsePage=None, ApplyTo=[], Rules=[], Exceptions=[], update=False):
    '''
    Create (or update) an "http protocol signatures" policy.

    >>> mx.create_http_protocol_signatures_policy(Name="giora web sig 5", ApplyTo=[], Rules=[{u'action': u'block', u'enabled': False, u'name': u'ASP Oracle Padding', u'severity': u'medium'}], Exceptions=[{u'comment': u'exception comment', u'predicates': [{u'type': u'httpRequestUrl', u'operation': u'atLeastOne', u'values': [u'/login'], u'match': u'prefix'}], u'ruleName': u'ASP Oracle Padding'}])

    :type Name: string
    :param Name: Policy Name
    :param SendToCd: See :py:attr:`imperva_sdk.HttpProtocolSignaturesPolicy.HttpProtocolSignaturesPolicy.SendToCd`
    :param DisplayResponsePage: See :py:attr:`imperva_sdk.HttpProtocolSignaturesPolicy.HttpProtocolSignaturesPolicy.DisplayResponsePage`
    :param ApplyTo: See :py:attr:`imperva_sdk.HttpProtocolSignaturesPolicy.HttpProtocolSignaturesPolicy.ApplyTo`
    :param Rules: See :py:attr:`imperva_sdk.HttpProtocolSignaturesPolicy.HttpProtocolSignaturesPolicy.Rules`
    :param Exceptions: See :py:attr:`imperva_sdk.HttpProtocolSignaturesPolicy.HttpProtocolSignaturesPolicy.Exceptions`
    :type update: boolean
    :param update: If `update=True` and the resource already exists, update and return the existing resource. If `update=False` (default) and the resource exists, an exception will be raised.
  
    :rtype: imperva_sdk.HttpProtocolSignaturesPolicy.HttpProtocolSignaturesPolicy
    :return: Created HttpProtocolSignaturesPolicy instance.
    '''
    return HttpProtocolSignaturesPolicy._create_http_protocol_signatures_policy(connection=self, Name=Name, SendToCd=SendToCd, DisplayResponsePage=DisplayResponsePage, ApplyTo=ApplyTo, Rules=Rules, Exceptions=Exceptions, update=update)

  def delete_http_protocol_signatures_policy(self, Name=None):
    '''
    Deletes policy.

    If policy does not exist, an exception will be raised. Cannot delete ADC predefined policies.

    :type Name: string
    :param Name: Policy name.
    '''
    return HttpProtocolSignaturesPolicy._delete_http_protocol_signatures_policy(connection=self, Name=Name)

  def _update_http_protocol_signatures_policy(self, Name=None, Parameter=None, Value=None):
    return HttpProtocolSignaturesPolicy._update_http_protocol_signatures_policy(connection=self, Name=Name, Parameter=Parameter, Value=Value)

  # ====================================== DAS Objects ==================================================

  #
  #-----------------------------------------------------------------------------
  # DB Assessment Scans
  #-----------------------------------------------------------------------------

  def get_assessment_scan(self, Name=None):
    return AssessmentScan._get_assessment_scan(connection=self, Name=Name)

  def get_all_assessment_scan_das_objects(self):
    return AssessmentScan._get_all_assessment_scans(connection=self)

  def create_assessment_scan_das_object(self, Name=None, Type=None, PolicyName=None, PreTest=None, PolicyTags=[], DbConnectionTags=[],
    ApplyTo=[], Scheduling=None, update=False):
    return AssessmentScan._create_assessment_scan(connection=self, Name=Name, Type=Type, PolicyName=PolicyName, PreTest=PreTest,
                                                  PolicyTags=PolicyTags, DbConnectionTags=DbConnectionTags,
                                                  ApplyTo=ApplyTo, Scheduling=Scheduling, update=update)

  def update_assessment_scan(self, Name=None, Parameter=None, Value=None):
    return AssessmentScan._update_assessment_scan(connection=self, Name=Name, Parameter=Parameter, Value=Value)

  def delete_assessment_scan(self, Name=None):
    return AssessmentScan._delete_assessment_scan(connection=self,Name=Name)


  #
  #-----------------------------------------------------------------------------
  # DB Classification Scans
  #-----------------------------------------------------------------------------

  def get_classification_scan(self, Name=None):
    return ClassificationScan._get_classification_scan(connection=self, Name=Name)

  def get_all_classification_scan_das_objects(self):
    return ClassificationScan._get_all_classification_scans(connection=self)

  def create_classification_scan_das_object(self, Name=None, ProfileName=None, ApplyTo=[], Scheduling=None, update=False):
    return ClassificationScan._create_classification_scan(connection=self,Name=Name, ProfileName=ProfileName,
                                                  ApplyTo=ApplyTo, Scheduling=Scheduling, update=update)

  def update_classification_scan(self, Name=None, Parameter=None, Value=None):
    return ClassificationScan._update_classification_scan(connection=self, Name=Name, Parameter=Parameter, Value=Value)

  def delete_classification_scan(self, Name=None):
    return ClassificationScan._delete_classification_scan(connection=self,Name=Name)


  #
  #-----------------------------------------------------------------------------
  # DB Classification Profile
  #-----------------------------------------------------------------------------

  def get_classification_profile(self, Name=None):
    return ClassificationProfile._get_classification_profile(connection=self, Name=Name)

  def get_all_classification_profile_das_objects(self):
    return ClassificationProfile._get_all_classification_profiles(connection=self)

  def create_classification_profile_das_object(self, Name=None, SiteName=None, DataTypes=[], AutoAcceptResults=None,
                                    ScanViewsAndSynonyms=None, SaveSampleData=None, DataSampleAccuracy=None,
                                         ScanSystemSchemas=None, DbsAndSchemasUsage=None, DbsAndSchemas=[],
                                          ExcludeTablesAndColumns=[], DelayBetweenQueries=None,
                                         NumberOfConcurrentDbConnection=None, update=False):
    return ClassificationProfile._create_classification_profile(connection=self, Name=Name, SiteName=SiteName,
                                         DataTypes=DataTypes, AutoAcceptResults=AutoAcceptResults,
                                         ScanViewsAndSynonyms=ScanViewsAndSynonyms, SaveSampleData=SaveSampleData,
                                         DataSampleAccuracy=DataSampleAccuracy, ScanSystemSchemas=ScanSystemSchemas,
                                         DbsAndSchemasUsage=DbsAndSchemasUsage, DbsAndSchemas=DbsAndSchemas,
                                         ExcludeTablesAndColumns=ExcludeTablesAndColumns,
                                         DelayBetweenQueries=DelayBetweenQueries,
                                         NumberOfConcurrentDbConnection=NumberOfConcurrentDbConnection, update=update)


  def _update_classification_profile(self, Name=None, Parameter=None, Value=None):
    return ClassificationProfile._update_classification_profile(connection=self, Name=Name, Parameter=Parameter, Value=Value)

  def delete_classification_profile(self, Name=None):
    return ClassificationProfile._delete_classification_profile(connection=self, Name=Name)

  #
  # -----------------------------------------------------------------------------
  # Assessment Policies
  # -----------------------------------------------------------------------------
  #
  def get_all_assessment_policy_das_objects(self):
    return AssessmentPolicy._get_all_assessment_policies(connection=self)

  def get_assessment_policy(self, Name=None):
    return AssessmentPolicy._get_assessment_policy(connection=self, Name=Name)

  def create_assessment_policy_das_object(self, Name=None, Description=None, DbType=None, PolicyTags=[], AdcKeywords=[],
                               TestNames=[], update=False):
    return AssessmentPolicy._create_assessment_policy(connection=self, Name=Name, Description=Description,
                                                      DbType=DbType,
                                                      PolicyTags=PolicyTags, AdcKeywords=AdcKeywords,
                                                      TestNames=TestNames, update=update)

  # Assessment Tests
  # -----------------------------------------------------------------------------
  #
  def get_all_assessment_test_das_objects(self):
    return AssessmentTest._get_all_assessment_tests(connection=self)

  def get_assessment_test(self, Name=None):
    return AssessmentTest._get_assessment_test(connection=self, Name=Name)

  def create_assessment_test_das_object(self, Name=None, Description=None,
                                       Severity=None, Category=None, ScriptType=None, OsType=None, DbType=None,
                                       RecommendedFix=None,
                                       TestScript=None, AdditionalScript=None, ResultsLayout=[], update=False):
    return AssessmentTest._create_assessment_test(connection=self, Name=Name, Description=Description,
                                                  Severity=Severity, Category=Category, ScriptType=ScriptType,
                                                  OsType=OsType, DbType=DbType, RecommendedFix=RecommendedFix,
                                                  TestScript=TestScript, AdditionalScript=AdditionalScript,
                                                  ResultsLayout=ResultsLayout, update=update)

  #
  # -----------------------------------------------------------------------------
  # Discovery Scans
  # -----------------------------------------------------------------------------
  #
  def get_all_discovery_scan_das_objects(self):
    return DiscoveryScan._get_all_discovery_scans(connection=self)

  def get_discovery_scan(self, Name=None):
    return DiscoveryScan._get_discovery_scan(connection=self, Name=Name)

  def create_discovery_scan_das_object(self, Name=None, ExistingSiteName=None, AutoAccept=None,
                                         ScanExistingServerGroups=None, ScanIpGroup=None, IpGroups=[],
                                         ScanCloudAccount=None,
                                         CloudAccounts=[], ServiceTypes=[], ResolveDns=None, ResolveVersions=None,
                                         EnhancedScanning=None,
                                         DiscoveryTimeout=None, GlobalPortConfiguration=None,
                                         ServerGroupNamingTemplate=None,
                                         ServiceNamingTemplate=None, CredentialsEnabled=None, OsCredentials=[],
                                         DbCredentials=[],
                                         Scheduling=None, update=False):
    return DiscoveryScan._create_discovery_scan(connection=self, Name=Name, ExistingSiteName=ExistingSiteName,
                                                    AutoAccept=AutoAccept,
                                                    ScanExistingServerGroups=ScanExistingServerGroups,
                                                    ScanIpGroup=ScanIpGroup, IpGroups=IpGroups,
                                                    ScanCloudAccount=ScanCloudAccount,
                                                    CloudAccounts=CloudAccounts, ServiceTypes=ServiceTypes,
                                                    ResolveDns=ResolveDns, ResolveVersions=ResolveVersions,
                                                    EnhancedScanning=EnhancedScanning,
                                                    DiscoveryTimeout=DiscoveryTimeout,
                                                    GlobalPortConfiguration=GlobalPortConfiguration,
                                                    ServerGroupNamingTemplate=ServerGroupNamingTemplate,
                                                    ServiceNamingTemplate=ServiceNamingTemplate,
                                                    CredentialsEnabled=CredentialsEnabled, OsCredentials=OsCredentials,
                                                    DbCredentials=DbCredentials, Scheduling=Scheduling, update=update)

  def export_das_objects(self):
    """
    Export all the das objects in the MX

    :return a dictionary in a json like format
    """
    dasObjectsDict = {
      'metadata': {
        'Host': self.Host,
        'Version': self.Version,
        'Challenge': self.Challenge,
        'SdkVersion': imperva_sdk_version(),
        'ExportTime': time.strftime("%Y-%m-%d %H:%M:%S")
      }
    }
    dasObjectsDict.update(self._export_objects_to_dict('objects', 'das'))
    return json.dumps(dasObjectsDict)

  def import_das_objects(self, Json=None, update=True):
    """
    Import only the das objects from valid JSON string.
    :param Json (string): valid imperva_sdk JSON export
    :param update (boolean): Set to `True` to update existing resources (default in import function).
                             If set to `False`, existing resources will cause import operations to fail.
    :return: (list of dict) Log with details of all import events and their outcome.
    """
    return self._import_object_from_json(Json=Json, ObjectType='objects', Context='das', Type='object', update=update)

  # ====================================== END DAS Objects ==============================================

  #-----------------------------------------------------------------------------
  # Tags
  #-----------------------------------------------------------------------------

  def get_all_tags(self):
    return Tag._get_all_tags(connection=self)

  def create_tag(self, Name=None, update=False):
    return Tag._create_tag(connection=self, Name=Name)


  def _upload_adc_content(self, path):
    adc_uploader = ADCUploader(self)
    status = adc_uploader.upload_adc_and_wait(path)
    return True if status['success'] == 'true' else False

  # Internal function to return MX API swagger JSON
  def _get_mx_swagger(self):
    return self._mx_api('GET', '/internal/swagger', ApiVersion="experimental")


  # ====================================== DAM reports ==================================================

  #
  # -----------------------------------------------------------------------------
  # Agent configuration
  # -----------------------------------------------------------------------------

  def get_all_agent_configurations(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.AgentConfiguration.AgentConfiguration`
    :return: List of all agent configurations.
    '''
    return AgentConfiguration._get_all_agent_configurations(connection=self)

  def get_agent_configuration(self, Name, Ip=None):
    '''
    :type Name: string
    :param Name: Agent Name
    :rtype: imperva_sdk.AgentConfiguration.AgentConfiguration
    :return: AgentConfiguration instance.
    '''
    return AgentConfiguration._get_agent_configuration_by_name(connection=self, Name=Name, Ip=Ip)


  def create_agent_configuration(self, Name=None, Ip=None, DataInterfaces=[], Tags=[], AdvancedConfig={},
                                 DiscoverySettings={}, CpuUsageRestraining={}, GeneralDetails={}, update=False):
    """

    :param Name (string): agent's name
    :param Ip (string): agent's IP
    :param DataInterfaces (list): agent's data interfaces
    :param Tags (list): agent's tags
    :param AdvancedConfig (dict): agent's advanced configuration
    :param DiscoverySettings (dict): agent's discovery settings
    :param CpuUsageRestraining (dict): agent's cpu usage restraining
    :param GeneralDetails (dict): agent's additional general details
    :param update: If `update=True` and the data set already exists, update and return the existing data set.
                  If `update=False` (default) and the data set exists, an exception will be raised.
    :return: AgentConfiguration instance
    """
    return AgentConfiguration._create_agent_configuration(connection=self,
                                                          Name=Name,
                                                          Ip=Ip,
                                                          DataInterfaces=DataInterfaces,
                                                          Tags=Tags,
                                                          AdvancedConfig=AdvancedConfig,
                                                          DiscoverySettings=DiscoverySettings,
                                                          CpuUsageRestraining=CpuUsageRestraining,
                                                          GeneralDetails=GeneralDetails,
                                                          update=update)


  def _update_agent_configuration(self, Name=None, Parameter=None, Value=None):
    """

    :param Name: Agent name (string)
    :param Parameter: The parameter in the agent configuration need to be updated (string)
    :param Value: The value of the parameter
    :return: True on success or exception on failure
    """
    return AgentConfiguration._update_agent_configuration(connection=self, Name=Name, Parameter=Parameter, Value=Value)


  def _export_agents_configuration(self):
    agentConfigDict = {
      'metadata': {
        'Host': self.Host,
        'Version': self.Version,
        'Challenge': self.Challenge,
        'SdkVersion': imperva_sdk_version(),
        'ExportTime': time.strftime("%Y-%m-%d %H:%M:%S")
      }
    }

    agentConfigDict['agent_configurations'] = []
    try:
      agents_config = self.get_all_agent_configurations()
      for agent in agents_config:
        as_dict = dict(agent)
        agentConfigDict['agent_configurations'].append(as_dict)
    except:
      # Previous versions didn't have action set APIs
      pass

    return agentConfigDict


  def export_agent_configurations(self):
    """
    Export all agents configurations in the MX

    >>> specificExport = srcMx.export_agents_configuration()
    >>> pSpecificExport = json.loads(specificExport)

    :return json object
    """
    return json.dumps(self._export_agents_configuration())


  def import_agent_configurations(self, Json=None, update=True):
    """
    Import all the agent configuration from valid JSON string.

    >>> targetMx.import_agent_configurations(specificExport)

    :param Json (string): valid imperva_sdk JSON export
    :param update (boolean): Set to `True` to update existing resources (default in import function).
                             If set to `False`, existing resources will cause import operations to fail.
    :return: (list of dict) Log with details of all import events and their outcome.
    """
    try:
      json_config = json.loads(Json)
    except:
      raise MxException("Invalid JSON configuration")

    return self._create_tree_from_json(Dict={'agent_configurations': json_config['agent_configurations']},
                                       ParentObject=self, update=update)

  # ====================================== DAM reports ==================================================

  #-----------------------------------------------------------------------------
  # DB audit report
  #-----------------------------------------------------------------------------

  def get_all_db_audit_dam_reports(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.DBAuditReport.DBAuditReport`
    :return: List of all db audit reports.
    '''
    return DBAuditReport._get_all_db_audit_reports(connection=self)

  def get_db_audit_report(self, Name):
    '''
    :type Name: string
    :param Name: The report Name
    :rtype: imperva_sdk.DBAuditReport.DBAuditReport
    :return: DBAuditReport instance of specified report.
    '''
    return DBAuditReport._get_db_audit_report_by_name(connection=self, Name=Name)

  def _update_db_audit_report(self, Name=None, Parameter=None, Value=None):
    """

    :param Name: The report name (string)
    :param Parameter: The parameter in the report need to update (string)
    :param Value: The value of the parameter
    :return: True on success or exception on failure
    """
    return DBAuditReport._update_db_audit_report(connection=self, Name=Name, Parameter=Parameter, Value=Value)

  def create_db_audit_dam_report(self, Name=None, ReportFormat=None, ReportId = None, Columns=[],
                                 Filters=[], Policies=[],  Sorting=[], TimeFrame={}, Scheduling=[], update=False):
    """

    :param Name: The report name (string)
    :param ReportFormat: The format of the report (string)
    :param ReportId: The ID of the report (string)
    :param Columns: A list of columns in the report (list)
    :param Filters: The filters applied to the report (list)
    :param Policies: The policies applied to the report (list)
    :param Sorting: The sorting criterion (list)
    :param TimeFrame: The time frame of the report (dict)
    :param Scheduling: The scheduling to determine the time the report will run
    :param update: If `update=True` and the report already exists, update and return the existing report.
                   If `update=False` (default) and the report exists, an exception will be raised.
    :return: DBAuditReport instance
    """
    return DBAuditReport._create_db_audit_report(connection=self,
                                                 Name=Name,
                                                 ReportFormat=ReportFormat,
                                                 ReportId=ReportId,
                                                 Columns=Columns,
                                                 Filters=Filters,
                                                 Policies=Policies,
                                                 Sorting=Sorting,
                                                 TimeFrame=TimeFrame,
                                                 Scheduling=Scheduling,
                                                 update=update)

  def export_dam_reports(self):
    """
    Export all the dam reports in the MX

    :return a dictionary in a json like format
    """
    globalObjectsDict = {
      'metadata': {
        'Host': self.Host,
        'Version': self.Version,
        'Challenge': self.Challenge,
        'SdkVersion': imperva_sdk_version(),
        'ExportTime': time.strftime("%Y-%m-%d %H:%M:%S")
      }
    }
    globalObjectsDict.update(self._export_objects_to_dict('reports', 'dam'))
    return json.dumps(globalObjectsDict)

  def import_dam_reports(self, Json=None, update=True):
    """
    Import only the dam reports from valid JSON string.
    :param Json (string): valid imperva_sdk JSON export
    :param update (boolean): Set to `True` to update existing resources (default in import function).
                             If set to `False`, existing resources will cause import operations to fail.
    :return: (list of dict) Log with details of all import events and their outcome.
    """
    return self._import_object_from_json(Json, 'reports', 'dam', 'report', update)

  # ====================================== END DAM reports ==================================================

  # ====================================== DAM GLOBAL OBJECTS ===============================================

  #
  # -----------------------------------------------------------------------------
  # Cloud Accounts
  # -----------------------------------------------------------------------------
  #
  def get_all_cloud_account_dam_global_objects(self):
    return CloudAccount._get_all_cloud_accounts(connection=self)

  def get_cloud_account(self, Name=None):
    return CloudAccount._get_cloud_account(connection=self, Name=Name)

  def create_cloud_account_dam_global_object(self, Name=None, PrivateKey=None, AccessKey=None, AwsRegion=None,
                                               AzureTenant=None, CloudProvider=None, update=False):
    return CloudAccount._create_cloud_account(connection=self, Name=Name, PrivateKey=PrivateKey,
                                                  AccessKey=AccessKey,
                                                  AwsRegion=AwsRegion, AzureTenant=AzureTenant,
                                                  CloudProvider=CloudProvider,
                                                  update=update)

  #
  # -----------------------------------------------------------------------------
  # Ip Group
  # -----------------------------------------------------------------------------
  #
  def get_all_ip_group_dam_global_objects(self):
    return IpGroup._get_all_ip_groups(connection=self)

  def get_ip_group(self, Name=None):
    return IpGroup._get_ip_group(connection=self, Name=Name)

  def create_ip_group_dam_global_object(self, Name=None, Entries=[], update=False):
    return IpGroup._create_ip_group(connection=self, Name=Name, Entries=Entries, update=update)

  #
  # -----------------------------------------------------------------------------
  # Table Groups
  # -----------------------------------------------------------------------------
  #

  def get_all_table_group_dam_global_objects(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.TableGroup.TableGroup`
    :return: List of all table groups.
    '''
    return TableGroup._get_all_table_groups(connection=self)


  def get_table_group(self, Name, IsSensitive=None, ServiceTypes=[]):
    """
    :param Name: Table group name (string)
    :param IsSensitive: Is the table group sesitive (boolean)
    :param ServiceTypes: a list of the servie types (list)
    :return: TableGroup instance of specified table group.
    """
    return TableGroup._get_table_group_by_name(connection=self, Name=Name, IsSensitive=IsSensitive,
                                               ServiceTypes=ServiceTypes)

  def create_table_group_dam_global_object(self, Name=None, IsSensitive=None, DataType=None, ServiceTypes=[], Records=[],
                                            update=False):
    """
    :param Name: Table group name (string)
    :param IsSensitive: Is the table group sesitive (boolean)
    :param DataType: the data type of the table group (string)
    :param ServiceTypes: a list of the servie types (list)
    :param Records: a list of records (list)
    :param update: update: If `update=True` and the resource already exists, update and return the existing resource.
                  If `update=False` (default) and the resource exists, an exception will be raised.
    :return: TableGroup instance
    """
    return TableGroup._create_table_group(connection=self, Name=Name, IsSensitive=IsSensitive, DataType=DataType,
                                          ServiceTypes=ServiceTypes, Records=Records, update=update)

  def _update_table_group(self, Name=None, Parameter=None, Value=None):
    """
    :param Name: Table group name (string)
    :param Parameter: The parameter in the table needed to be updated (string)
    :param Value: The value of the parameter
    :return: True on success or exception on failure
    """
    return TableGroup._update_table_group(connection=self, Name=Name, Parameter=Parameter, Value=Value)

  #
  # -----------------------------------------------------------------------------
  # Lookup data sets
  # -----------------------------------------------------------------------------
  #

  def get_all_lookup_data_set_dam_global_objects(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.LookupDataSet.LookupDataSet`
    :return: List of all lookup data sets.
    '''
    return LookupDataSet._get_all_lookup_data_set(connection=self)

  def get_lookup_data_set(self, Name):
    '''
    :type Name: string
    :param Name: data set Name
    :rtype: imperva_sdk.LookupDataSet.LookupDataSet
    :return: LookupDataSet instance of specified data set.
    '''
    return LookupDataSet._get_lookup_data_set_by_name(connection=self, Name=Name)

  def _update_lookup_data_set(self, Name=None, Parameter=None, Value=None):
    """

    :param Name: Data set name (string)
    :param Parameter: The parameter to update (string)
    :param Value: The value of the parameter to update
    :return: True on success or exception on failure
    """
    return LookupDataSet._update_lookup_data_set(connection=self, Name=Name, Parameter=Parameter, Value=Value)

  def create_lookup_data_set_dam_global_object(self, Name=None, Records=[], Columns=[], update=False):
    """

    :param Name: Data set name (string)
    :param Records: The records in the data set
    :param Columns: the columns of the data set
    :param update: If `update=True` and the data set already exists, update and return the existing data set.
                  If `update=False` (default) and the data set exists, an exception will be raised.
    :return:  LookupDataSet instance
    """
    return LookupDataSet._create_lookup_data_set(connection=self, Name=Name, Records=Records, Columns=Columns, update=update)

  #
  # -----------------------------------------------------------------------------
  # Agent Monitoring Rules
  # -----------------------------------------------------------------------------
  #

  def get_all_agent_monitoring_rule_dam_global_objects(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.AgentMonitoringRule.AgentMonitoringRule`
    :return: List of all agent monitoring rules.
    '''
    return AgentMonitoringRule._get_all_agent_monitoring_rules(connection=self)

  def get_all_agent_monitoring_rules_by_agent(self, AgentName=None, AgentTags=[]):
    '''

    :param AgentName: Agent name
    :param AgentTags: list of all the agent's tags
    :return: List of AgentMonitoringRule objects that belong to the agent
    '''
    return AgentMonitoringRule._get_all_agent_monitoring_rules_by_agent(connection=self, AgentName=AgentName, AgentTags=AgentTags)

  def get_agent_monitoring_rule(self, Name):
    '''
    :type Name: string
    :param Name: Rule Name
    :rtype: imperva_sdk.AgentMonitoringRule.AgentMonitoringRule
    :return: AgentMonitoringRule instance of specified policy.
    '''
    return AgentMonitoringRule._get_agent_monitoring_rules_by_name(connection=self, Name=Name)

  def _update_agent_monitoring_rule(self, Name=None, Parameter=None, Value=None):
    """
    :param Name: Rule name (string)
    :param Parameter: The parameter in the rule need to update (string)
    :param Value: The value of the parameter
    :return: True on success or exception on failure
    """
    return AgentMonitoringRule._update_agent_monitoring_rule(connection=self, Name=Name, Parameter=Parameter, Value=Value)

  def create_agent_monitoring_rule_dam_global_object(self, Name=None, PolicyType=None, Action=None, CustomPredicates=[],
                                                     ApplyToAgent=[], ApplyToTag=[], update=False):
    """
    :param Name: Rule name (string)
    :param PolicyType: The type of the policy (string)
    :param Action: The followed action of the rule (string)
    :param CustomPredicates: Policy Match Criteria in API JSON format
    :param ApplyToAgent: Agents that rule is applied to, in API JSON format
    :param ApplyToTag: Tags that rule is applied to, in API JSON format
    :param update: If `update=True` and the resource already exists, update and return the existing resource.
                  If `update=False` (default) and the resource exists, an exception will be raised.
    :return:  AgentMonitoringRule instance
    """
    return AgentMonitoringRule._create_agent_monitoring_rule(connection=self,
                                                             Name=Name,
                                                             PolicyType=PolicyType,
                                                             Action=Action,
                                                             CustomPredicates=CustomPredicates,
                                                             ApplyToAgent=ApplyToAgent,
                                                             ApplyToTag=ApplyToTag,
                                                             update=update)

  #
  #-----------------------------------------------------------------------------
  #           Data type
  #-----------------------------------------------------------------------------

  def get_all_data_type_dam_global_objects(self):
    '''
    :rtype: `list` of :obj:`imperva_sdk.DataType.DataType`
    :return: List of all data types.
    '''
    return DataType._get_all_data_type(connection=self)

  def get_data_type(self, Name):
    '''
    :type Name: string
    :param Name: data type Name
    :rtype: imperva_sdk.DataType.DataType
    :return: DataType instance of specified data type.
    '''
    return DataType._get_data_type_by_name(connection=self, Name=Name)

  def create_data_type_dam_global_object(self, Name=None, IsSensitive=True, Rules=[], TargetTableGroupName=None,
                                         update=False):
    """
    :param Name: Data type name (string)
    :param IsSensitive: True if data type is sensitive (boolean)
    :param Rules: the rules of the data type (list)
    :param TargetTableGroupName: The name of the target table group (string)
    :param update: If `update=True` and the data type already exists, update and return the existing data type.
                  If `update=False` (default) and the data type exists, an exception will be raised.
    :return:  DataType instance
    """
    return DataType._create_data_type(connection=self, Name=Name, IsSensitive=IsSensitive, Rules=Rules,
                                      TargetTableGroupName=TargetTableGroupName, update=update)

  def _update_data_type(self, Name=None, Parameter=None, Value=None):
    """

    :param Name: Data type name (string)
    :param Parameter: The parameter to update (string)
    :param Value: The value of the parameter to update
    :return: True on success or exception on failure
    """
    return DataType._update_data_type(connection=self, Name=Name, Parameter=Parameter, Value=Value)



  def export_dam_global_objects(self):
    """
    Export all the dam global objects in the MX
    :return a dictionary in a json like format
    """
    globalObjectsDict = {
      'metadata': {
        'Host': self.Host,
        'Version': self.Version,
        'Challenge': self.Challenge,
        'SdkVersion': imperva_sdk_version(),
        'ExportTime': time.strftime("%Y-%m-%d %H:%M:%S")
      }
    }
    globalObjectsDict.update(self._export_objects_to_dict('global_objects', 'dam'))
    return json.dumps(globalObjectsDict)

  def import_dam_global_objects(self, Json=None, update=True):
    """
    Import only the dam global objects configuration from valid JSON string.
    :param Json (string): valid imperva_sdk JSON export
    :param update (boolean): Set to `True` to update existing resources (default in import function).
                             If set to `False`, existing resources will cause import operations to fail.
    :return: (list of dict) Log with details of all import events and their outcome.
    """
    return self._import_object_from_json(Json, 'global_objects', 'dam', 'global_object', update)

  # ==================================== END DAM GLOBAL OBJECTS ================================================

  def get_all_dam_policies_types(self):
    ''' Returns all DAM available policies types '''
    types = []
    for cur_item in dir(self):
      if cur_item.startswith('get_all') and cur_item.endswith('_dam_policies'):
        types.append(cur_item.replace('get_all_','').replace('_dam_policies',''))
    return types

  def get_all_dam_reports_types(self):
    ''' Returns all available DAM report types '''
    types = []
    for cur_item in dir(self):
      if cur_item.startswith('get_all_') and cur_item.endswith('_dam_reports'):
        types.append(cur_item.replace('get_all_','').replace('_dam_reports',''))
    return types

  def get_all_dam_global_objects_types(self):
    ''' Returns all DAM available global_object types '''
    types = []
    for cur_item in dir(self):
      if cur_item.startswith('get_all') and cur_item.endswith('_dam_global_objects') and cur_item != 'get_all_global_objects':
        types.append(cur_item.replace('get_all_','').replace('_dam_global_objects',''))
    return types

  def get_all_das_objects_types(self):
    ''' Returns all available DAS object types '''
    types = []
    for cur_item in dir(self):
      if cur_item.startswith('get_all_') and cur_item.endswith('_das_objects') and cur_item != 'get_all_das_objects_types':
        types.append(cur_item.replace('get_all_','').replace('_das_objects',''))
    return types

  def get_all_global_object_types(self):
    ''' Returns all available global_object types '''
    types = []
    for cur_item in dir(self):
      if cur_item.startswith('get_all_') and cur_item.endswith('_global_objects') and cur_item != 'get_all_global_objects':
        types.append(cur_item.replace('get_all_','').replace('_global_objects',''))
    return types

  def get_all_global_objects(self):
    ''' Returns all global objects by type '''
    global_objects = {}
    for object_type in self.get_all_global_object_types():
      get_func = getattr(self, 'get_all_' + object_type + '_global_objects')
      global_objects[object_type] = get_func()
    return global_objects

  def get_all_policy_types(self):
    ''' Returns all available policy types '''
    policy_types = []
    for cur_item in dir(self):
      if cur_item.startswith('get_all_') and cur_item.endswith('_policies') and cur_item != 'get_all_policies':
        policy_types.append(cur_item.replace('get_all_','').replace('_policies',''))
    return policy_types

  def get_all_policies(self):
    ''' Returns all policy objects by policy type '''
    policies = {}
    for policy_type in self.get_all_policy_types():
      get_func = getattr(self, 'get_all_' + policy_type + '_policies')
      policies[policy_type] = get_func()
    return policies

  def upload_license(self, LicenseContent=None, LicenseFile=None, LicenseURL=None):
    '''
    Upload a license file to the system (specify one of the three formats).

    >>> mx.upload_license(LicenseFile='/etc/passwd')
    ...
    imperva_sdk.MxException: MX returned errors - [{u'error-code': u'IMP-12101', u'description': u'Invalid license file'}]

    :type LicenseContent: string
    :param LicenseContent: License file encoded in Base64
    :type LicenseFile: string
    :param LicenseFile: Path to license file on local system
    :type LicenseURL: string
    :param LicenseURL: Accessible URL to download license file from
    '''
    if LicenseURL:
      if LicenseFile or LicenseContent:
        raise MxException("Must provide only 1 license parameter (Content, File or URL)")
      try:
        response = requests.get(LicenseURL, verify=False, timeout=ConnectionTimeout)
        lic_data = response.text
        LicenseContent = base64.b64encode(lic_data.encode('utf-8')).decode('utf-8')
      except:
        raise MxException("Failed getting license file from '%s'" % LicenseURL)
    elif LicenseFile:
      if LicenseURL or LicenseContent:
        raise MxException("Must provide only 1 license parameter (Content, File or URL)")
      try:
        with open(LicenseFile, 'r') as fd:
          lic_data = fd.read()
          LicenseContent = base64.b64encode(lic_data.encode('utf-8')).decode('utf-8')
      except:
        raise MxException("Failed reading license file '%s'" % LicenseFile)
    if not LicenseContent:
      raise MxException("No license content provided")
    body = { 'licenseContent': LicenseContent }
    self._mx_api('POST', '/administration/license', timeout=1800, data=json.dumps(body))
    return True

  def _export_objects_to_dict(self, object_type, context):
    """
    Export all the objects from type 'object_type' in the correct context within the MX

    :param object_type (string)- the object types name we want to export. For example, 'global_objects'
    :param context (string)- the context of the objects. For example, 'dam', 'waf' etc.
    :return a dictionary in a json like format
    """
    json_like_obj = {}
    full_object_name = context + '_' + object_type
    json_like_obj[full_object_name] = {}
    try:
      object_types_fun = getattr(self, 'get_all_' + context + '_' + object_type + '_' + 'types')
      inner_object_types = object_types_fun()
    except:
      return
    for type in inner_object_types:
      json_like_obj[full_object_name][type] = []
      try:
        get_pol_func = getattr(self, 'get_all_' + type + '_' + full_object_name)
        objects = get_pol_func()
        for cur_object in objects:
          obj_dict = dict(cur_object)
          json_like_obj[full_object_name][type].append(obj_dict)
      except Exception as e:
        # Some versions don't have all Object APIs
        pass

    return json_like_obj


  def export_to_json(self, Discard=[]):
    '''
    Export MX configuration to a JSON string.

    .. note:: The function only exports objects that are implemented in imperva_sdk. It is not the entire MX configuration.

    >>> import pprint
    >>> import json
    >>> export = mx.export_to_json(Dicard=['policies'])
    >>> pprint.pprint(json.loads(export))
    {u'metadata': {u'Challenge': u'k+hvfY+Vgv8a',
                   u'ExportTime': u'2017-04-12 13:39:10',
                   u'Host': u'10.0.0.1',
                   u'SdkVersion': u'0.1.4',
                   u'Version': u'12.0.0.41'},
     u'policies': {},
     u'sites': [{u'Name': u'site name',
                 u'server_groups': [{u'Name': u'server group name',
                                     u'OperationMode': u'simulation',
                                     u'web_services': [{u'ForwardedClientIp': {u'forwardClientIP': True,
                                                                               u'forwardHeaderName': u'X-Forwarded-For'},
                                                        u'ForwardedConnections': {u'forwardedConnections': [{u'headerName': u'X-Forwarded-For',
                                                                                                             u'proxyIpGroup': u''}],
                                                                                  u'useHttpForwardingHeader': True},
                                                        u'Name': u'advanced web service',
                                                        u'Ports': [8080],
                                                        u'SslKeys': [{u'certificate': u'',
                                                                      u'format': u'pem',
                                                                      u'hsm': False,
                                                                      u'password': u'',
                                                                      u'private': u'',
                                                                      u'sslKeyName': u'key name'}],
                                                        u'SslPorts': [8443],
                                                        u'krp_rules': [{u'Alias': u'aa',
                                                                        u'ClientAuthenticationAuthorities': None,
                                                                        u'GatewayGroup': u'giora-tmp2',
                                                                        u'GatewayPorts': [8443],
                                                                        u'Name': u'giora-tmp2-aa-[8443]',
                                                                        u'OutboundRules': [{u'clientAuthenticationRules': None,
                                                                                            u'encrypt': False,
                                                                                            u'externalHost': None,
                                                                                            u'internalIpHost': u'1.2.3.4',
                                                                                            u'priority': 1,
                                                                                            u'serverPort': 443,
                                                                                            u'urlPrefix': None,
                                                                                            u'validateServerCertificate': False}],
                                                                        u'ServerCertificate': u'key name'}],
                                                        u'web_applications': [{u'IgnoreUrlsDirectories': None,
                                                                               u'LearnSettings': u'LearnAll',
                                                                               u'Name': u'Default Web Application',
                                                                               u'ParseOcspRequests': False,
                                                                               u'RestrictMonitoringToUrls': None}]},
                                                       {u'ForwardedClientIp': {u'forwardClientIP': False,
                                                                               u'forwardHeaderName': u'X-Forwarded-For'},
                                                        u'ForwardedConnections': {u'forwardedConnections': [],
                                                                                  u'useHttpForwardingHeader': False},
                                                        u'Name': u'simple web service',
                                                        u'Ports': [80],
                                                        u'SslKeys': [],
                                                        u'SslPorts': [443],
                                                        u'krp_rules': [],
                                                        u'web_applications': [{u'IgnoreUrlsDirectories': None,
                                                                               u'LearnSettings': u'LearnAll',
                                                                               u'Name': u'Default Web Application',
                                                                               u'ParseOcspRequests': False,
                                                                               u'RestrictMonitoringToUrls': None}]}]}]}]}
    
    :type Discard: list of string
    :param Discard: Objects or attributes to discard from export. For example, you can choose not to export all policy information by passing `['policies']` or only discard certain attributes of policy objects by passing `['MatchCriteria', 'ApplyTo']`
    :rtype: JSON string
    :return: string in JSON format representing MX configuration export (and can be used by :py:meth:`imperva_sdk.MxConnection.import_from_json` function)
    
    '''
    def dict_discard(d, Discard=[]):
      for k in d.keys():
        if k in Discard:
          del d[k]
          continue
        if isinstance(d[k], dict):
          dict_discard(d[k], Discard)
        elif isinstance(d[k], list):
          for v in d[k]:
            if isinstance(v, dict):
              dict_discard(v, Discard)

    tmp_json = {
      'metadata': {
        'Host': self.Host,
        'Version': self.Version,
        'Challenge': self.Challenge,
        'SdkVersion': imperva_sdk_version(),
        'ExportTime': time.strftime("%Y-%m-%d %H:%M:%S")
      }
    }
    tmp_json['sites'] = []
    if 'sites' not in Discard:
      sites = self.get_all_sites()
      for site in sites:
        site_dict = dict(site)
        dict_discard(site_dict, Discard)
        tmp_json['sites'].append(site_dict)

    tmp_json['action_sets'] = {}
    if 'action_sets' not in Discard:
      res = self._export_action_sets()
      tmp_json['action_sets'] = res['action_sets']

    tmp_json['policies'] = {}
    if 'policies' not in Discard:
      policy_types = self.get_all_policy_types()
      for policy_type in policy_types:
        tmp_json['policies'][policy_type] = []
        if policy_type not in Discard:
          try:
            get_pol_func = getattr(self, 'get_all_' + policy_type + '_policies')
            policies = get_pol_func()
            for cur_policy in policies:
              pol_dict = dict(cur_policy)
              dict_discard(pol_dict, Discard)
              tmp_json['policies'][policy_type].append(pol_dict)
          except:
            # Some versions don't have all policy APIs
            pass
    tmp_json['global_objects'] = {}
    if 'global_objects' not in Discard:
      object_types = self.get_all_global_object_types()
      for object_type in object_types:
        tmp_json['global_objects'][object_type] = []
        if object_type not in Discard:
          try:
            get_pol_func = getattr(self, 'get_all_' + object_type + '_global_objects')
            objects = get_pol_func()
            for cur_object in objects:
              obj_dict = dict(cur_object)
              dict_discard(obj_dict, Discard)
              tmp_json['global_objects'][object_type].append(obj_dict)
          except:
            # Some versions don't have all Global Object APIs
            pass

    tmp_json['dam_reports'] = {}
    if 'reports' not in Discard:
      res = self._export_objects_to_dict('reports', 'dam')
      tmp_json['dam_reports'].update(res['dam_reports'])

    tmp_json['das_objects'] = {}
    if 'das' not in Discard:
      res = self._export_objects_to_dict('objects', 'das')
      tmp_json['das_objects'].update(res['das_objects'])

    # format and sort output json to allow easy comparison
    return json.dumps(tmp_json, indent=4, sort_keys=True, separators=(',', ': '))

  def _import_object_from_json(self, Json=None, ObjectType=None, Context=None, Type=None, update=True):
    """
    Import a specific MX object type configuration from valid JSON string.
    note: The function only imports objects that are implemented in imperva_sdk. It is not the entire MX configuration.
    """
    try:
      json_config = json.loads(Json)
    except:
      raise MxException("Invalid JSON configuration")

    full_object_name = Context + '_' + ObjectType
    return self._create_objects_from_json(Objects=json_config[full_object_name], Type= Context+'_'+Type, update=update)

  def import_from_json(self, Json=None, update=True):
    '''
    Import MX configuration from valid JSON string. It is a good idea to use :py:meth:`imperva_sdk.MxConnection.export_to_json` as the basis for creating the JSON structure.

    .. note:: The function only imports objects that are implemented in imperva_sdk. It is not the entire MX configuration.

    >>> # Copy site tree (without policies) from one MX to another
    >>> mx1 = imperva_sdk.MxConnection("10.0.0.1")
    >>> mx2 = imperva_sdk.MxConnection("10.0.0.2")
    >>> export = mx1.export_to_json(Discard=['policies'])
    >>> log = mx2.import_from_json(export)
    >>> log[0]
    {'Function': 'create_site', 'Parent': '<imperva_sdk.MxConnection object at 0x27ff510>', 'Parameters': u'Name=Default Site', 'Result': 'SUCCESS'}


    :type Json: string 
    :param Json: valid imperva_sdk JSON export
    :type update: boolean
    :param update: Set to `True` to update existing resources (default in import function). If set to `False`, existing resources will cause import operations to fail.
    :rtype: list of dict
    :return: Log with details of all import events and their outcome.
    '''
    try:
      json_config = json.loads(Json)
      imperva_sdk_version = json_config['metadata']['SdkVersion']
    except:
      raise MxException("Invalid JSON configuration")

    log = self._create_objects_from_json(Objects=json_config['global_objects'], Type="global_object", update=update)
    log += self._create_tree_from_json(Dict={'sites': json_config['sites']}, ParentObject=self, update=update)
    log += self._create_tree_from_json(Dict={'action_sets': json_config['action_sets']}, ParentObject=self, update=update)
    log += self._create_objects_from_json(Objects=json_config['policies'], Type="policy", update=update)
    log += self.import_dam_reports(Json)
    log += self.import_das_objects(Json)

    return log

  def _create_objects_from_json(self, Objects=None, Type=None, update=True):
    log = []
    for object_type in Objects:
      create_name = 'create_' + object_type
      if Type:
        create_name += '_' + Type

      create_function = getattr(self, create_name)
      for cur_object in Objects[object_type]:
        log_entry = {
          'Function': create_name,
          'Object Name': cur_object['Name']
        }
        try:
          cur_object['update'] = update
          create_function(**cur_object)
          log_entry['Result'] = "SUCCESS"
        except Exception as e:
          log_entry['Result'] = "ERROR"
          log_entry['Error Message'] = str(e)
        log.append(log_entry)
    return log

  def _create_tree_from_json(self, Dict=None, ParentObject=None, update=True):
    log = []
    for object_type in Dict:
      for cur_object in Dict[object_type]:
        parent_object_parameters = {}
        child_objects = {}
        for field in cur_object:
          if is_parameter.match(field):
            parent_object_parameters[field] = cur_object[field]
          else:
            child_objects[field] = cur_object[field]
        parent_object = None
        log_entry = {
          'Function': "create_" + object_type[:-1],
          'Parameters': ",".join(["%s=%s" % (x, parent_object_parameters[x]) for x in parent_object_parameters]),
          'Parent': str(ParentObject)
        }
        try:
          create_function = getattr(ParentObject, "create_" + object_type[:-1])
          parent_object_parameters['update'] = update

          parent_object = create_function(**parent_object_parameters)
          log_entry['Result'] = "SUCCESS"
        except Exception as e:
          log_entry['Result'] = "ERROR"
          log_entry['Error Message'] = str(e)
        log.append(log_entry)

        log += self._create_tree_from_json(child_objects, parent_object)

        #-----------------------------------------------------------------------
        # Unfortunately, there are cases in which you must update the created
        # object after creating the children. One such case is a DB service in
        # the case that there are multiple applications. The applications are
        # not recognized when the service is created. Therefore, the creation
        # has to be split into two parts. The regular name is for pre-children
        # and there's a create_db_service_pc (post_children) function for after
        # the children are created.
        # We are using the same parameters so we don't need to change the list
        # of parameters that we created above
        #-----------------------------------------------------------------------

        funcname = "create_" + object_type[:-1] + "_pc"
        if funcname in dir(ParentObject):
          try:
            log_entry['Function'] = funcname
            create_function = getattr(ParentObject, funcname)
            parent_object = create_function(**parent_object_parameters)
            log_entry['Result'] = "SUCCESS"
          except Exception as e:
            log_entry['Result'] = "ERROR"
            log_entry['Error Message'] = str(e)
          log.append(log_entry)

    return log

  def _get_mx_proxy_settings(self):
    '''
    Gets 'External HTTP Settings' from 'System Definitions'

    :rtype: JSON string
    :return: External HTTP Settings

    '''
    response = self._mx_api('GET', '/conf/systemDefinitions/httpProxy')

    if 'useProxy' in response:
      return response
    else:
      return None

  def _set_mx_proxy_settings(self, UseProxy=None, Host=None, Port=None, User=None, Password=None, AuthPolicy='Basic', Domain=None):
    '''
    Sets 'External HTTP Settings' in 'System Definitions'

    :type UseProxy: boolean
    :param UseProxy: If UpdateProxy=True the MX will use proxy to access Imperva services
    :type Host: String
    :param Host: Hostname or IP of the proxy server
    :type Port: String
    :param Port: Port number of the proxy server
    :type User: String
    :param User: Username for authentication with the proxy server
    :type Password: String
    :param Password: Password of the user used for authentication with the proxy server
    :type AuthPolicy: String
    :param AuthPolicy: Type of Authentication (Basic, Digest, NTLM)
    :type Domain: String
    :param Domain: Domain name for use with NTLM authentication only

    '''
    body = {
      'useProxy': UseProxy,
      'host': Host,
      'port': Port,
      'user': User,
      'password': Password,
      'authPolicy': AuthPolicy,
      'domain': Domain
    }

    self._mx_api('PUT', '/conf/systemDefinitions/httpProxy', data=json.dumps(body))

    return True
