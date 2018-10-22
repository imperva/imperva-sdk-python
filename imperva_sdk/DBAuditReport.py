# Copyright 2018 Imperva. All rights reserved.

from imperva_sdk.core import *
import json

class DBAuditReport(MxObject):
  '''
   MX DB audit report Class

   >>> report = mx.get_db_audit_report("testReport")
   >>> report.ReportFormat
   'pdf'
   >>> report.Scheduling
   {'once': {'at-date': '2018-12-21', 'at-time': '00:45:00'}, 'occurs': 'once'}
   >>> # Create user defined copy of report
   >>> report_dict = dict(report)
   >>> report_dict['Name'] = 'user defined - %s' % report_dict['Name']
   >>> mx.create_db_audit_report(**report_dict)
   <imperva_sdk 'DBAuditReport' Object - 'user defined - testReport'>

   '''

  # Store created Policy objects in_instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = DBAuditReport._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj
  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'DBAuditReport':
        if cur_obj.Name == Name:
          return cur_obj
    return None

  def __init__(self, connection=None, Name=None, ReportFormat=None, ReportId = None, Columns=[],
               Filters=[], Policies=[],  Sorting=[], TimeFrame=[], Scheduling={}):
    super(DBAuditReport, self).__init__(connection=connection, Name=Name)
    self._ReportFormat = ReportFormat
    self._ReportId = ReportId
    self._Columns = MxList(Columns)
    self._Filters = MxList(Filters)
    self._Policies = MxList(Policies)
    self._Sorting = MxList(Sorting)
    self._TimeFrame = TimeFrame
    self._Scheduling = Scheduling



  #
  # DB audit report Parameters
  #

  @property
  def Name(self):
    ''' The name of the db audit report (string) '''
    return self._Name

  @property
  def ReportFormat(self):
    ''' The format of the report(string) '''
    return self._ReportFormat

  @property
  def ReportId(self):
    ''' The id of the report(string) '''
    return self._ReportId

  @property
  def Columns(self):
    '''
    The columns being used in the report.
    >>> report = mx.get_db_audit_report("report1")
    >>> report.Columns
     [
        {
            "name": "Destination IP",
            "aggregation": "group-by"
        },
        {
            "name": "User Defined Field 1",
            "aggregation": "group-by"
        }
    ]
    '''
    return self._Columns

  @property
  def Filters(self):
    '''
    The filters being used in the report. It is similar to Policy Match Criteria in API JSON format
    >>> report = mx.get_db_audit_report("report1")
    >>> report.Filters
     [
        {
            "values": [
                "Query"
            ],
            "column-name": "Event Type",
            "operation": "equals",
            "user-defined-values": []
        }
    ]
    '''
    return self._Filters

  @property
  def Policies(self):
    '''
    List of Policy Match Criterias (list of strings)

    >>> report = mx.get_db_audit_report("report1")
    >>> report.Policies = ["Default Rule - All Events"]
    >>> report.Policies
    ['wDefault Rule - All Events']

    '''
    return self._Policies

  @property
  def Sorting(self):
    '''
    The sorting attributes that being used in the report.
    >>> report = mx.get_db_audit_report("report1")
    >>> report.Sorting
     [
        {
            "aggregation": "group-by",
            "direction": "asc",
            "column-name": "Database"
        },
        {
            "aggregation": "group-by",
            "direction": "asc",
            "column-name": "Destination IP"
        }
    ]
    '''
    return self._Sorting

  @property
  def TimeFrame(self):
    '''
    The time frame of the report
    >>> report = mx.get_db_audit_report("report1")
    >>> report.TimeFrame
     {
        "from-to": false,
        "time-duration": 3,
        "time-scope": "days"
    }
    '''
    return self._TimeFrame

  @property
  def Scheduling(self):
    '''
    The details of the scheduling of the report(dictionary)
    >>> report = mx.get_db_audit_report("report1")
    >>> report.Scheduling
    {
      "occurs": "once",
      "once": {
        "at-time": "00:45:00",
        "at-date": "2018-12-21"
      }
    }
    '''
    return self._Scheduling

  @ReportFormat.setter
  def ReportFormat(self, ReportFormat):
    if ReportFormat != self._ReportFormat:
      self._connection._update_db_audit_report(Name=self._Name, Parameter='ReportFormat', Value=ReportFormat)
      self._ReportFormat = ReportFormat

  @ReportId.setter
  def ReportId(self, ReportId):
    if ReportId != self._ReportId:
      self._connection._update_db_audit_report(Name=self._Name, Parameter='ReportId', Value=ReportId)
      self._ReportId = ReportId

  @Columns.setter
  def Columns(self, Columns):
    #Order is important here
    tmp1 = []
    for cur_item in Columns:
      tmp1.append(''.join(sorted(str(cur_item))))
    #tmp1 = sorted(tmp1)
    tmp2 = []
    for cur_item in self._Columns:
      tmp2.append(''.join(sorted(str(cur_item))))
    #tmp2 = sorted(tmp2)
    if tmp1 != tmp2:
      self._connection._update_db_audit_report(Name=self._Name, Parameter='Columns',
                                               Value=Columns)
      self._Columns = Columns

  @Filters.setter
  def Filters(self, Filters):
    # Because the lists in SecureSphere don't have order, we need to sort them so we can compare them
    tmp1 = []
    for cur_item in Filters:
      tmp1.append(''.join(sorted(str(cur_item))))
    tmp1 = sorted(tmp1)
    tmp2 = []
    for cur_item in self._Filters:
      tmp2.append(''.join(sorted(str(cur_item))))
    tmp2 = sorted(tmp2)
    if tmp1 != tmp2:
      self._connection._update_db_audit_report(Name=self._Name, Parameter='Filters',
                                                     Value=Filters)
      self._Filters = Filters

  @Policies.setter
  def Policies(self, Policies):
    #intersect the lists in order to find a match
    if list(set(Policies) & set(self._Policies)):
      self._connection._update_db_audit_report(Name=self._Name, Parameter='Policies', Value=Policies)
      self._Policies = Policies

  @Sorting.setter
  def Sorting(self, Sorting):
    # Because the lists in SecureSphere don't have order, we need to sort them so we can compare them
    tmp1 = []
    for cur_item in Sorting:
      tmp1.append(''.join(sorted(str(cur_item))))
    tmp1 = sorted(tmp1)
    tmp2 = []
    for cur_item in self._Sorting:
      tmp2.append(''.join(sorted(str(cur_item))))
    tmp2 = sorted(tmp2)
    if tmp1 != tmp2:
      self._connection._update_db_audit_report(Name=self._Name, Parameter='Sorting', Value=Sorting)
      self._Sorting = Sorting



  @TimeFrame.setter
  def TimeFrame(self, TimeFrame):
    if TimeFrame != self._TimeFrame:
      self._connection._update_db_audit_report(Name=self._Name, Parameter='TimeFrame', Value=TimeFrame)
      self._TimeFrame = TimeFrame

  @Scheduling.setter
  def Scheduling(self, Scheduling):
    if Scheduling != self._Scheduling:
      self._connection._update_db_audit_report(Name=self._Name, Parameter='Scheduling', Value=Scheduling)
      self._Scheduling = Scheduling

  #
  # DB audit report internal functions
  #
  @staticmethod
  def _get_all_db_audit_reports(connection):
    try:
      res = connection._mx_api('GET', '/conf/dbauditreports')
      rule_names = res['db-audit-reports']
    except:
      raise MxException("Failed getting all DB audit reports")
    rules_objects = []
    for name in rule_names:
      try:
        obj = connection.get_db_audit_report(Name=name)
      except:
        raise MxException("Failed getting all DB audit reports")
      if obj:
        rules_objects.append(obj)
    return rules_objects

  @staticmethod
  def _get_db_audit_report_by_name(connection, Name=None):
    validate_string(Name=Name)
    obj_exists = DBAuditReport._exists(connection=connection, Name=Name)
    if obj_exists:
      return obj_exists
    try:
      res = connection._mx_api('GET', '/conf/dbauditreports/%s' % Name)
    except:
      return None
    return DBAuditReport(connection=connection, Name=Name, ReportFormat=res['report-format'], ReportId=res['report-id'],
                         Columns=res['columns'], Filters=res['filters'], Policies=res['policies'], Sorting=res['sorting'],
                         TimeFrame=res['time-frame'], Scheduling=res['scheduling'])


  @staticmethod
  def _update_db_audit_report(connection, Name=None, Parameter=None, Value=None):
    '''
        DB audit report open API doesn't support update
        Assume that _update will be called ONLY within the class setters
    '''
    print("WARNING: DB Audit Report doesn't support update %" % Name)
    return True


  @staticmethod
  def _create_db_audit_report(connection, Name=None, ReportFormat=None, ReportId = None, Columns=[],
                              Filters=[], Policies=[],  Sorting=[], TimeFrame={}, Scheduling=[], update=False):
    validate_string(Name=Name)
    obj = connection.get_db_audit_report(Name=Name)
    if obj:
      if not update:
        raise MxException("report '%s' already exists" % Name)
      else:
        # Update existing report
        parameters = locals()
        for cur_key in list(parameters):
          if is_parameter.match(cur_key) and cur_key != 'Name' and parameters[cur_key] != None:
            setattr(obj, cur_key, parameters[cur_key])
        return obj
    body = {}
    if Name: body['display-name'] = Name
    if ReportFormat: body['report-format'] = ReportFormat
    if ReportId: body['report-id'] = ReportId
    body['columns'] = Columns
    body['filters'] = Filters
    body['policies'] = Policies
    body['sorting'] = Sorting
    body['time-frame'] = TimeFrame
    body['scheduling'] = Scheduling

    try:
      res = connection._mx_api('POST', '/conf/dbauditreports', data=json.dumps(body))
    except Exception as e:
      raise MxException("Failed creating DB audit report: %s" % e)

    return DBAuditReport(connection=connection, Name=Name, ReportFormat=ReportFormat, ReportId=ReportId,
                         Columns=Columns, Filters=Filters, Policies=Policies, Sorting=Sorting, TimeFrame=TimeFrame,
                         Scheduling=Scheduling)

