# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

# Assessment Scan - Iris

class AssessmentScan(MxObject):
    '''
    MX Assessment Scan Class

    '''

    # Store created Assessment Scan objects in _instances to prevent duplicate instances and redundant API calls
    def __new__(ClassType, *args, **kwargs):
        obj_exists = AssessmentScan._exists(connection=kwargs['connection'], Name=kwargs['Name'])
        if obj_exists:
            return obj_exists
        else:
            obj = super(MxObject, ClassType).__new__(ClassType)
            kwargs['connection']._instances.append(obj)
            return obj

    @staticmethod
    def _exists(connection=None, Name=None):
        for cur_obj in connection._instances:
            if type(cur_obj).__name__ == 'AssessmentScan':
                if cur_obj.Name == Name:
                    return cur_obj
        return None

    def __init__(self, connection=None, Name=None, Type=None, PreTest=None, PolicyTags=[],DbConnectionTags=[],ApplyTo=[], Scheduling=None):
        super(AssessmentScan, self).__init__(connection=connection, Name=Name)
        validate_string(Name=Name, Type=Type)
        self._Type = Type
        self._PreTest = PreTest
        self._PolicyTags = MxList(PolicyTags)
        self._DbConnectionTags = MxList(DbConnectionTags)
        self._ApplyTo = MxList(ApplyTo)
        self._Scheduling = Scheduling


    # Override the MxObject __iter__ function to print ApplyTo Assessment Scan objects
    def __iter__(self):
        iters = {}
        for field in dir(self):
            if is_parameter.match(field):
                variable_function = getattr(self, field)
                if field == 'ApplyTo':
                    ApplyToNames = []
                    for cur_apply in variable_function:
                        ApplyToNames.append({u'dbConnectionName': cur_apply})
                    iters[field] = ApplyToNames
                else:
                    iters[field] = variable_function
        for x, y in iters.items():
            yield x, y

    #
    # Assessment Scan Parameters Getters
    #
    @property
    def Name(self):
        ''' The name of the scan (string) '''
        return self._Name

    @property
    def Type(self):
        ''' Type of scan - policy based or tag based (string) '''
        return self._Type

    @property
    def PreTest(self):
        ''' Is pre test considered (or ignored)? (boolean) '''
        return self._PreTest

    @property
    def PolicyTags(self):
        ''' Policy Tags that are assigned to the scan '''
        return self._PolicyTags

    @property
    def DbConnectionTags(self):
        ''' DB Connection tags that are assigned to the scan '''
        return self._DbConnectionTags


    @property
    def ApplyTo(self):
        '''
        DB Connections that scan is applied to (list of :py:class:`imperva_sdk.DbConnection` objects). Can be in API JSON format or DBConnection objects
        '''
        return self._ApplyTo


    @property
    def Scheduling(self):
        ''' The scan's scheduling '''
        return self._Scheduling

    ##########
    # Setters
    ##########

    @Type.setter
    def Type(self, Type):
        if Type != self._Type:
            self._connection._update_assessment_scan(Name=self._Name, Parameter='type', Value=Type)
            self._Type = Type

    @PreTest.setter
    def PreTest(self, PreTest):
        if PreTest != self._PreTest:
            self._connection._update_assessment_scan(Name=self._Name, Parameter='preTest', Value=PreTest)
            self._PreTest = PreTest


    @PolicyTags.setter
    def PolicyTags(self, PolicyTags):
        tmp1 = []
        for cur_item in PolicyTags:
            tmp1.append(''.join(sorted(str(cur_item).replace('u', ''))))
        tmp1 = sorted(tmp1)
        tmp2 = []
        for cur_item in self._PolicyTags:
            tmp2 = sorted(tmp2)
            tmp2.append(''.join(sorted(str(cur_item).replace('u', ''))))
        tmp2 = sorted(tmp2)
        if tmp1 != tmp2:
            self._connection._update_assessment_scan(Name=self._Name, Parameter='policyTags', Value=PolicyTags)
            self._PolicyTags = PolicyTags


    @DbConnectionTags.setter
    def DbConnectionTags(self, DbConnectionTags):
        tmp1 = []
        for cur_item in DbConnectionTags:
            tmp1.append(''.join(sorted(str(cur_item).replace('u', ''))))
        tmp1 = sorted(tmp1)
        tmp2 = []
        for cur_item in self._DbConnectionTags:
            tmp2 = sorted(tmp2)
            tmp2.append(''.join(sorted(str(cur_item).replace('u', ''))))
        tmp2 = sorted(tmp2)
        if tmp1 != tmp2:
            self._connection._update_assessment_scan(Name=self._Name, Parameter='dbConnectionTags', Value=DbConnectionTags)
            self._DbConnectionTags = DbConnectionTags



    @ApplyTo.setter
    def ApplyTo(self, ApplyTo):

        change = []

        # Translate ApplyTo to objects if we need to
        ApplyToObjects = []
        for cur_apply in ApplyTo:
            if type(cur_apply).__name__ == 'DbConnection':
                ApplyToObjects.append(cur_apply)
            else:
                raise MxException("Bad 'ApplyTo' parameter")

        # Check if we need to add anything
        for cur_apply in ApplyToObjects:
            if cur_apply not in self._ApplyTo:
                change.append(cur_apply)
        # Check if we need to remove anything
        for cur_apply in self._ApplyTo:
            if cur_apply not in ApplyToObjects:
                change.append(cur_apply)

        if change:
            self._connection._update_assessment_scan(Name=self._Name, Parameter='apply-to', Value=change)
            self._ApplyTo = MxList(ApplyToObjects)

    @Scheduling.setter
    def Scheduling(self, Scheduling):
        if Scheduling != self._Scheduling:
            self._connection._update_assessment_scan(Name=self._Name, Parameter='scheduling', Value=Scheduling)
            self._Scheduling = Scheduling

    ##########################################################
    # static methods for GET ALL, GET, CREATE. DELETE, UPDATE
    ##########################################################

    @staticmethod
    def _get_all_assessment_scans(connection):
        try:
            scan_names = connection._mx_api('GET', '/conf/assessment/scans')
        except:
            raise MxException("Failed getting Assessment Scans")
        scan_objects = []
        for name in scan_names:
            scan_obj = connection.get_assessment_scan(Name=name)
            if scan_obj:
                scan_objects.append(scan_obj)
        return scan_objects


    @staticmethod
    def _get_assessment_scan(connection, Name=None):
        validate_string(Name=Name)
        obj_exists = AssessmentScan._exists(connection=connection, Name=Name)
        if obj_exists:
            return obj_exists
        try:
            res = connection._mx_api('GET', '/conf/assessment/scans/%s' % Name)
        except:
            return None

        if 'type' not in res: res['type'] = ''
        if 'pre-test' not in res: res['pre-test'] = None
        if 'policy-tags' not in res: res['policy-tags'] = []
        if 'db-connection-tags' not in res: res['db-connection-tags'] = []
        if 'apply-to' not in res: res['apply-to'] = []

        ApplyToObjects = []
        for cur_apply in res['apply-to']:
            ApplyToObjects.append(cur_apply)

        return AssessmentScan(connection=connection, Name=Name, Type=res['type'], PreTest=res['pre-test'],
                            PolicyTags=res['policy-tags'], DbConnectionTags=res['db-connection-tags'],
                              ApplyTo=ApplyToObjects, Scheduling=res['scheduling'])


    @staticmethod
    def _create_assessment_scan(connection, Name=None, Type=None, PreTest=None, PolicyTags=None,
                                DbConnectionTags=None, ApplyTo=None, Scheduling=None, update=False):
        validate_string(Name=Name)
        scan = connection.get_assessment_scan(Name=Name)
        if scan:
            if not update:
                raise MxException("Scan '%s' already exists" % Name)
            else:
                # Update existing scan
                parameters = locals()
                for cur_key in parameters:
                    if is_parameter.match(cur_key) and cur_key != 'Name' and parameters[cur_key] != None:
                        setattr(scan, cur_key, parameters[cur_key])
            return scan
        else:
            # Create new scan
            body = {
                'pre-test': PreTest,
            }
            if Type: body['type'] = Type
            if PolicyTags: body['policy-tags'] = PolicyTags
            if DbConnectionTags: body['db-connection-tags'] = DbConnectionTags

            # We want to support ApplyTo in dictionary (API) and WebService object formats
            ApplyToNames = []
            ApplyToObjects = []
            if ApplyTo:
                for cur_apply in ApplyTo:
                    if type(cur_apply).__name__ == 'str':
                        ApplyToNames.append(cur_apply)
                        ApplyToObjects.append(cur_apply)
                    else:
                        raise MxException("Bad 'ApplyTo' parameter")
            if ApplyToNames: body['apply-to'] = ApplyToNames
            connection._mx_api('POST', '/conf/assessment/scans/%s' % Name, data=json.dumps(body))
            return AssessmentScan(connection=connection, Name=Name, Type=Type, PreTest=PreTest,
                                              PolicyTags=PolicyTags, DbConnectionTags=DbConnectionTags,
                                               ApplyTo=ApplyToObjects, Scheduling=Scheduling)


    @staticmethod
    def _delete_assessment_scan(connection, Name=None):
        validate_string(Name=Name)
        scan = connection.get_assessment_scan(Name=Name)
        if scan:
            connection._mx_api('DELETE', '/conf/assessment/scans/%s' % Name)
            connection._instances.remove(scan)
            del scan
        else:
            raise MxException("Scan does not exist")
        return True




    @staticmethod
    def _update_assessment_scan(connection, Name=None, Parameter=None, Value=None):
        if Parameter == 'pre-test':
            if Value != True and Value != False:
                raise MxException("Parameter '%s' must be True or False" % Parameter)
        elif Parameter == 'type':
            if Value not in ['tag based','policy based']:
                raise MxException("Parameter '%s' must be 'tag based' or 'policy based'" %Parameter)
        body = {Parameter: Value}
        connection._mx_api('PUT', '/conf/assessment/scans/%s' %Name, data=json.dumps(body))

        return True