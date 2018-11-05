# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *

class AssessmentPolicy(MxObject):
    '''
    MX Assessment Policy Class
    '''

    # Store created DB Audit Policy objects in _instances to prevent duplicate instances and redundant API calls
    def __new__(Type, *args, **kwargs):
        obj_exists = AssessmentPolicy._exists(connection=kwargs['connection'], Name=kwargs['Name'])
        if obj_exists:
            return obj_exists
        else:
            obj = super(MxObject, Type).__new__(Type)
            kwargs['connection']._instances.append(obj)
            return obj

    @staticmethod
    def _exists(connection=None, Name=None):
        for curr_obj in connection._instances:
            if type(curr_obj).__name__ == 'AssessmentPolicy':
                if curr_obj.Name == Name:
                    return curr_obj
        return None
    #
    def __init__(self, connection=None, Name=None, Description=None,
        DbType=None, PolicyTags=[], AdcKeywords=[], TestNames=[]):

        super(AssessmentPolicy, self).__init__(connection=connection, Name=Name)

        self._Description = Description
        self._DbType = DbType
        self._PolicyTags = MxList(PolicyTags)
        self._AdcKeywords = MxList(AdcKeywords)
        self._TestNames = MxList(TestNames)

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

    # Policy Parameter getters
    #-----------------------------------------------------------------------------------------------------
    # Description: properties for all policy parameters
    #-----------------------------------------------------------------------------------------------------
    #
    @property
    def Name(self):                  return self._Name
    @property
    def Description                  (self): return self._Description
    @property
    def DbType                  (self): return self._DbType
    @property
    def PolicyTags               (self): return self._PolicyTags
    @property
    def AdcKeywords(self):               return self._AdcKeywords
    @property
    def TestNames         (self): return self._TestNames

    #
    # Assessment policy internal functions
    #
    @staticmethod
    def _get_all_assessment_policies(connection):
        try:
            assessmentPolicyNames = connection._mx_api('GET', '/conf/assessment/policies')
        except:
            raise MxException("Failed getting Assessment Policies")
        assessmentPolicies = []
        for assessmentPolicyName in assessmentPolicyNames:
            if '/' in assessmentPolicyName:
                print("%s cannot be used by the API. Skipping..." % assessmentPolicyName)
                continue
            try:
                assessmentPolicy = connection._mx_api('GET', '/conf/assessment/policies/' + assessmentPolicyName)
            except:
                raise MxException("Failed getting Assessment Policy '%s'" % assessmentPolicyName)

            assessmentPolicy = AssessmentPolicy.validateEmptyIndices(assessmentPolicy)
            policyObj = AssessmentPolicy(connection=connection, Name=assessmentPolicy['name'], Description=assessmentPolicy['description'],
                                            DbType=assessmentPolicy['db-type'], PolicyTags=assessmentPolicy['policy-tags'], AdcKeywords=assessmentPolicy['adc-keywords'], TestNames=assessmentPolicy['test-names'])
            assessmentPolicies.append(policyObj)
        return assessmentPolicies

    @staticmethod
    def _get_assessment_policy(connection, Name=None):
        validate_string(Name=Name)
        obj_exists = AssessmentPolicy._exists(connection=connection, Name=Name)
        if obj_exists:
            return obj_exists
        try:
            assessmentPolicy = connection._mx_api('GET', '/conf/assessment/policies/' + Name)
        except:
            raise MxException("Failed getting Assessment Policy '%s'" % Name)

        assessmentPolicy = AssessmentPolicy.validateEmptyIndices(assessmentPolicy)
        return AssessmentPolicy(connection=connection, Name=assessmentPolicy['name'], Description=assessmentPolicy['description'],
                                            DbType=assessmentPolicy['db-type'],PolicyTags=assessmentPolicy['policy-tags'] , AdcKeywords=assessmentPolicy['adc-keywords'],
                                            TestNames=assessmentPolicy['test-names'])


    @staticmethod
    def _create_assessment_policy(connection, Name=None, Description=None, DbType=None, PolicyTags=[], AdcKeywords=[], TestNames=[]):
        validate_string(Name=Name)
        body = {}
        body['name'] = Name
        body['description'] = Description
        body['db-type'] = DbType
        body['policy-tags'] = PolicyTags
        body['adc-keywords'] = AdcKeywords
        body['test-names'] = TestNames

        try:
            connection._mx_api('POST', '/conf/assessment/policies/%s' % Name, data=json.dumps(body))
        except:
            raise MxException("Failed creating Assessment Policy '%s'" % Name)

        return AssessmentPolicy(connection=connection, Name=Name, Description=Description, DbType=DbType, PolicyTags=PolicyTags, AdcKeywords=AdcKeywords, TestNames=TestNames)

    @staticmethod
    def _update_assessment_policy(connection, Name=None, Description=None, DbType=None, PolicyTags=[], AdcKeywords=[], TestNames=[]):
        raise MxException("Assessment Update API currently not supported")

    @staticmethod
    def _delete_assessment_policy(connection, Name=None):
        raise MxException("Assessment Delete API currently not supported")

    @staticmethod
    def validateEmptyIndices(assessmentPolicy):
        if 'name' not in assessmentPolicy:
            assessmentPolicy['name'] = None
        if 'description' not in assessmentPolicy:
            assessmentPolicy['description'] = None
        if 'db-type' not in assessmentPolicy:
            assessmentPolicy['db-type'] = None
        if 'policy-tags' not in assessmentPolicy:
            assessmentPolicy['policy-tags'] = []
        if 'adc-keywords' not in assessmentPolicy:
            assessmentPolicy['adc-keywords'] = []
        if 'test-names' not in assessmentPolicy:
            assessmentPolicy['test-names'] = []

        return assessmentPolicy
