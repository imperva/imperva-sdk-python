# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *
import sys

class DataEnrichmentPolicy(MxObject):
    '''
    MX Data Erichment Policy Class
    '''

    # Store created DB Audit Policy objects in _instances to prevent duplicate instances and redundant API calls
    def __new__(Type, *args, **kwargs):
        obj_exists = DataEnrichmentPolicy._exists(connection=kwargs['connection'], Name=kwargs['Name'])
        if obj_exists:
            return obj_exists
        else:
            obj = super(MxObject, Type).__new__(Type)
            kwargs['connection']._instances.append(obj)
            return obj

    @staticmethod
    def _exists(connection=None, Name=None):
        for curr_obj in connection._instances:
            if type(curr_obj).__name__ == 'DataEnrichmentPolicy':
                if curr_obj.Name == Name:
                    return curr_obj
        return None
    #
    def __init__(self, connection=None, Name=None, PolicyType=None,
        Rules = [],
        MatchCriteria=[], ApplyTo=[]):

        super(DataEnrichmentPolicy, self).__init__(connection=connection, Name=Name)

        self._Type = PolicyType
        self._Rules = MxList(Rules)
        self._MatchCriteria = MxList(MatchCriteria)
        self._ApplyTo = MxList(ApplyTo)

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
    def Name                  (self): return self._Name
    @property
    def Type                  (self): return self._Type
    @property
    def Rules                 (self): return self._Rules
    @property
    def ApplyTo               (self): return self._ApplyTo
    @property
    def MatchCriteria         (self): return self._MatchCriteria

    #
    # Data Enrichment policy internal functions
    #
    @staticmethod
    def _get_all_data_enrichment_policies(connection):
        try:
            policyNames = connection._mx_api('GET', '/conf/dataEnrichmentPolicies')
        except:
            raise MxException("Failed getting Data Enrichment Policies")
        policyObjects = []
        for policyName in policyNames:
            # Bug - we have policies with '/' character that don't work with the API...
            if '/' in policyName:
                print("%s cannot be used by the API. Skipping..." % policyName)
                continue
            try:
                policy = connection._mx_api('GET', '/conf/dataEnrichmentPolicies/' + policyName)
            except:
                raise MxException("Failed getting Data Enrichment Policy '%s'" % policyName)
            policyObj = DataEnrichmentPolicy(connection=connection, Name=policy['policy-name'], PolicyType=policy['policy-type'], Rules=policy['rules'],
                                    MatchCriteria=policy['match-criteria'], ApplyTo=policy['apply-to'])
            policyObjects.append(policyObj)
        return policyObjects

    @staticmethod
    def _get_data_enrichment_policy(connection, Name=None):
        validate_string(Name=Name)
        obj_exists = DataEnrichmentPolicy._exists(connection=connection, Name=Name)
        if obj_exists:
            return obj_exists
        try:
            policy = connection._mx_api('GET', '/conf/dataEnrichmentPolicies/' + Name)
        except:
            raise MxException("Failed getting Data Enrichment Policy '%s'" % Name)

        return DataEnrichmentPolicy(connection=connection, Name=policy['policy-name'], PolicyType=policy['policy-type'], Rules=policy['rules'],
                                    MatchCriteria=policy['match-criteria'], ApplyTo=policy['apply-to'])


    @staticmethod
    def _create_data_enrichment_policy(connection, Name=None, PolicyType=None, Rules=[], MatchCriteria=[], ApplyTo=[]):
        validate_string(Name=Name)
        body = {}
        body['policy-name'] = Name
        body['policy-type'] = PolicyType
        body['apply-to'] = ApplyTo
        body['rules'] = Rules
        body['match-criteria'] = MatchCriteria

        # print(json.dumps(body))

        connection._mx_api('POST', '/conf/dataEnrichmentPolicies/%s' % slash(Name), data=json.dumps(body))
        return DataEnrichmentPolicy(connection=connection, Name=Name, PolicyType=PolicyType, ApplyTo=ApplyTo, Rules=Rules, MatchCriteria=MatchCriteria)


    @staticmethod
    def _update_data_enrichment_policy(connection, Name=None, Rules=[], MatchCriteria=[], ApplyTo=[]):
        raise MxException("Data Enrichment Update API currently not supported")

    @staticmethod
    def _delete_data_enrichment_policy(connection, Name=None):
        raise MxException("Data Enrichment Delete API currently not supported")