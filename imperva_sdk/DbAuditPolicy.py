# Copyright 2018 Imperva. All rights reserved.

import json
import copy
from imperva_sdk.core import *

# Helper functions for comparing the parameters of a policy
# Returns True if all match criteria are equal
def _auditMatchEqual(match1, match2):
   if len(match1) != len(match2):
      return False
   for item in match1:
      if item not in match2:
         return False
   return True

# Returns True if all policy parameters are equal
def _auditPoliciesEqual(pol1, pol2):
   if len(pol1) != len(pol2):
      return False
   for item in pol1:
      if item not in pol2:
         return False
      # Match criteria has its own function. Check the rest of the attributes
      if item != 'match-criteria' and pol1[item] != pol2[item]:
         return False
   # match-criteria is an array and we check that each item exists in the other list
   if 'match-criteria' in pol1:
      return _auditMatchEqual(pol1['match-criteria'], pol2['match-criteria'])
   return True



class DbAuditPolicy(MxObject):
    '''
    MX DB Audit Policy Class
    '''

    # Store created DB Audit Policy objects in _instances to prevent duplicate instances and redundant API calls
    def __new__(Type, *args, **kwargs):
        obj_exists = DbAuditPolicy._exists(connection=kwargs['connection'], Name=kwargs['Name'])
        if obj_exists:
            return obj_exists
        else:
            obj = super(MxObject, Type).__new__(Type)
            kwargs['connection']._instances.append(obj)
            return obj

    @staticmethod
    def _exists(connection=None, Name=None):
        for cur_obj in connection._instances:
            if type(cur_obj).__name__ == 'DbAuditPolicy':
                if cur_obj.Name == Name:
                    return cur_obj
        return None

    # Method: __init__
    #-----------------------------------------------------------------------------------------------------
    # Inputs:
    #     Parameters    - includes all of the Audit Policy parameters
    #-----------------------------------------------------------------------------------------------------
    #
    def __init__(self, connection=None, Name=None, Parameters=None):
        super(DbAuditPolicy, self).__init__(connection=connection, Name=Name)
        self._Parameters = Parameters

    # Method: __iter__
    #-----------------------------------------------------------------------------------------------------
    # Description: Override the MxObject __iter__ function
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
    def Parameters            (self): return self._Parameters

    # Policy Parameter setters
    #-----------------------------------------------------------------------------------------------------
    # Description: setters for all policy parameters
    #-----------------------------------------------------------------------------------------------------
    #
    @Name.setter
    def Name(self,Name):
        if Name != self._Name:
            self._connection._update_db_audit_policy(Name = self._Name, Parameter='Name', Value=Name)
            self._Name = Name

    @Parameters.setter
    def Parameters(self, Parameters):
        if not _auditPoliciesEqual(Parameters, self._Parameters):
            self._connection._update_db_audit_policy(Name = self._Name, Parameter='Parameters', Value=Parameters)
            self._Parameters = Parameters

    #
    # DB Audit policy internal functions
    #
    @staticmethod
    def _get_all_db_audit_policies(connection):
        res = connection._mx_api('GET', '/conf/auditPolicies')
        try:
            policy_names = res['audit-policies']
        except:
            raise MxException("Failed getting DB Audit Policies")
        policy_objects = []
        for policy in policy_names:
            name = policy['policy-name']
            # Bug - we have policies with '/' character that don't work with the API...
            if '/' in name:
                # We need to print something to log to tell the user that this was not sent. We need a log mechanism
########
                print("%s cannot be used by the API. Skipping..." % name)
                continue
            pol_obj = connection.get_db_audit_policy(Name=name)
            if pol_obj:
                policy_objects.append(pol_obj)
        return policy_objects

    @staticmethod
    def _get_db_audit_policy(connection, Name=None):
        validate_string(Name=Name)
        obj_exists = DbAuditPolicy._exists(connection=connection, Name=Name)
        if obj_exists:
            return obj_exists
        # Read the policy from MX
        try:
          res = connection._mx_api('GET', '/conf/auditPolicies/%s' % Name)
        except:
          return None
        # The whole JSON parameter list is stored in Parameters.
        # It would make it harder to edit fields, but we don't need it now
        Parameters = res
        return DbAuditPolicy(connection=connection, Name=Name, Parameters=Parameters)

    @staticmethod
    def _create_db_audit_policy(connection, Name=None, Parameters=None, update=False):
        validate_string(Name=Name)
        pol = connection.get_db_audit_policy(Name=Name)
        if pol:
            if not update:
                raise MxException("Policy '%s' already exists" % Name)
            else:
                # Update existing policy. All parameters are in the parameter called Parameters
                if Parameters:
                   setattr(pol, "Parameters", Parameters)
            return pol
        else:
            # Create new policy
            body = {
            }
            if Parameters: body = Parameters

            try:
                connection._mx_api('POST', '/conf/auditPolicies/%s' % Name, data=json.dumps(body))
            except:
                pass
            return DbAuditPolicy(connection=connection, Name=Name, Parameters=Parameters)

    @staticmethod
    def _delete_db_audit_policy(connection, Name=None):
        validate_string(Name=Name)
        pol = connection.get_db_audit_policy(Name=Name)
        if pol:
            connection._mx_api('DELETE', '/conf/auditPolicies/%s' % Name)
            connection._instances.remove(pol)
            del pol
        else:
            raise MxException("Policy does not exist")
        return True

    @staticmethod
    def _update_db_audit_policy(connection, Name=None, Parameter=None, Value=None):
      if Parameter in ['Parameters']:
         body = Value
         connection._mx_api('PUT', '/conf/auditPolicies/%s' % Name, data=json.dumps(body))
      return True
