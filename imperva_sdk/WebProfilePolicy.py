# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *


class WebProfilePolicy(MxObject):
    '''
    MX Web  Profile Policy Class

    '''

    # Store created Web Profile Policy objects in _instances to prevent duplicate instances and redundant API calls
    def __new__(Type, *args, **kwargs):
        obj_exists = WebProfilePolicy._exists(connection=kwargs['connection'], Name=kwargs['Name'])
        if obj_exists:
            return obj_exists
        else:
            obj = super(MxObject, Type).__new__(Type)
            kwargs['connection']._instances.append(obj)
            return obj

    @staticmethod
    def _exists(connection=None, Name=None):
        for cur_obj in connection._instances:
            if type(cur_obj).__name__ == 'WebProfilePolicy':
                if cur_obj.Name == Name:
                    return cur_obj
        return None
    def __init__(self, connection=None, Name=None, SendToCd=None, Rules=[], Exceptions=[], ApuConfig={}, DisableLearning=None,
                 DisplayResponsePage=None, ApplyTo=[]):
        super(WebProfilePolicy, self).__init__(connection=connection, Name=Name)
        validate_string(Name=Name)
        self._SendToCd = SendToCd
        self._DisplayResponsePage = DisplayResponsePage
        self._DisableLearning = DisableLearning
        self._ApplyTo = MxList(ApplyTo)
        self._Rules = MxList(Rules)
        self._Exceptions = MxList(Exceptions)
        self._ApuConfig = ApuConfig

    # Override the MxObject __iter__ function to print ApplyTo WebApplication objects as dictionaries
    def __iter__(self):
        iters = {}
        for field in dir(self):
            if is_parameter.match(field):
                variable_function = getattr(self, field)
                if field == 'ApplyTo':
                    ApplyToNames = []
                    for cur_apply in variable_function:
                        ApplyToNames.append({u'siteName': cur_apply._Site, u'serverGroupName': cur_apply._ServerGroup,
                                             u'webServiceName': cur_apply._WebService,
                                             u'webApplicationName': cur_apply.Name})
                    iters[field] = ApplyToNames
                else:
                    iters[field] = variable_function
        for x, y in iters.items():
            yield x, y

    #
    # HTTP Protocol Signatures Policy Parameters
    #
    @property
    def Name(self):
        ''' The name of the policy (string) '''
        return self._Name

    @property
    def SendToCd(self):
        ''' Send policy alerts to community defense. Applicable for only some predefined policies (boolean) '''
        return self._SendToCd

    @property
    def DisplayResponsePage(self):
        ''' Show response page in alerts (boolean) '''
        return self._DisplayResponsePage

    @property
    def Rules(self):
        '''
        Policy dictionary rules (list of dict)

        >>> pol.Rules
        [{'name': 'Cookie Injection', 'enabled': False, 'severity': 'medium', 'action': 'none'}, {'name': 'Cookie Tampering', 'enabled': True, 'severity': 'medium', 'action': 'none'}, {'name': 'Non-SOAP Access to a SOAP Only URL', 'enabled': False, 'severity': 'medium', 'action': 'none'}, {'name': 'Parameter Read Only Violation', 'enabled': False, 'severity': 'informative', 'action': 'none', 'parameters': {'issueAnomalyForRequestsWithoutSession': 'false', 'issueAnomalyForCorrelatedParameterTampering': 'true', 'issueAnomalyForResponseEvasion': 'true'}}, {'name': 'Parameter Type Violation', 'enabled': False, 'severity': 'medium', 'action': 'none'}, {'name': 'Parameter Value Length Violation', 'enabled': False, 'severity': 'informative', 'action': 'none'}, {'name': 'Required Parameter Not Found', 'enabled': False, 'severity': 'informative', 'action': 'none'}, {'name': 'Required XML Element Not Found', 'enabled': False, 'severity': 'informative', 'action': 'none'}, {'name': "Reuse of Expired Session's Cookie", 'enabled': False, 'severity': 'informative', 'action': 'none'}, {'name': 'SOAP Access to a Non-SOAP URL', 'enabled': False, 'severity': 'medium', 'action': 'none'}, {'name': 'SOAP Element Value Length Violation', 'enabled': False, 'severity': 'informative', 'action': 'none'}, {'name': 'SOAP Element Value Type Violation', 'enabled': False, 'severity': 'medium', 'action': 'none'}, {'name': 'Unauthorized Content Type for Known URL', 'enabled': False, 'severity': 'low', 'action': 'none'}, {'name': 'Unauthorized Method for Known URL', 'enabled': False, 'severity': 'low', 'action': 'none'}, {'name': 'Unauthorized SOAP Action', 'enabled': False, 'severity': 'high', 'action': 'none'}, {'name': 'Unauthorized URL Access', 'enabled': False, 'severity': 'high', 'action': 'block'}, {'name': 'Unknown Parameter', 'enabled': False, 'severity': 'informative','action': 'none'}, {'name': 'Unknown SOAP Element', 'enabled': False, 'severity': 'informative', 'action': 'none'}]

        '''

        return self._Rules

    @property
    def Exceptions(self):
        '''
        Policy exceptions (list of dict)

        >>> pol.Exceptions
        [{'ruleName': 'Cookie Injection', 'comment': 'This is an exception', 'predicates': [{'matchNoOrUnknownUser': False, 'values': ['admin'], 'type': 'applicationUser', 'operation': 'atLeastOne'}]}]

        '''
        return self._Exceptions

    @property
    def ApplyTo(self):
        '''
        Web Applications that policy is applied to (list of :py:class:`imperva_sdk.WebApplication` objects). Can be in API JSON format or WebApplication objects

        >>> pol.ApplyTo = [{'siteName': 'site name', 'serverGroupName': 'server group name', 'webServiceName': 'web service name', 'webApplicationName': 'web application name'}]
        >>> pol.ApplyTo
        [<imperva_sdk 'WebApplication' Object - 'web application name'>]

        * siteName - Name of the site (string)
        * serverGroupName - Name of the server group (string)
        * webServiceName - Name of the web service (string)
        * webApplicationName - Name of the web application (string)

        '''
        return self._ApplyTo
    @property
    def ApuConfig(self):
        '''
        Policy's Automatic Profile Update Configuration list (dict)

        >>> pol.ApuConfig
        {'SOAP Element Value Length Violation': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Parameter Read Only Violation': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, "Reuse of Expired Session's Cookie": {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'SOAP Element Value Type Violation': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Required Parameter Not Found': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Unauthorized Method forKnown URL': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Unknown Parameter': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Parameter Type Violation': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Unauthorized SOAP Action': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Unknown SOAP Element': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Required XML Element Not Found': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Parameter Value Length Violation': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Cookie Injection': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}, 'Cookie Tampering': {'enabled': True, 'sources': 50, 'occurrences': 50, 'hours': 12}}

        '''
        return self._ApuConfig
    @property
    def DisableLearning(self):
        '''
        Disable learning engine (boolean)
        '''
        return self._DisableLearning

    @SendToCd.setter
    def SendToCd(self, SendToCd):
        if SendToCd != self._SendToCd:
            self._connection._update_web_profile_policy(Name=self._Name, Parameter='sendToCd',
                                                                     Value=SendToCd)
            self._SendToCd = SendToCd

    @DisplayResponsePage.setter
    def DisplayResponsePage(self, DisplayResponsePage):
        if DisplayResponsePage != self._DisplayResponsePage:
            self._connection._update_web_profile_policy(Name=self._Name, Parameter='displayResponsePage',
                                                                     Value=DisplayResponsePage)
            self._DisplayResponsePage = DisplayResponsePage

    @ApplyTo.setter
    def ApplyTo(self, ApplyTo):
      change = []
      # Translate ApplyTo to objects if we need to
      ApplyToObjects = []
      for cur_apply in ApplyTo:
        if type(cur_apply).__name__ == 'dict':
          ApplyToObjects.append(
            self._connection.get_web_application(Site=cur_apply['siteName'], ServerGroup=cur_apply['serverGroupName'],
                                                 WebService=cur_apply['webServiceName'],
                                                 Name=cur_apply['webApplicationName']))
        elif type(cur_apply).__name__ == 'WebApplication':
          ApplyToObjects.append(cur_apply)
        else:
          raise MxException("Bad 'ApplyTo' parameter")

      # Check if we need to add anything
      for cur_apply in ApplyToObjects:
        if cur_apply not in self._ApplyTo:
          apply_dict = {
            'siteName': cur_apply._Site,
            'serverGroupName': cur_apply._ServerGroup,
            'webServiceName': cur_apply._WebService,
            'webApplicationName': cur_apply.Name,
            'operation': 'add'
          }
          change.append(apply_dict)
      # Check if we need to remove anything
      for cur_apply in self._ApplyTo:
        if cur_apply not in ApplyToObjects:
          apply_dict = {
            'siteName': cur_apply._Site,
            'serverGroupName': cur_apply._ServerGroup,
            'webServiceName': cur_apply._WebService,
            'webApplicationName': cur_apply.Name,
            'operation': 'remove'
          }
          change.append(apply_dict)

      if change:
        self._connection._update_web_profile_policy(Name=self._Name, Parameter='applyTo', Value=change)
        self._ApplyTo = MxList(ApplyToObjects)

    @Rules.setter
    def Rules(self, Rules):
        # Because the Rules isn't really a list and the MX can return it in different orders, we need to compare only the rules
        change = False
        for cur_rule in Rules:
            if cur_rule not in self._Rules:
                change = True
                break
        if not change:
            for cur_rule in self._Rules:
                if cur_rule not in Rules:
                    change = True
                    break
        if change:
            self._connection._update_web_profile_policy(Name=self._Name, Parameter='rules', Value=Rules)
            self._Rules = Rules

    @Exceptions.setter
    def Exceptions(self, Exceptions):
        # Because the Exceptions isn't really a list and the MX can return it in different orders, we need to compare only the rules
        change = False
        for cur_rule in Exceptions:
            if cur_rule not in self._Exceptions:
                change = True
                break
        if not change:
            for cur_rule in self._Exceptions:
                if cur_rule not in Exceptions:
                    change = True
                    break
        if change:
            self._connection._update_web_profile_policy(Name=self._Name, Parameter='exceptions',
                                                                     Value=Exceptions)
            self._Exceptions = Exceptions


    @ApuConfig.setter
    def ApuConfig(self, ApuConfig):
      if self._ApuConfig != ApuConfig:
        self._connection._update_web_profile_policy(Name=self._Name, Parameter='apuConfig', Value=ApuConfig)
        self._ApuConfig = ApuConfig

    @DisableLearning.setter
    def DisableLearning(self, DisableLearning):
      if self._DisableLearning != DisableLearning:
        self._connection._update_web_profile_policy(Name=self._Name, Parameter='disableLearning', Value=DisableLearning)
        self._DisableLearning = DisableLearning

    #
    # HTTP Protocol Signatures internal functions
    #
    @staticmethod
    def _get_all_web_profile_policies(connection):
        res = connection._mx_api('GET', '/conf/policies/security/webProfilePolicies')
        try:
            policy_names = res['policies']
        except:
            raise MxException("Failed getting HTTP Protocol Signatures Policies")
        policy_objects = []
        for name in policy_names:
            # Bug - we have policies with '/' character that don't work with the API...
            if '/' in name:
                continue
            pol_obj = connection.get_web_profile_policy(Name=name)
            if pol_obj:
                policy_objects.append(pol_obj)
        return policy_objects

    @staticmethod
    def _get_web_profile_policy(connection, Name=None):
        validate_string(Name=Name)
        obj_exists = WebProfilePolicy._exists(connection=connection, Name=Name)
        if obj_exists:
            return obj_exists
        try:
            res = connection._mx_api('GET', '/conf/policies/security/webProfilePolicies/%s' % Name)
        except:
            return None
        if 'sendToCd' not in res: res['sendToCd'] = None
        if 'exceptions' not in res: res['exceptions'] = []
        # Translate the ApplyTo dictionary to WebApplication objects
        ApplyToObjects = []
        for cur_apply in res['applyTo']:
            # Check if we already have the web service instance created, we can use it instead of creating a new one
            wa = connection.get_web_application(Site=cur_apply['siteName'], ServerGroup=cur_apply['serverGroupName'],
                                                WebService=cur_apply['webServiceName'],
                                                Name=cur_apply['webApplicationName'])
            if wa:
                ApplyToObjects.append(wa)
        return WebProfilePolicy(connection=connection, Name=Name, SendToCd=res['sendToCd'], ApuConfig=res['apuConfig'],
                                DisableLearning=res['disableLearning'], DisplayResponsePage=res['displayResponsePage'],
                                ApplyTo=ApplyToObjects, Rules=res['rules'], Exceptions=res['exceptions'])

    @staticmethod
    def _create_web_profile_policy(connection, Name=None, SendToCd=None, DisplayResponsePage=None, DisableLearning=None,
                                   ApuConfig=None, ApplyTo=[], Rules=[], Exceptions=[], update=False):
        validate_string(Name=Name)
        pol = connection.get_web_profile_policy(Name=Name)
        if pol:
            if not update:
                raise MxException("Policy '%s' already exists" % Name)
            else:
                # Update existing policy
                parameters = dict(locals())
                for cur_key in parameters:
                    if is_parameter.match(cur_key) and cur_key != 'Name' and parameters[cur_key] != None:
                        setattr(pol, cur_key, parameters[cur_key])
            return pol
        else:
            # Create new policy
            body = {
                'displayResponsePage': DisplayResponsePage,
                'disableLearning': DisableLearning
            }
            if Rules: body['rules'] = Rules
            if Exceptions: body['exceptions'] = Exceptions
            # We want to support ApplyTo in dictionary (API) and WebService object formats
            ApplyToNames = []
            ApplyToObjects = []
            for cur_apply in ApplyTo:
                if type(cur_apply).__name__ == 'dict':
                    ApplyToNames.append(cur_apply)
                    ApplyToObjects.append(connection.get_web_application(Site=cur_apply['siteName'],
                                                                         ServerGroup=cur_apply['serverGroupName'],
                                                                         WebService=cur_apply['webServiceName'],
                                                                         Name=cur_apply['webApplicationName']))
                elif type(cur_apply).__name__ == 'WebApplication':
                    ApplyToNames.append({u'siteName': cur_apply._Site, u'serverGroupName': cur_apply._ServerGroup,
                                         u'webServiceName': cur_apply._WebService,
                                         u'webApplicationName': cur_apply.Name})
                    ApplyToObjects.append(cur_apply)
                else:
                    raise MxException("Bad 'ApplyTo' parameter")
            if ApplyToNames: body['applyTo'] = ApplyToNames
            try:
                connection._mx_api('POST', '/conf/policies/security/webProfilePolicies/%s' % Name,
                               data=json.dumps(body))
            except:
                # Some versions of the API does not support Exceptions
                del body['exceptions']
                Exceptions = []
                connection._mx_api('POST', '/conf/policies/security/webProfilePolicies/%s' % Name,
                                   data=json.dumps(body))
            return WebProfilePolicy(connection=connection, Name=Name, SendToCd=SendToCd,
                                    DisableLearning=DisableLearning, DisplayResponsePage=DisplayResponsePage,
                                    ApplyTo=ApplyToObjects, Rules=Rules, Exceptions=Exceptions, ApuConfig=ApuConfig)

    @staticmethod
    def _delete_web_profile_policy(connection, Name=None):
        validate_string(Name=Name)
        pol = connection.get_web_profile_policy(Name=Name)
        if pol:
            connection._mx_api('DELETE', '/conf/policies/security/webProfilePolicies/%s' % Name)
            connection._instances.remove(pol)
            del pol
        else:
            raise MxException("Policy does not exist")
        return True

    @staticmethod
    def _update_web_profile_policy(connection, Name=None, Parameter=None, Value=None):
        if Parameter in ['sendToCd', 'displayResponsePage']:
            if Value != True and Value != False:
                raise MxException("Parameter '%s' must be True or False" % Parameter)
        body = {Parameter: Value}
        connection._mx_api('PUT', '/conf/policies/security/webProfilePolicies/%s' % Name,
                           data=json.dumps(body))
        return True

