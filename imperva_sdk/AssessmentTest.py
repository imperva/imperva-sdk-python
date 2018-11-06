# Copyright 2018 Imperva. All rights reserved.
import json
from imperva_sdk.core import *
class AssessmentTest(MxObject):
    '''
    MX Assessment Test Class
    '''
     # Store created Assessment test objects in _instances to prevent duplicate instances and redundant API calls
    def __new__(Type, *args, **kwargs):
        obj_exists = AssessmentTest._exists(connection=kwargs['connection'], Name=kwargs['Name'])
        if obj_exists:
            return obj_exists
        else:
            obj = super(MxObject, Type).__new__(Type)
            kwargs['connection']._instances.append(obj)
            return obj
    @staticmethod
    def _exists(connection=None, Name=None):
        for curr_obj in connection._instances:
            if type(curr_obj).__name__ == 'AssessmentTest':
                if curr_obj.Name == Name:
                    return curr_obj
        return None
    #
    def __init__(self, connection=None, Name=None, Description=None,
                    Severity=None, Category=None, ScriptType=None, OsType=None, DbType=None, RecommendedFix=None,
                    TestScript=None, AdditionalScript=None, ResultsLayout=[]):
         super(AssessmentTest, self).__init__(connection=connection, Name=Name)
         self._Name = Name
         self._Description = Description
         self._Severity = Severity
         self._Category = Category
         self._ScriptType = ScriptType
         self._OsType = OsType
         self._DbType = DbType
         self._RecommendedFix = RecommendedFix
         self._TestScript = TestScript
         self._AdditionalScript = AdditionalScript
         self._ResultsLayout = ResultsLayout

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
     # Test Parameter getters
    #-----------------------------------------------------------------------------------------------------
    # Description: properties for all test parameters
    #-----------------------------------------------------------------------------------------------------
    #
    @property
    def Name(self):   return self._Name
    @property
    def Description(self):    return self._Description
    @property
    def Severity(self):    return self._Severity
    @property
    def Category(self):    return self._Category
    @property
    def ScriptType(self):    return self._ScriptType
    @property
    def OsType(self):    return self._OsType
    @property
    def DbType(self):    return self._DbType
    @property
    def RecommendedFix(self):    return self._RecommendedFix
    @property
    def TestScript(self):    return self._TestScript
    @property
    def AdditionalScript(self):    return self._AdditionalScript
    @property
    def ResultsLayout(self):    return self._ResultsLayout
    #
    # Assessment test internal functions
    #
    @staticmethod
    def _get_all_assessment_tests(connection):
        try:
            assessmentTestNames = connection._mx_api('GET', '/conf/assessment/tests')
        except:
            raise MxException("Failed getting Assessment Policies")
        assessmentTests = []
        for assessmentTestName in assessmentTestNames:
            if '/' in assessmentTestName or r'"' in assessmentTestName or '$' in assessmentTestName:
                print("%s cannot be used by the API. Skipping..." % assessmentTestName)
                continue
            try:
                assessmentTest = connection._mx_api('GET', '/conf/assessment/tests/' + assessmentTestName)
            except:
                raise MxException("Failed getting Assessment Test '%s'" % assessmentTestName)
            assessmentTest = AssessmentTest.validateEmptyIndices(assessmentTest)
            assessTestObj = AssessmentTest(connection=connection, Name=assessmentTest['name'], Description=assessmentTest['description'],Severity=assessmentTest['severity'],
                                           Category=assessmentTest['category'], ScriptType=assessmentTest['scriptType'], OsType=assessmentTest['osType'], DbType=assessmentTest['dbType'],
                                           RecommendedFix=assessmentTest['recommended-fix'], TestScript=assessmentTest['test-script'], AdditionalScript=assessmentTest['additional-script'],
                                           ResultsLayout=assessmentTest['result-layout'])
            assessmentTests.append(assessTestObj)
        return assessmentTests

    @staticmethod
    def _get_assessment_test(connection, Name=None):
        validate_string(Name=Name)
        obj_exists = AssessmentTest._exists(connection=connection, Name=Name)
        if obj_exists:
            return obj_exists
        try:
            assessmentTest = connection._mx_api('GET', '/conf/assessment/tests/' + Name)
        except:
            raise MxException("Failed getting Assessment Test '%s'" % Name)
        assessmentTest = AssessmentTest.validateEmptyIndices(assessmentTest)
        return AssessmentTest(connection=connection, Name=assessmentTest['name'], Description=assessmentTest['description'],Severity=assessmentTest['severity'],
                                           Category=assessmentTest['category'], ScriptType=assessmentTest['scriptType'], OsType=assessmentTest['osType'], DbType=assessmentTest['dbType'],
                                           RecommendedFix=assessmentTest['recommended-fix'], TestScript=assessmentTest['test-script'], AdditionalScript=assessmentTest['additional-script'],
                                           ResultsLayout=assessmentTest['result-layout'])
    @staticmethod
    def _create_assessment_test(connection, Name=None, Description=None,
                                Severity=None, Category=None, ScriptType=None, OsType=None, DbType=None, RecommendedFix=None,
                                TestScript=None, AdditionalScript=None, ResultsLayout=[]):
        validate_string(Name=Name)
        body = {}
        body['name'] = Name
        body['description'] = Description
        body['severity'] = Severity
        body['category'] = Category
        body['scriptType'] = ScriptType
        body['osType'] = OsType
        body['dbType'] = DbType
        body['recommended-fix'] = RecommendedFix
        body['test-script'] = TestScript
        body['additional-script'] = AdditionalScript
        body['result-layout'] = ResultsLayout

        print(json.dumps(body))

        try:
            connection._mx_api('POST', '/conf/assessment/tests/%s' % Name, data=json.dumps(body))
        except:
            raise MxException("Failed creating Assessment Test '%s'" % Name)
        return AssessmentTest(connection=connection, Name=Name, Description=Description, Severity=Severity,
                                           Category=Category, ScriptType=ScriptType, OsType=OsType, DbType=DbType,
                                           RecommendedFix=RecommendedFix, TestScript=TestScript, AdditionalScript=AdditionalScript,
                                           ResultsLayout=ResultsLayout)
    @staticmethod
    def _update_assessment_test(connection, Name=None, Description=None,
                                Severity=None, Category=None, ScriptType=None, OsType=None, DbType=None, RecommendedFix=None,
                                TestScript=None, AdditionalScript=None, ResultsLayout=[]):
        raise MxException("Assessment Update API currently not supported")
    @staticmethod
    def _delete_assessment_test(connection, Name=None):
        raise MxException("Assessment Delete API currently not supported")

    @staticmethod
    def validateEmptyIndices(assessmentTest):
        if 'name' not in assessmentTest:
            assessmentTest['name'] = None
        if 'description' not in assessmentTest:
            assessmentTest['description'] = None
        if 'severity' not in assessmentTest:
            assessmentTest['severity'] = None
        if 'category' not in assessmentTest:
            assessmentTest['category'] = None
        if 'scriptType' not in assessmentTest:
            assessmentTest['scriptType'] = None
        if 'osType' not in assessmentTest:
            assessmentTest['osType'] = None
        if 'dbType' not in assessmentTest:
            assessmentTest['dbType'] = None
        if 'recommended-fix' not in assessmentTest:
            assessmentTest['recommended-fix'] = None
        if 'test-script' not in assessmentTest:
            assessmentTest['test-script'] = None
        if 'additional-script' not in assessmentTest:
            assessmentTest['additional-script'] = None
        if 'result-layout' not in assessmentTest:
            assessmentTest['result-layout'] = []

        return assessmentTest