# Copyright 2018 Imperva. All rights reserved.

import json
from imperva_sdk.core import *


# Classification Scan - Iris

class ClassificationProfile(MxObject):
    '''
    MX Classification Profile Class

    '''

    # Store created Classification Scan objects in _instances to prevent duplicate instances and redundant API calls
    def __new__(ClassType, *args, **kwargs):
        obj_exists = ClassificationProfile._exists(connection=kwargs['connection'], Name=kwargs['Name'])
        if obj_exists:
            return obj_exists
        else:
            obj = super(MxObject, ClassType).__new__(ClassType)
            kwargs['connection']._instances.append(obj)
            return obj

    @staticmethod
    def _exists(connection=None, Name=None):
        for cur_obj in connection._instances:
            if type(cur_obj).__name__ == 'ClassificationProfile':
                if cur_obj.Name == Name:
                    return cur_obj
        return None

    def __init__(self, connection=None, Name=None, SiteName=None, DataTypes=[], AutoAcceptResults=None, ScanViewsAndSynonyms=None,
                 SaveSampleData=None, DataSampleAccuracy=None, ScanSystemSchemas=None, DbsAndSchemasUsage=None, DbsAndSchemas=[],
                 ExcludeTablesAndColumns=[], DelayBetweenQueries=None, NumberOfConcurrentDbConnection=None):
        super(ClassificationProfile, self).__init__(connection=connection, Name=Name)
        validate_string(Name=Name)
        self._SiteName = SiteName
        self._DataTypes = MxList(DataTypes)
        self._AutoAcceptResults = AutoAcceptResults
        self._ScanViewsAndSynonyms = ScanViewsAndSynonyms
        self._SaveSampleData = SaveSampleData
        self._DataSampleAccuracy = DataSampleAccuracy
        self._ScanSystemSchemas = ScanSystemSchemas
        self._DbsAndSchemasUsage = DbsAndSchemasUsage
        self._DbsAndSchemas = MxList(DbsAndSchemas)
        self._ExcludeTablesAndColumns = MxList(ExcludeTablesAndColumns)
        self._DelayBetweenQueries = DelayBetweenQueries
        self._NumberOfConcurrentDbConnection = NumberOfConcurrentDbConnection



    #
    # Classification Profile Parameters Getters
    #
    @property
    def Name(self):
        ''' The name of the profile (string) '''
        return self._Name

    @property
    def SiteName(self):
        ''' Site Name (string) '''
        return self._SiteName

    @property
    def DataTypes(self):
        '''
        Data Types configured in this profile (list of Strings)
        '''
        return self._DataTypes


    @property
    def AutoAcceptResults(self):
        ''' Is Auto accept result (boolean) '''
        return self._AutoAcceptResults

    @property
    def ScanViewsAndSynonyms(self):
        ''' Is Scanning views and synonyms? (boolean) '''
        return self._ScanViewsAndSynonyms

    @property
    def SaveSampleData(self):
        ''' Is saving sample data (boolean) '''
        return self._SaveSampleData


    @property
    def DataSampleAccuracy(self):
        ''' Data sample accuracy (float) '''
        return self._DataSampleAccuracy


    @property
    def ScanSystemSchemas(self):
        ''' Is scanning system schemas (boolean) '''
        return self._ScanSystemSchemas

    @property
    def DbsAndSchemasUsage(self):
        ''' DB and Schema Usage (string) '''
        return self._DbsAndSchemasUsage

    @property
    def DbsAndSchemas(self):
        '''
        DBs and Schemas configured in this profile (list of Dictionaries)
        '''
        return self._DbsAndSchemas

    @property
    def ExcludeTablesAndColumns(self):
        '''
        Tables and columns to be excluded configured in this profile (list of Dictionaries)
        '''
        return self._ExcludeTablesAndColumns

    @property
    def DelayBetweenQueries(self):
        ''' Delay between queries (Long) '''
        return self._DelayBetweenQueries

    @property
    def NumberOfConcurrentDbConnection(self):
        ''' _Number Of Concurrent Db Connection (Integer) '''
        return self._NumberOfConcurrentDbConnection



    ##########
    # Setters
    ##########


    @SiteName.setter
    def SiteName(self, SiteName):
        if SiteName != self._SiteName:
            self._connection._update_classification_profile(Name=self._Name, Parameter='siteName', Value=SiteName)
            self._SiteName = SiteName


    @DataTypes.setter
    def DataTypes(self, DataTypes):
        tmp1 = []
        for cur_item in DataTypes:
            tmp1.append(''.join(sorted(str(cur_item).replace('u', ''))))
        tmp1 = sorted(tmp1)
        tmp2 = []
        for cur_item in self._DataTypes:
            tmp2 = sorted(tmp2)
            tmp2.append(''.join(sorted(str(cur_item).replace('u', ''))))
        tmp2 = sorted(tmp2)
        if tmp1 != tmp2:
            self._connection._update_classification_profile(Name=self._Name, Parameter='dataTypes', Value=DataTypes)
            self._DataTypes = DataTypes


    @AutoAcceptResults.setter
    def AutoAcceptResults(self, AutoAcceptResults):
        if AutoAcceptResults != self._AutoAcceptResults:
            self._connection._update_classification_profile(Name=self._Name, Parameter='autoAcceptResults', Value=AutoAcceptResults)
            self._AutoAcceptResults = AutoAcceptResults


    @ScanViewsAndSynonyms.setter
    def ScanViewsAndSynonyms(self, ScanViewsAndSynonyms):
        if ScanViewsAndSynonyms != self._ScanViewsAndSynonyms:
            self._connection._update_classification_profile(Name=self._Name, Parameter='scanViewsAndSynonyms', Value=ScanViewsAndSynonyms)
            self._ScanViewsAndSynonyms = ScanViewsAndSynonyms


    @SaveSampleData.setter
    def SaveSampleData(self, SaveSampleData):
        if SaveSampleData != self._SaveSampleData:
            self._connection._update_classification_profile(Name=self._Name, Parameter='saveSampleData', Value=SaveSampleData)
            self._SaveSampleData = SaveSampleData


    @DataSampleAccuracy.setter
    def DataSampleAccuracy(self, DataSampleAccuracy):
        if DataSampleAccuracy != self._DataSampleAccuracy:
            self._connection._update_classification_profile(Name=self._Name, Parameter='dataSampleAccuracy', Value=DataSampleAccuracy)
            self._DataSampleAccuracy = DataSampleAccuracy


    @ScanSystemSchemas.setter
    def ScanSystemSchemas(self, ScanSystemSchemas):
        if ScanSystemSchemas != self._ScanSystemSchemas:
            self._connection._update_classification_profile(Name=self._Name, Parameter='scanSystemSchemas', Value=ScanSystemSchemas)
            self._ScanSystemSchemas = ScanSystemSchemas


    @DbsAndSchemasUsage.setter
    def DbsAndSchemasUsage(self, DbsAndSchemasUsage):
        if DbsAndSchemasUsage != self._DbsAndSchemasUsage:
            self._connection._update_classification_profile(Name=self._Name, Parameter='dbsAndSchemasUsage', Value=DbsAndSchemasUsage)
            self._DbsAndSchemasUsage = DbsAndSchemasUsage


    @DbsAndSchemas.setter
    def DbsAndSchemas(self, DbsAndSchemas):
        tmp1 = []
        for cur_item in DbsAndSchemas:
            tmp1.append(''.join(sorted(str(cur_item).replace('u', ''))))
        tmp1 = sorted(tmp1)
        tmp2 = []
        for cur_item in self._DbsAndSchemas:
            tmp2 = sorted(tmp2)
            tmp2.append(''.join(sorted(str(cur_item).replace('u', ''))))
        tmp2 = sorted(tmp2)
        if tmp1 != tmp2:
            self._connection._update_classification_profile(Name=self._Name, Parameter='dbsAndSchemas', Value=DbsAndSchemas)
            self._DbsAndSchemas = DbsAndSchemas


    @ExcludeTablesAndColumns.setter
    def ExcludeTablesAndColumns(self, ExcludeTablesAndColumns):
            tmp1 = []
            for cur_item in ExcludeTablesAndColumns:
                tmp1.append(''.join(sorted(str(cur_item).replace('u', ''))))
            tmp1 = sorted(tmp1)
            tmp2 = []
            for cur_item in self._ExcludeTablesAndColumns:
                tmp2 = sorted(tmp2)
                tmp2.append(''.join(sorted(str(cur_item).replace('u', ''))))
            tmp2 = sorted(tmp2)
            if tmp1 != tmp2:
                self._connection._update_classification_profile(Name=self._Name, Parameter='excludeTablesAndColumns', Value=ExcludeTablesAndColumns)
                self._ExcludeTablesAndColumns = ExcludeTablesAndColumns


    @DelayBetweenQueries.setter
    def DelayBetweenQueries(self, DelayBetweenQueries):
        if DelayBetweenQueries != self._DelayBetweenQueries:
            self._connection._update_classification_profile(Name=self._Name, Parameter='delayBetweenQueries', Value=DelayBetweenQueries)
            self._DelayBetweenQueries = DelayBetweenQueries


    @NumberOfConcurrentDbConnection.setter
    def NumberOfConcurrentDbConnection(self, NumberOfConcurrentDbConnection):
        if NumberOfConcurrentDbConnection != self._NumberOfConcurrentDbConnection:
            self._connection._update_classification_profile(Name=self._Name, Parameter='numberOfConcurrentDbConnection', Value=NumberOfConcurrentDbConnection)
            self._NumberOfConcurrentDbConnection = NumberOfConcurrentDbConnection


    ##########################################################
    # static methods for GET ALL, GET, CREATE. DELETE, UPDATE
    ##########################################################

    @staticmethod
    def _get_all_classification_profiles(connection):
        try:
            profile_names = connection._mx_api('GET', '/conf/classification/profiles')
        except:
            raise MxException("Failed getting Classification Profiles")
        prof_objects = []
        for name in profile_names:
            prof_obj = connection.get_classification_profile(Name=name)
            if prof_obj:
                prof_objects.append(prof_obj)
        return prof_objects



    @staticmethod
    def _get_classification_profile(connection, Name=None):
        validate_string(Name=Name)
        obj_exists = ClassificationProfile._exists(connection=connection, Name=Name)
        if obj_exists:
            return obj_exists
        try:
            res = connection._mx_api('GET', '/conf/classification/profiles/%s' % Name)
        except:
            return None

        if 'site-name' not in res: res['site-name'] = None
        if 'data-types' not in res: res['data-types'] = []
        if 'auto-accept-results' not in res: res['auto-accept-results'] = None
        if 'scan-views-and-synonyms' not in res: res['scan-views-and-synonyms'] = None
        if 'save-sample-data' not in res: res['save-sample-data'] = None
        if 'data-sample-accuracy' not in res: res['data-sample-accuracy'] = None
        if 'scan-system-schemas' not in res: res['scan-system-schemas'] = None
        if 'dbs-and-schemas-usage' not in res: res['dbs-and-schemas-usage'] = None
        if 'dbs-and-schemas' not in res: res['dbs-and-schemas'] = []
        if 'exclude-tables-and-columns' not in res: res['exclude-tables-and-columns'] = []
        if 'delay-between-queries' not in res: res['delay-between-queries'] = None
        if 'number-of-concurrent-db-connection' not in res: res['number-of-concurrent-db-connection'] = None

        return ClassificationProfile(connection=connection, Name=Name, SiteName=res['site-name'], DataTypes=res['data-types'],
                                     AutoAcceptResults=res['auto-accept-results'], ScanViewsAndSynonyms=res['scan-views-and-synonyms'],
                                     SaveSampleData=res['save-sample-data'], DataSampleAccuracy=res['data-sample-accuracy'],
                                     ScanSystemSchemas=res['scan-system-schemas'],DbsAndSchemasUsage=res['dbs-and-schemas-usage'],
                                     DbsAndSchemas=res['dbs-and-schemas'],ExcludeTablesAndColumns=res['exclude-tables-and-columns'],
                                     DelayBetweenQueries=res['delay-between-queries'],
                                     NumberOfConcurrentDbConnection=res['number-of-concurrent-db-connection']
                                     )



    @staticmethod
    def _create_classification_profile(connection, Name=None, SiteName=None, DataTypes=[], AutoAcceptResults=None,
                                        ScanViewsAndSynonyms=None, SaveSampleData=None, DataSampleAccuracy=None,
                                        ScanSystemSchemas=None, DbsAndSchemasUsage=None, DbsAndSchemas=[],
                                        ExcludeTablesAndColumns=[], DelayBetweenQueries=None,
                                       NumberOfConcurrentDbConnection=None, update=False):
        validate_string(Name=Name)
        profile = connection.get_classification_profile(Name=Name)
        if profile:
            if not update:
                raise MxException("Profile '%s' already exists" % Name)
            else:
                # Update existing profile
                parameters = locals()
                for cur_key in parameters:
                    if is_parameter.match(cur_key) and cur_key != 'Name' and parameters[cur_key] != None:
                        setattr(profile, cur_key, parameters[cur_key])
            return profile
        else:
            # Create new profile
            body = {
                'site-name': SiteName,
            }
            if DataTypes: body['data-types'] = DataTypes
            if AutoAcceptResults: body['auto-accept-results'] = AutoAcceptResults
            if ScanViewsAndSynonyms: body['scan-views-and-synonyms'] = ScanViewsAndSynonyms
            if SaveSampleData: body['save-sample-data'] = SaveSampleData
            if DataSampleAccuracy: body['data-sample-accuracy'] = DataSampleAccuracy
            if ScanSystemSchemas: body['scan-system-schemas'] = ScanSystemSchemas
            if DbsAndSchemasUsage: body['dbs-and-schemas-usage'] = DbsAndSchemasUsage
            if DbsAndSchemas: body['dbs-and-schemas'] = DbsAndSchemas
            if ExcludeTablesAndColumns: body['exclude-tables-and-columns'] = ExcludeTablesAndColumns
            if DelayBetweenQueries: body['delay-between-queries'] = DelayBetweenQueries
            if NumberOfConcurrentDbConnection: body['number-of-concurrent-db-connection'] = NumberOfConcurrentDbConnection


            connection._mx_api('POST', '/conf/classification/profiles/%s' % Name, data=json.dumps(body))
            return ClassificationProfile(connection=connection, Name=Name, SiteName=SiteName, DataTypes=DataTypes,
                                         AutoAcceptResults=AutoAcceptResults, ScanViewsAndSynonyms=ScanViewsAndSynonyms,
                                         SaveSampleData=SaveSampleData, DataSampleAccuracy=DataSampleAccuracy,
                                         ScanSystemSchemas=ScanSystemSchemas, DbsAndSchemasUsage=DbsAndSchemasUsage,
                                         DbsAndSchemas=DbsAndSchemas, ExcludeTablesAndColumns=ExcludeTablesAndColumns,
                                         DelayBetweenQueries=DelayBetweenQueries,
                                         NumberOfConcurrentDbConnection=NumberOfConcurrentDbConnection
                                         )



    @staticmethod
    def _delete_classification_profile(connection, Name=None):
        validate_string(Name=Name)
        profile = connection.get_classification_profile(Name=Name)
        if profile:
            connection._mx_api('DELETE', '/conf/classification/profiles/%s' % Name)
            connection._instances.remove(profile)
            del profile
        else:
            raise MxException("Profile does not exist")
        return True


    @staticmethod
    def _update_classification_profile(connection, Name=None, Parameter=None, Value=None):
        body = {Parameter: Value}
        connection._mx_api('PUT', '/conf/classification/profiles/%s' % Name, data=json.dumps(body))

        return True
