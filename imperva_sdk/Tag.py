# Copyright 2018 Imperva. All rights reserved.

from imperva_sdk.core import *
import json

class Tag(MxObject):
  '''
  MX tag Class
  TODO orf - update comment
  >>> dataSet = mx.get_lookup_data_set("testDataSet")
  >>> dataSet.records
  [{'Organizational Account': 'dfgdfgdfgdfg', 'DB Account': '345345345'},
  {'Organizational Account': 'bbb1', 'DB Account': 'aaa1'},
  {'Organizational Account': '345345', 'DB Account': 'dfgdfg'},
  {'Organizational Account': '1111111111111', 'DB Account': 'ssssssss'}]

  Note that for setting Records the columns name must be exist
  >>> dataSet.Records = [{'Organizational Account': 'dfgdfgdfgdfg', 'DB Account': '345345345'}]

  Note that we don't support in updating/add columns. Only creating new dataset
  >>> dataSet.Columns
  [{'name': 'DB Account', 'key': True}, {'name': 'Organizational Account', 'key': False}]

  >>> # Create user defined copy of dataset
  >>> dataset_dict = dict(dataSet)
  >>> dataset_dict['Name'] = 'user defined - %s' % dataset_dict['Name']
  >>> dataset_dict['update'] = True
  >>> mx._create_lookup_data_set(**dataset_dict)
  <imperva_sdk 'LookupDataSet' Object - 'user defined - testDataSet'>

  '''


  # Store created tags objects in_instances to prevent duplicate instances and redundant API calls
  def __new__(Type, *args, **kwargs):
    obj_exists = Tag._exists(connection=kwargs['connection'], Name=kwargs['Name'])
    if obj_exists:
      return obj_exists
    else:
      obj = super(MxObject, Type).__new__(Type)
      kwargs['connection']._instances.append(obj)
      return obj

  @staticmethod
  def _exists(connection=None, Name=None):
    for cur_obj in connection._instances:
      if type(cur_obj).__name__ == 'Tag':
        if cur_obj.Name == Name:
          return cur_obj
    return None

  def __init__(self, connection=None, Name=None):
    super(Tag, self).__init__(connection=connection, Name=Name)


  @property
  def Name(self):
    ''' The name of the tag (string) '''
    return self._Name

  #
  # Tag internal functions
  #

  @staticmethod
  def _get_all_tags(connection):
    res = connection._mx_api('GET', '/conf/tags')
    tags_objects = []
    for tag_name in res['tags']:
      tags_objects.append(Tag(connection=connection, Name=tag_name))
    return tags_objects

  @staticmethod
  def _create_tag(connection, Name=None):
    validate_string(Name=Name)
    # tag_list = connection._get_all_tags(Name=Name)
    # if Name in tag_list:
    #   if not update:
    #     raise MxException("Tag '%s' already exists" % Name)
    try:
      res = connection._mx_api('POST', '/conf/tags/%s' % Name)
    except Exception as e:
      raise MxException("Failed creating tag: %s" % e)

    return Tag(connection=connection, Name=Name)
