#!/usr/bin/python

import imperva_sdk
import json
import os
import unittest
from imperva_sdk.SwaggerJsonFile import SwaggerJsonFile


class TestImpervaSdkSwagger(unittest.TestCase):
  host			= None
  user			= "admin"
  password		= "password"
  port			= 8083

  def setUp(self):
    if 'MX_HOST' in os.environ: self.host = os.environ['MX_HOST']
    if 'MX_USER' in os.environ: self.user = os.environ['MX_USER']
    if 'MX_PASSWORD' in os.environ: self.password = os.environ['MX_PASSWORD']
    if 'MX_PORT' in os.environ: self.port = int(os.environ['MX_PORT'])
    if not self.host:
      raise Exception("No MX specified (MX_HOST environment variable)")

    self.mx = imperva_sdk.MxConnection(Host=self.host, Username=self.user, Password=self.password, Port=self.port)

  def tearDown(self):
    self.mx.logout()

  def test_swagger_to_plugin(self):
    srv = self.mx.get_web_service(Name="http-srv", Site="Default Site", ServerGroup="zofim-sg")
    open_api_json = SwaggerJsonFile(file_path="resources/open_api.json")
    volume_api_json = SwaggerJsonFile(file_path="resources/volume-api-v2.json")
    srv.update_all_plugins(SwaggerJsonList=[open_api_json, volume_api_json], PrintPayload=True)

  def test_swagger_to_profile(self):
    app = self.mx.get_web_application(Name="Default Web Application", Site="Default Site", ServerGroup="zofim-sg", WebService="http-srv")
    open_api_json = SwaggerJsonFile("resources/open_api.json")
    app.update_profile(SwaggerJson=open_api_json)

  def test_expand_external_references(self):
    swagger = SwaggerJsonFile(file_path="resources/spec/swagger.json")
    print(swagger.base_path)
