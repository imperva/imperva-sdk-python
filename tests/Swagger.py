#!/usr/bin/python

import imperva_sdk
import json
import os
import unittest


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
    with open('resources/swagger.json', 'r') as fd:
      swagger_json = json.loads(fd.read())
    with open('resources/open_api.json', 'r') as fd:
      open_api_json = json.loads(fd.read())
    with open('resources/volume-api-v2.json', 'r') as fd:
      volume_api_json = json.loads(fd.read())
    srv.update_all_plugins(swagger_json_list=[open_api_json, volume_api_json], print_payload=True)

  def test_swagger_to_profile(self):
    app = self.mx.get_web_application(Name="Default Web Application", Site="Default Site", ServerGroup="zofim-sg", WebService="http-srv")
    with open('resources/swagger.json', 'r') as fd:
      swagger_json = json.loads(fd.read())
    with open('resources/open_api.json', 'r') as fd:
      open_api_json = json.loads(fd.read())
    with open('resources/volume-api-v2.json', 'r') as fd:
      volume_api_json = json.loads(fd.read())
    app.update_profile(SwaggerJson=open_api_json)
