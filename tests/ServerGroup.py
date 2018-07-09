#!/usr/bin/python

import unittest
import imperva_sdk
import json

class TestServerGroup(unittest.TestCase):

  host                  = None
  user                  = "admin"
  password              = "password"
  port                  = 8083

  SiteName = "TestServerGroup site"
  ServerGroupName = "TestServerGroup server group"

  def setUp(self):
    if 'MX_HOST' in os.environ: self.host = os.environ['MX_HOST']
    if 'MX_USER' in os.environ: self.user = os.environ['MX_USER']
    if 'MX_PASSWORD' in os.environ: self.password = os.environ['MX_PASSWORD']
    if 'MX_PORT' in os.environ: self.port = int(os.environ['MX_PORT'])
    if not self.host:
      raise Exception("No MX specified (MX_HOST environment variable)")

    self.mx = imperva_sdk.MxConnection(Host=self.host, Username=self.user, Password=self.password, Port=self.port)
    self.site = self.mx.create_site(self.SiteName, update=True)

  def tearDown(self):
    self.mx.delete_site(self.SiteName)
    self.mx.logout()

  def test_get_all(self):
    sgs = self.site.get_all_server_groups()
    for sg in sgs:
      self.assertNotEqual(sg.Name, self.ServerGroupName)
    sg = self.site.create_server_group(self.ServerGroupName)
    sgs = self.site.get_all_server_groups()
    self.assertTrue(sg in sgs)

  def test_get(self):
    sg = self.site.get_server_group(self.ServerGroupName)
    self.assertEqual(sg, None)
    self.site.create_server_group(self.ServerGroupName)
    self.mx.logout()
    self.mx = imperva_sdk.MxConnection(Host=self.host, Username=self.user, Password=self.password)
    sg = self.mx.get_server_group(Name=self.ServerGroupName, Site=self.SiteName)
    self.assertTrue(self.ServerGroupName == sg.Name)

  def test_create(self):
    # Create is tested in the other tests so we can skip it
    pass

  def test_delete(self):
    try:
      self.site.delete_server_group(self.ServerGroupName)
      self.assertFalse(True)
    except:
      pass
    self.site.create_server_group(self.ServerGroupName)
    self.mx.logout()
    self.mx = imperva_sdk.MxConnection(Host=self.host, Username=self.user, Password=self.password)
    ret = self.mx.delete_server_group(Name=self.ServerGroupName, Site=self.SiteName)
    self.assertTrue(ret)

  def test_update(self):
    sg = self.site.create_server_group(self.ServerGroupName)
    self.assertTrue(sg.OperationMode == 'simulation')
    sg.OperationMode = 'active'
    sg.Name = '%s - 2' % self.ServerGroupName
    self.mx.logout()
    self.mx = imperva_sdk.MxConnection(Host=self.host, Username=self.user, Password=self.password)
    sg = self.mx.get_server_group(Name='%s - 2' % self.ServerGroupName, Site=self.SiteName)
    self.assertTrue(sg.OperationMode == 'active')

  def test_export_import(self):
    sg = self.site.create_server_group(self.ServerGroupName)
    export = self.mx.export_to_json(Discard=['policies'])
    export_dict = json.loads(export)
    # Remove from export sites that aren't part of the test
    test_site = []
    for site in export_dict['sites']:
      if site['Name'] == self.SiteName:
        test_site.append(site)
    export_dict['sites'] = test_site
    export_dict['sites'][0]['server_groups'][0]['OperationMode'] = 'disabled'
    self.site.delete_server_group(self.ServerGroupName)
    self.mx.logout()
    self.mx = imperva_sdk.MxConnection(Host=self.host, Username=self.user, Password=self.password)
    log = self.mx.import_from_json(json.dumps(export_dict))
    sg = self.mx.get_server_group(Name=self.ServerGroupName, Site=self.SiteName)
    self.assertTrue(sg.OperationMode == 'disabled')

if __name__ == '__main__':

  suite = unittest.TestLoader().loadTestsFromTestCase(TestServerGroup)
  unittest.TextTestRunner(verbosity=2).run(suite)
