import re
import requests
import os
import json
import threading

from time import sleep
from imperva-sdk.core import *


class ADCUploader(MxObject):
    """A simple example class"""
    def __init__(self, connection):
        self.cookies = {'JSESSIONID': str(connection._MxConnection__Headers['Cookie'])[11:],
                        'SSOSESSIONID': str(connection._MxConnection__Headers['Cookie'])[11:]}
        self.ip = connection.Host

    # for tracking the upload we need the script id.
    def get_script_id(self):

        headers = {
            'Host': '%s:8083' % self.ip,
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Referer': 'https://%s:8083/SecureSphere/app/' % self.ip,
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
        }

        # getting script id for later tracking
        api_url = 'https://%s:8083/SecureSphere/ui/main.html' % (self.ip)
        r = requests.get(api_url, cookies=self.cookies, verify=False)
        regex_result = re.search(r"JAWR.dwr_scriptSessionId='([a-zA-Z0-9_.-]*)'", r.text)

        # check if not found?
        # No need, we believe in ourselves :)
        return regex_result.group(1)

    # uploading by multipart post request
    def upload_adc_content(self, path):
        api_url = 'https://%s:8083/SecureSphere/ui/adc_content.html' % self.ip

        # secure sphere want to receive it like this.
        prod = open(path, 'rb')

        headers = {
            'Host': '%s:8083' % self.ip,
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Referer': 'https://%s:8083/SecureSphere/ui/main.html' % self.ip,
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        r = requests.post(api_url, files={'ADC1': prod},
                          cookies=self.cookies, headers=headers, verify=False)

        return r.status_code == 200

    # check the status of the upload, need to parse the weird json.
    def check_upload_status(self, sessionid):
        api_url = 'https://%s:8083/SecureSphere/dwr/call/plaincall/AsyncOperationsContainer.getOperationState.dwr' % self.ip

        headers = {
            'Host': '%s:8083' % self.ip,
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Referer': 'https://%s:8083/SecureSphere/ui/main.html' % self.ip,
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'text/plain'
        }

        data = 'callCount=1\n' \
               'page=/SecureSphere/ui/main.html\n' \
               'httpSessionId=\n' \
               'scriptSessionId={0}\n' \
               'c0-scriptName=AsyncOperationsContainer\n' \
               'c0-methodName=getOperationState\n' \
               'c0-id=0\n' \
               'c0-param0=string:%2Fadc_content.html\n' \
               'c0-param1=boolean:false\n' \
               'batchId=5'.format(sessionid)

        response = requests.post(api_url, headers=headers, data=data, cookies=self.cookies, verify=False)

        regex_result = re.search(r"dwr\.engine\.\_remoteHandleCallback.*({.*})", response.text)

        if regex_result is not None:
            # split to from of: ['attributes:s0', 'childrenProgressInfo:s1'...
            result_touple = re.findall(r"([a-zA-Z0-9_.-]*):([a-zA-Z0-9\" _.-]*)", regex_result.group(1))
            response = {}
            for tup in result_touple:
              response[tup[0]] = tup[1]
            return response
        else:
            return {}

    def wait_upload_finish(self, scriptid):

        status = self.check_upload_status(scriptid)

        while status == {} or status['inProgress'] == 'true':
            sleep(1)
            status = self.check_upload_status(scriptid)

        #weird secure sphere, returning true even it is false.
        err_msg = ['"System is busy. Please try again later."',
                   '"Failed unpacking ADC content. Please verify you uploaded valid ADC content file"',
                   '"Failed to upload ADC content , duplicate item with full id"']


        if any([status['stage'] in err for err in err_msg]):
            status['success'] = 'false'

        return status

    def upload_adc_and_wait(self, path):
        script_id = self.get_script_id()
        self.upload_adc_content(path)
        return self.wait_upload_finish(script_id)

    def upload_adc_and_wait_multithreaded(self, path):
        script_id = self.get_script_id()

        upload_thread = threading.Thread(target=self.upload_adc_content, args=(path,))
        status_thread = threading.Thread(target=self.wait_upload_finish, args=(script_id,))

        upload_thread.start();
        status_thread.start();

        status_thread.join();
