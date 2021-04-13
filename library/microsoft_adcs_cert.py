# READ LICENSE before using this module
from __future__ import absolute_import, division, print_function
__metaclass__ = type
ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['stableinteface'],
                    'supported_by': 'curated'}
DOCUMENTATION = r'''
---
module: msacds_certreq
short_description: Upload CSR and download signed SSL certificate from Microsoft Active Directory Certificate Services.
description:
    - This module generates and downloads certs from internal Microsoft Active Directory Certificate Services (CA).
    - This module does not generate a CSR, CSR should be pre-existing in local disk and full path for CSR file should be passed in as variable.
    - This module was tested only against Windows Server 2012 R2 Datacenter 64 bit Edition.
    - This module needs requests_ntlm [pip install requests_ntlm] package as a pre-requisite.
version_added: 2.9
author: nareshhkumar512@gmail.com
options:
  ca_server:
    description:
       - Include Fully Qualified domain name or IP address of the Certificate Microsoft Active Directory Certificate server. 
         This server should be reachable from controller and 'https' GUI should be enabled.
    type: str
    required: True
  user:
    description:
       - Admin user name that has access to request certificate from the CA.
    type: str
    required: True
  password:
    description:
       - Password of the C(user).
    type: str
    required: True
  ca_template_name:
    description:
       - Name of the template that will be used in CA to sign the CSR request.
    type: str
    required: True
  san_names:
    description:
       - List of Subject Alternative Names.
    type: str
    required: True
  csr_file_path:
    description:
       - Complete path to CSR file in local disc.
    type: str
    required: True
  cert_encoding:
    description:
       - Option to specify the encoding type while downloading the cert.
    type: str
    choices:
      - pem
      - der
    default: pem
notes:
   - Tested only against Windows Server 2012 R2 Datacenter 64 bit Edition.
   - Backslash should be escaped , refer example.
   - 'Compatible with both py v2.7 and py v3.6+'
   - requests_ntlm package should be installed and available.
        pip install requests_ntlm
        pip3 install requests_ntlm
   - Cert file will be written in the same directory as input CSR file.
'''
EXAMPLES = r'''
- name: Upload a CSR and download Signed SSL cert
  msadcs_certreq:
    ca_server: msadserver.mydomain.com
    user: "domain\\user"
    password: "myadminpassword"
    ca_template_name: CSR_SIGNING_TEMPLATE_2048
    san_names:
      - altname1.mydomain.com
      - altname2.mydomain.com
    csr_file_path: '/full/path/to/csr/file'
    cert_encoding: pem
  register: result
'''
RESULT = r'''
msacds_certreq_facts:
   cert_full_path : '/full/path/to/cert/file'
   err: '<Disposition Message if any> or null'
'''
from ansible.module_utils.basic import AnsibleModule
import json
import re
import sys
import time
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from requests_ntlm import HttpNtlmAuth

if sys.version.startswith('3') :
    from urllib.parse import quote_plus as encode_util
    SLEEP_TIME=3
else :
    from urllib import quote_plus as encode_util
    SLEEP_TIME=3.0

ENCODING_MAP = {
    'pem':'b64',
    'der':'bin'
}

class ArgumentSpec(object):
    '''
    Aruguments specification to align with Ansible argument class.
    '''
    def __init__(self):
        self.supports_check_mode = False
        argument_spec = dict(
            ca_server=dict(
                required=True,
                aliases=['ca'],
                type = 'str'
            ),
            user=dict(
                required=True,
                aliases=['ca_admin_user'],
                type='str'
                ),
            password=dict(
                required=True,
                aliases=['ca_admin_pass'],
                type='str',
                no_log=True
            ),
            ca_template_name=dict(
                required=True,
                type='str'
            ),
            san_names=dict(
                required=True,
                type='list'
            ),
            csr_file_path=dict(
                required=True,
                type='str'
            ),
            cert_encoding=dict(
                type='str',
                default='pem',
                choices=['pem', 'der']
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)

def _get_csr_content() :
    '''
    private function to read csr from given file path and return URL encoded CSR data.
    Parameters :
            None  : csr_path(global str) : Full path to CSR file.

    Returns :
            URL encoded CSR data only the content is returned header ('BEGIN CERTIFICATE REQUEST') 
            and footer ('END CERTIFICATE REQUEST') are removed.(str)
    '''
    csr_f = open(csr_path,'r')
    csr_data = csr_f.read().replace('-----BEGIN CERTIFICATE REQUEST-----','')
    csr_f.close()
    csr_data = csr_data.split('-----END CERTIFICATE REQUEST-----',1)
    csr_data = csr_data[0]
    return csr_data

def _get_crt_attrib():
    '''
    private function to frame CertAttrib fpor the CURL calls.
    Parameters :
            None  : sans(global list(str)) : List of San names.
            None  : ca_template(global str) : Template name to use for CSR signing.

    Returns :
            URL encoded crt_attribute data neccessary for the cert request call.(str)
    '''
    crt_attrb = ''
    san_list = []
    for each_san in sans :
        san_list.append("dns={each_san}".format(each_san=each_san))
    #CA SAN format : SAN:dns=host1.mydomain.com&dns=host2&dns=host3.mydomain.com
    san_updated = 'SAN:'+('&'.join(san_list))
    crt_attrb += san_updated
    crt_attrb += "\nCertificateTemplate:{ca_template}".format(ca_template=ca_template)
    crt_attrb += '\nUserAgent:Mozilla/5.0 \(Windows NT 10.0; Win64; x64\) AppleWebKit/537.36 \(KHTML, like Gecko\) Chrome/81.0.4044.122 Safari/537.36'
    return crt_attrb

def _request_cert_req():
    '''
    private function to submit a csr signing request.
    Parameters :
            None  : global vars

    Returns :
            request ID to download cert(str)
    Raises:
            Disposition message if any.
    '''
    payload =dict()
    payload['Mode'] = 'newreq'
    payload['CertRequest'] = _get_csr_content()
    payload['CertAttrib'] = _get_crt_attrib()
    payload['TargetStoreFlags'] = 0
    payload['SaveCert'] = 'yes'
    payload['ThumbPrint'] = ''
    payload['FriendlyType'] = encode_util('Saved-Request Certificate')

    headers=dict()
    headers['Accept'] =  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
    headers['Accept-Encoding'] = "gzip, deflate, br"
    headers['Accept-Language'] = "en-US,en;q=0.9"
    headers['Content-Type'] = "application/x-www-form-urlencoded"
    headers['Cache-Control'] = "max-age=0"
    headers['Connection'] = "keep-alive"
    headers['Host'] = ca
    headers['Origin'] = "https://{ca}".format(ca=ca)
    headers['Referer'] = "https://{ca}/certsrv/certrqxt.asp".format(ca=ca)
    headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36"
    response = session.post(cert_req_ep,data=payload,headers=headers,verify=False)
    rsp_txt = response.text
    try :
        match = re.search('certnew.p7b\?ReqID=(.+?)\&\"\+getEncoding',rsp_txt)
        req_id = match.group(1)
    except Exception:
        match = re.search('The disposition message is (.+?)\\n',rsp_txt)
        err_msg = match.group(1)
        raise ValueError(err_msg)
    return req_id

def _download_cert_req(req_id,encoding) :
    '''
    private function to download certificate after signing.
    Parameters :
            req_id(str)  : request ID to download the certificate.

    Returns :
            cert_obj(dict) : returns { 'cert_full_path' '/full/path/to/cert/in/local/disc', 
                                       'err': 'Exception messages if any' or null}
    '''
    crt_path = csr_path.replace('.csr','.p7b')
    download_url = cert_down_ep.replace('<req_id>',req_id)

    headers=dict()
    headers['Accept'] =  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
    headers['Accept-Encoding'] = "gzip, deflate, br"
    headers['Accept-Language'] = "en-US,en;q=0.9"
    headers['Content-Type'] = "application/x-www-form-urlencoded"
    headers['Cache-Control'] = "max-age=0"
    headers['Connection'] = "keep-alive"
    headers['Host'] = ca
    headers['Origin'] = "https://{ca}".format(ca=ca)
    headers['Referer'] = "https://{ca}/certsrv/certfnsh.asp".format(ca=ca)
    headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36"
    err=None
    try:
        #Handle for DER formatted file download.
        if encoding == "der" :
          #Download only leaf cert  
          response = session.get(download_url.replace('.p7b','.cer'),headers=headers,verify=False)
          crt_path = csr_path.replace('.csr','.crt')
          file = open(crt_path, "wb")
          file.write(response.content)
        else:
          response = session.get(download_url,headers=headers,verify=False)
          file = open(crt_path, "w")
          file.write(response.text)
          file.close()
    except Exception as e:
        err = str(e)
    if err: 
        return {
          'cert_full_path' : None,
          'err' : err
        }
    return {
        'cert_full_path' : crt_path,
        'err' : err
     }

def _exec_module(module):
    '''
    private proxy ansible function to invoke the cert request routines.
    Parameters :
        module(AnsibleModule)  : request ID to download the certificate.

    Returns :
        updated results(dict) : returns updated cert object path { 'cert_full_path' '/full/path/to/cert/in/local/disc', 
                                       'err': 'Exception messages if any' or null}
    '''
    results = dict()
    args = module.params
    global csr_path
    csr_path = args['csr_file_path']
    global user
    user = args['user']
    global passwd
    passwd = args['password']
    global session
    session=requests.Session()
    session.verify=False
    session.auth = HttpNtlmAuth(user,passwd)
    global ca_template
    ca_template=args['ca_template_name']
    global sans
    sans=args['san_names']
    global ca
    ca=args['ca_server']
    global cert_req_ep
    cert_req_ep = 'https://{ca}/certsrv/certfnsh.asp'.format(ca=ca)
    encoding = args['cert_encoding']
    global cert_down_ep
    cert_down_ep = "https://{ca}/certsrv/certnew.p7b?ReqID=<req_id>&Enc={encoding}".format(ca=ca,encoding=ENCODING_MAP[encoding])    
    req_id = _request_cert_req()
    time.sleep(SLEEP_TIME)
    crt_path_obj = _download_cert_req(req_id,encoding)
    err_msg = crt_path_obj['err']
    if err_msg:
        module.fail_json(msg='400:'+err_msg)
    results.update(crt_path_obj)
    return results
def main():
    '''
    Main routine.
    Returns :
        path facts to the invoking ansible play (dict) : returns msacds_certreq_facts dict
                                    "msacds_certreq_facts": {
                                      "cert_full_path": "/tmp/ansiblehost.mydomain.com.p7b",
                                       "err": null
                                        },
                                        "msg": "200:Success"
                                      }

    '''
    spec = ArgumentSpec()
    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )
    try:
        results = _exec_module(module)
        module.exit_json(changed=True,msacds_certreq_facts=results,msg='200:Success')
    except Exception as ex:
        module.fail_json(msg='400:'+str(ex))
if __name__ == '__main__':
    main()