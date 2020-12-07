# Documentation

## Package: ansible role microsoft_adcs_cert

This Ansible role, microsoft_adcs_cert, is designed to make it easy for a Linux machine to acquire a certificate signed from a Microsoft Active Directory Certificate Services CA server.

## Pre-Requisites:

 1. Ansible v2.9 or above
 2. requests_ntlm python package should be installed and available in ansible control machine. Use below command if the package is not avaialble.\
        `pip install requests_ntlm`
 3. CA server should be reachable from Ansible controller and 'https' webservices should be enabled and available.

## Steps to install:

  1. Navigate to your ansible project's root directory. 
  2. Clone the role using below command\
        `git clone https://github.com/nareshhkumar512/microsoft_adcs_cert.git`
  3. Include in main play.

### Usage inside a playbook:
```yaml
- hosts: localhost
  gather_facts: no
  connection: local
  roles:
  - microsoft_adcs_cert
 ```
  _Refer examples/msadcs_request_cert.yml documentation section. for more information_

The role downloads the signed pem/der formatted SSL certificate file.

## Input Requirements:
|Variable Name| Usage |
|--|--|
|ca_server| Include Fully Qualified domain name or IP address of the Certificate Microsoft Active Directory Certificate server. |
| ca_admin_user |  Admin user with permission to generate certificate using template mentioned in `ca_template_name` variable |
|ca_admin_pass| Admin password |
|ca_template_name| Name of the certificate template to be used to sign the CSR |
|san_names| List of Subject alternative names |
|csr_file_path| Full path to the CSR file in local machine |
|cert_encoding_type| Specify certificate encoding type, current supported formats are `pem` or `der` |

## Notes:

- Tested only against Windows Server 2012 R2 Datacenter 64 bit Edition.
- Any backslash in username/password should be escaped with '\\', refer examples/msadcs_request_cert.yml .
- Compatible with both py v2.7 and py v3.6+
- SSL Certificate file will be downloaded in the same directory as input CSR file.


## Weblinks

* Fundamental curl statements https://stackoverflow.com/questions/31283476/submitting-base64-csr-to-a-microsoft-ca-via-curl/39722983#39722983

## Generosity:

- Designer Brands Inc.

## Inspired by:

- Nate Britton (https://www.linkedin.com/in/nsbritton)

- https://bgstack15.wordpress.com/author/bgstack15/

## Next Steps
Happy to take any feedback or pull requests from others. DM me in [Linkedin](https://www.linkedin.com/in/nareshhkumar512/) for questions.