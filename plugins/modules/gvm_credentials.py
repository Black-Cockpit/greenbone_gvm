# Copyright: (c) 2024, Hasni Mehdi <hasnimehdi@outlook.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)

import traceback
from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from gvm.connections import UnixSocketConnection

from ..module_utils.exceptions.ResourceInUseError import ResourceInUseError
from ..module_utils.models.GvmAdminCredentialsModel import GvmAdminCredentialsModel
from ..module_utils.models.CredentialsModel import CredentialsModel
from ..module_utils.libs.GvmManager import GvmManager

__metaclass__ = type
LIB_IMP_ERR = None
try:
    from gvm.protocols.gmp.requests.v225 import CredentialType

    HAS_LIB = True
except ModuleNotFoundError or NameError:
    HAS_LIB = False
    LIB_IMP_ERR = traceback.format_exc()

DOCUMENTATION = r'''
---
module: gvm_credentials

short_description: Manage credentials in Greenbone Vulnerability Manager (GVM)

version_added: "1.0.0"

description: 
    This module manages the credentials list on GVM.

options:
    socket_path:
        description: 
            - GVM socket path, default: /run/gvmd/gvmd.sock
        required: false
        type: str
        default: /run/gvmd/gvmd.sock
    gvm_username:
        description: 
            - GVM admin username: default: admin.
        required: false
        type: str
        default: admin
    gvm_password:
        description: 
            - GVM admin password: default: admin.
        required: false
        type: str
        default: admin
    name:
        description:
            - Name of the new credential
        required: true
        type: str
    credential_type:
        description:
            - The credentials type.
        required: true
        type: str
        choices: ['CLIENT_CERTIFICATE', 'SNMP', 'USERNAME_PASSWORD', 'USERNAME_SSH_KEY', 'SMIME_CERTIFICATE', 'PGP_ENCRYPTION_KEY',"PASSWORD_ONLY"]
    comment:
        description: 
            - Description of the credential
        required: false
        type: str
    allow_insecure:
        description:
            - Whether to allow insecure use of the credential.
        required: false
        type: bool 
        default: true
    certificate_base64:
        description:
            - Certificate for the credential. Required for client-certificate and smime credentials types.
        required: false
        type: str
    key_phrase:
        description:
            - Password used for the username+ssh-key credentials type (If applicable).
        required: false
        type: str
    private_key_base64:
        description:
            - Private key to use for login. Required for usk credentials type. Also used for the cc credentials type. 
            The supported key types (dsa, rsa, ecdsa, ...) and formats (PEM, PKC#12, OpenSSL, ...) depend on your installed GnuTLS version.
        required: false
        type: str
    login:
        description:
            - Username for the credential. Required for username+password, username+ssh-key and snmp credentials type.
        required: false
        type: str
    password:
        description:
            - Password for the credential. Used for username+password and snmp credentials types.
        required: false
        type: str
    auth_algorithm:
        description:
            - The SNMP authentication algorithm. Required for snmp credentials type.
        required: false
        type: str
        choices: ["MD5","SHA1"]
    community:
        description:
            - The SNMP community
        required: false
        type: str
    privacy_algorithm:
        description:
            - The SNMP privacy algorithm.
        required: false
        type: str
        choices: ["AES","DES"]
    privacy_password:
        description:
            - The SNMP privacy password
        required: false
        type: str
    public_key_base64:
        description:
            - GP public key in *armor* plain text format. Required
                for pgp credentials type.
        required: false
        type: str
    state:
        description:
            - State of the credentials, possible values are present, or absent. The default is present.
        required: false
        type: str
        default: present
        choices: ["absent", "present"]
'''

EXAMPLES = r'''
# Create a new credential of type USERNAME_PASSWORD
- name: Create USERNAME_PASSWORD credential
  gvm_credentials:
    name: "My Credential"
    credential_type: "USERNAME_PASSWORD"
    login: "user123"
    password: "pass123"
    comment: "This is a test credential"
    state: present

# Create a new SNMP credential
- name: Create SNMP credential
  gvm_credentials:
    name: "SNMP Credential"
    credential_type: "SNMP"
    login: "snmpuser"
    password: "snmppass"
    auth_algorithm: "SHA1"
    privacy_algorithm: "AES"
    comment: "SNMP credential for monitoring"
    state: present

# Create a new PGP encryption key credential
- name: Create PGP encryption key credential
  gvm_credentials:
    name: "PGP Credential"
    credential_type: "PGP_ENCRYPTION_KEY"
    public_key_base64: "{{ lookup('file', '/path/to/public/key.asc') }}"
    comment: "PGP public key credential"
    state: present

# Delete a credential
- name: Delete credential
  gvm_credentials:
    name: "Old Credential"
    state: absent
'''

RETURN = r'''
# These are the attributes that can be returned by the module.
changed:
    description: The state of the task.
    type: bool
    returned: always
msg:
    description: Error message if applicable.
    type: str
    returned: when_failed
failed:
    description: Indicate if the task failed
    type: bool
    returned: always
'''


def run_module():
    """
    gvm_credentials module
    Returns:
    """

    # gvm_credentials module arguments
    module_args = dict(
        socket_path=dict(type='str', required=False, default='/run/gvmd/gvmd.sock'),
        gvm_username=dict(type='str', required=False, default='admin'),
        gvm_password=dict(type='str', required=False, default='admin', no_log=True),
        name=dict(type='str', required=True),
        credential_type=dict(type='str', required=True,
                             choices=['CLIENT_CERTIFICATE', 'SNMP', 'USERNAME_PASSWORD', 'USERNAME_SSH_KEY',
                                      'SMIME_CERTIFICATE', 'PGP_ENCRYPTION_KEY', 'PASSWORD_ONLY']),
        comment=dict(type='str', required=False),
        allow_insecure=dict(type='bool', required=False, default=True),
        certificate_base64=dict(type='str', required=False),
        key_phrase=dict(type='str', required=False),
        private_key_base64=dict(type='str', required=False),
        login=dict(type='str', required=False),
        password=dict(type='str', required=False, no_log=True),
        auth_algorithm=dict(type='str', required=False, choices=['MD5', 'SHA1']),
        community=dict(type='str', required=False),
        privacy_algorithm=dict(type='str', required=False, choices=['AES', 'DES']),
        privacy_password=dict(type='str', required=False, no_log=True),
        public_key_base64=dict(type='str', required=False),
        state=dict(type='str', required=False, default='present', choices=['absent', 'present'])
    )

    # module result initialization
    result = dict(
        changed=False,
        failed=False,
    )

    # module initialization
    gvm_module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    # Validate socket path
    if gvm_module.params['socket_path'] is None or gvm_module.params['socket_path'] == '' or gvm_module.params[
        'socket_path'].isspace():
        gvm_module.fail_json(msg='socket_path is required')

    # Validate GVM username
    if gvm_module.params['gvm_username'] is None or gvm_module.params['gvm_username'] == '' or gvm_module.params[
        'gvm_username'].isspace():
        gvm_module.fail_json(msg='gvm_username is required')

    # Validate GVM username
    if gvm_module.params['gvm_password'] is None or gvm_module.params['gvm_password'] == '' or gvm_module.params[
        'gvm_password'].isspace():
        gvm_module.fail_json(msg='gvm_username is required')

    if not HAS_LIB:
        gvm_module.fail_json(msg=missing_required_lib("gvm"), exception=LIB_IMP_ERR)

    try:
        # Initialize GVM manager
        manager = GvmManager(UnixSocketConnection(path=gvm_module.params['socket_path']),
                             GvmAdminCredentialsModel(gvm_module.params['gvm_username'],
                                                      gvm_module.params['gvm_password']))

        # Initialize credentials
        credentials = CredentialsModel(name=gvm_module.params['name'],
                                       credential_type=gvm_module.params['credential_type'],
                                       comment=gvm_module.params['comment'],
                                       allow_insecure=gvm_module.params['allow_insecure'],
                                       certificate_base64=gvm_module.params['certificate_base64'],
                                       key_phrase=gvm_module.params['key_phrase'],
                                       private_key_pem=gvm_module.params['private_key_base64'],
                                       login=gvm_module.params['login'],
                                       password=gvm_module.params['password'],
                                       auth_algorithm=gvm_module.params['auth_algorithm'],
                                       community=gvm_module.params['community'],
                                       privacy_algorithm=gvm_module.params['privacy_algorithm'],
                                       privacy_password=gvm_module.params['privacy_password'],
                                       public_key_base64=gvm_module.params['public_key_base64'])

        if gvm_module.params['state'] == 'present':
            # Create credentials
            execution_result = manager.create_or_update_credentials([credentials])
            result['changed'] = execution_result.changed
            if execution_result.warning_message is not None and execution_result.warning_message != '':
                gvm_module.warn(execution_result.warning_message)
        else:
            # Delete credentials
            execution_result = manager.delete_credentials([credentials])
            result['changed'] = execution_result.changed
    except ResourceInUseError as e:
        result['failed'] = True
        result['msg'] = str(e)
        gvm_module.fail_json(**result)
    except Exception as e:
        result['failed'] = True
        result['msg'] = str(f'Failed to manage GVM credentials {str(e)}')
        gvm_module.fail_json(**result)

    # Exit with result
    gvm_module.exit_json(**result)


def main():
    """
    Execute gvm_credentials module
    Returns:

    """
    run_module()


if __name__ == '__main__':
    """
    Module main
    """
    main()
