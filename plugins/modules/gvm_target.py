# Copyright: (c) 2024, Hasni Mehdi <hasnimehdi@outlook.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from gvm.connections import UnixSocketConnection

from ..module_utils.models.TargetModel import TargetModel
from ..module_utils.exceptions.ResourceInUseError import ResourceInUseError
from ..module_utils.models.GvmAdminCredentialsModel import GvmAdminCredentialsModel
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
module: gvm_target
short_description: Manage Greenbone GVM targets

description:
  - This module allows you to create, update, and delete targets in Greenbone Vulnerability Manager (GVM).
  - You can specify target details such as name, hosts, port lists, and alive tests.

version_added: "1.0.0"

author:
    - Hasni Mehdi (@hasnimehdi91)
    - hasnimehdi@outlook.com
    
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
            - The name of the target.
        required: true
        type: str
    comment:
        description:
            - An optional comment or description for the target.
        required: false
        type: str
    hosts:
        description:
            - A list of hosts to be included in the target.
        required: true
        type: list
        elements: str
    exclude_hosts:
        description:
            - A list of hosts to be excluded from the target.
        required: false
        type: list
        elements: str
    allow_simultaneous_ips:
        description:
            - Whether to allow simultaneous testing of multiple IPs.
        required: false
        type: bool
        default: true
    port_list_name:
        description:
            - The name of the port list to be used for scanning.
        required: true
        type: str
    port_range:
        description:
            - A list of port ranges to be included in the scan.
        required: false
        type: list
        elements: str
    alive_test:
        description:
            - The method used to determine if a host is alive.
        required: false
        type: str
        choices: ["ICMP_PING", "TCP_ACK_SERVICE_PING", "TCP_SYN_SERVICE_PING", "ARP_PING", 
                "ICMP_AND_TCP_ACK_SERVICE_PING", "ICMP_AND_ARP_PING", "TCP_ACK_SERVICE_AND_ARP_PING",
                "ICMP_TCP_ACK_SERVICE_AND_ARP_PING", "CONSIDER_ALIVE"]
        default: "ICMP_PING"
    reverse_lookup_only:
        description:
            - Whether to perform reverse DNS lookup only.
        required: false
        type: bool
        default: false
    reverse_lookup_unify:
        description:
            - Whether to unify the results of reverse DNS lookups.
        required: false
        type: bool
        default: false
    credentials_name:
        description:
            - Credentials name.
        required: false
        type: str
    ssh_port:
        description:
            - The SSH port to use for connections.
        required: false
        type: int
        default: 22
    state:
        description:
            - The desired state of the target.
        required: false
        type: str
        choices: ["present", "absent"]
        default: "present"
'''

EXAMPLES = r'''
- name: Create a new target for a database server
  gvm_target:
    socket_path: "/run/gvmd/gvmd.sock"
    gvm_username: "admin"
    gvm_password: "admin"
    name: "database_server"
    comment: "Database server"
    hosts:
      - "10.116.0.2"
    exclude_hosts: []
    allow_simultaneous_ips: true
    port_list_name: "All TCP and Nmap top 100 UDP"
    port_range: []
    alive_test: "TCP_ACK_SERVICE_PING"
    reverse_lookup_only: false
    reverse_lookup_unify: false
    ssh_port: 22
    state: present

- name: Delete an existing target
  gvm_target:
    socket_path: "/run/gvmd/gvmd.sock"
    gvm_username: "admin"
    gvm_password: "admin"
    name: "database_server"
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
    gvm_target module
    Returns:
    """

    # gvm_target module arguments
    module_args = dict(
        socket_path=dict(type='str', required=False, default='/run/gvmd/gvmd.sock'),
        gvm_username=dict(type='str', required=False, default='admin'),
        gvm_password=dict(type='str', required=False, default='admin', no_log=True),
        name=dict(type='str', required=True),
        comment=dict(type='str', required=False, default=''),
        hosts=dict(type='list', elements='str', required=True),
        exclude_hosts=dict(type='list', elements='str', required=False, default=[]),
        allow_simultaneous_ips=dict(type='bool', required=False, default=True),
        port_list_name=dict(type='str', required=True),
        port_range=dict(type='list', elements='str', required=False, default=[]),
        alive_test=dict(
            type='str',
            required=False,
            choices=["ICMP_PING", "TCP_ACK_SERVICE_PING", "TCP_SYN_SERVICE_PING", "ARP_PING",
                     "ICMP_AND_TCP_ACK_SERVICE_PING", "ICMP_AND_ARP_PING", "TCP_ACK_SERVICE_AND_ARP_PING",
                     "ICMP_TCP_ACK_SERVICE_AND_ARP_PING", "CONSIDER_ALIVE"],
            default="ICMP_PING"),
        reverse_lookup_only=dict(type='bool', required=False, default=False),
        reverse_lookup_unify=dict(type='bool', required=False, default=False),
        credentials_name=dict(type='str', required=False),
        ssh_port=dict(type='int', required=False, default=22),
        state=dict(type='str', required=False, choices=['present', 'absent'], default='present')
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

        # Initialize target
        target = TargetModel(name=gvm_module.params['name'],
                             hosts=gvm_module.params['hosts'],
                             comment=gvm_module.params['comment'],
                             exclude_hosts=gvm_module.params['exclude_hosts'],
                             allow_simultaneous_ips=gvm_module.params['allow_simultaneous_ips'],
                             port_list_name=gvm_module.params['port_list_name'],
                             port_range=gvm_module.params['port_range'],
                             alive_test=gvm_module.params['alive_test'],
                             reverse_lookup_only=gvm_module.params['reverse_lookup_only'],
                             reverse_lookup_unify=gvm_module.params['reverse_lookup_unify'],
                             credentials_name=gvm_module.params['credentials_name'],
                             ssh_port=gvm_module.params['ssh_port'])

        if gvm_module.params['state'] == 'present':
            # Create target
            execution_result = manager.create_or_update_targets([target])
            result['changed'] = execution_result.changed
            if execution_result.warning_message is not None and execution_result.warning_message != '':
                gvm_module.warn(execution_result.warning_message)
        else:
            # Delete target
            execution_result = manager.delete_targets([target])
            result['changed'] = execution_result.changed
    except ResourceInUseError as e:
        result['failed'] = True
        result['msg'] = str(e)
        gvm_module.fail_json(**result)
    except Exception as e:
        result['failed'] = True
        result['msg'] = str(f'Failed to manage GVM target {str(e)}')
        gvm_module.fail_json(**result)

    # Exit with result
    gvm_module.exit_json(**result)


def main():
    """
    Execute gvm_target module
    Returns:

    """
    run_module()


if __name__ == '__main__':
    """
    Module main
    """
    main()
