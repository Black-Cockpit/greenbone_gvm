# Copyright: (c) 2024, Black-Cockpit <hasnimehdi@outlook.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)
from __future__ import (absolute_import, division, print_function)

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from gvm.connections import UnixSocketConnection

from ..module_utils.models.TaskModel import TaskModel
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
module: gvm_task

short_description: Manage Greenbone Vulnerability Manager (GVM) tasks

version_added: "1.0.0"

description:
  - This module allows for the management of tasks in Greenbone Vulnerability Manager (GVM). 
    It provides functionalities to create, update, and manage vulnerability scan tasks.

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
            - The name of the task.
        required: true
        type: str
    comment:
        description:
            - A comment or description for the task.
        required: false
        type: str
    target_name:
        description:
            - The name of the target for the scan.
        required: true
        type: str
    schedule_name:
        description:
            - The name of the schedule to use for the scan.
        required: false
        type: str
    scan_once:
        description:
            - Whether to run the scan only once.
        required: false
        type: bool
        default: true
    add_result_in_assets:
        description:
            - Whether to add results to assets.
        required: false
        type: bool
        default: true
    apply_overrides:
        description:
            - Whether to apply overrides.
        required: false
        type: bool
        default: true
    min_quality_of_detection:
        description:
            - Minimum quality of detection for the scan.
        required: false
        type: int
        default: 70
    alterable:
        description:
            - Whether the task can be altered.
        required: false
        type: bool
        default: true
    auto_delete:
        description:
            - Whether to auto-delete the task.
        required: false
        type: bool
        default: false
    auto_delete_data:
        description:
            - Number of days after which data should be auto-deleted.
        required: false
        type: int
    scanner_name:
        description:
            - The name of the scanner to use.
        required: false
        type: str
        default: "OpenVAS Default"
    config_name:
        description:
            - The name of the configuration to use.
        required: false
        type: str
        default: "Full and fast"
    hosts_ordering:
        description:
            - Ordering of hosts in the scan.
        required: false
        type: str
        choices: ['sequential', 'random', 'reverse']
        default: "sequential"
    max_concurrency_executed_nvt_per_host:
        description:
            - Maximum concurrency of executed NVTs per host.
        required: false
        type: int
        default: 4
    max_concurrency_scanned_host:
        description:
            - Maximum concurrency of scanned hosts.
        required: false
        type: int
        default: 20
    state:
        description:
            - State of the scan task, possible values are present, absent, started or stopped. The default is present.
        required: false
        type: str
        default: present
        choices: ["absent", "present","started", "stopped"]
'''

EXAMPLES = r'''
- name: Create a new database server scan task
  gvm_task:
    socket_path: "/run/gvmd/gvmd.sock"
    gvm_username: "admin"
    gvm_password: "admin"
    name: "database_server_scan"
    comment: "Database server vulnerability scan"
    target_name: "database_server"
    schedule_name: "weekly_saturday_schedule"
    scan_once: false
    add_result_in_assets: true
    apply_overrides: true
    min_quality_of_detection: 70
    alterable: false
    auto_delete: true
    auto_delete_data: 5
    scanner_name: "OpenVAS Default"
    config_name: "Full and fast"
    hosts_ordering: "sequential"
    max_concurrency_executed_nvt_per_host: 4
    max_concurrency_scanned_host: 20
    status: present
    
- name: Delete a task
  gvm_task:
    socket_path: "/run/gvmd/gvmd.sock"
    gvm_username: "admin"
    gvm_password: "admin"
    name: "database_server_scan"
    target_name: "database_server"
    status: absent
'''


def run_module():
    """
    gvm_task module
    Returns:
    """

    # gvm_task module arguments
    module_args = dict(
        socket_path=dict(type='str', required=False, default='/run/gvmd/gvmd.sock'),
        gvm_username=dict(type='str', required=False, default='admin'),
        gvm_password=dict(type='str', required=False, default='admin', no_log=True),
        name=dict(type='str', required=True),
        comment=dict(type='str', required=False, default=''),
        target_name=dict(type='str', required=True),
        schedule_name=dict(type='str', required=False),
        scan_once=dict(type='bool', required=False, default=False),
        add_result_in_assets=dict(type='bool', required=False, default=True),
        apply_overrides=dict(type='bool', required=False, default=True),
        min_quality_of_detection=dict(type='int', required=False, default=70),
        alterable=dict(type='bool', required=False, default=False),
        auto_delete=dict(type='bool', required=False, default=True),
        auto_delete_data=dict(type='int', required=False, default=5),
        scanner_name=dict(type='str', required=False, default='OpenVAS Default'),
        config_name=dict(type='str', required=False, default='Full and fast'),
        hosts_ordering=dict(type='str', required=False, choices=['sequential', 'random', 'reverse'],
                            default='sequential'),
        max_concurrency_executed_nvt_per_host=dict(type='int', required=False, default=4),
        max_concurrency_scanned_host=dict(type='int', required=False, default=20),
        state=dict(type='str', required=False, default='present', choices=["absent", "present", "started", "stopped"])
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

        # Initialize task
        task = TaskModel(name=gvm_module.params['name'],
                         comment=gvm_module.params['comment'],
                         target_name=gvm_module.params['target_name'],
                         schedule_name=gvm_module.params['schedule_name'],
                         scan_once=gvm_module.params['scan_once'],
                         add_result_in_assets=gvm_module.params['add_result_in_assets'],
                         apply_overrides=gvm_module.params['apply_overrides'],
                         min_quality_of_detection=gvm_module.params['min_quality_of_detection'],
                         alterable=gvm_module.params['alterable'],
                         auto_delete=gvm_module.params['auto_delete'],
                         auto_delete_data=gvm_module.params['auto_delete_data'],
                         scanner_name=gvm_module.params['scanner_name'],
                         config_name=gvm_module.params['config_name'],
                         hosts_ordering=gvm_module.params['hosts_ordering'],
                         max_concurrency_scanned_host=gvm_module.params['max_concurrency_scanned_host'],
                         start=False)

        if gvm_module.params['state'] == 'present':
            # Create scan task
            execution_result = manager.create_or_update_tasks([task])
            result['changed'] = execution_result.changed
            if execution_result.warning_message is not None and execution_result.warning_message != '':
                gvm_module.warn(execution_result.warning_message)
        elif gvm_module.params['state'] == 'absent':
            # Delete scan task
            execution_result = manager.delete_tasks([task])
            result['changed'] = execution_result.changed
        elif gvm_module.params['state'] == 'started':
            # Start scan task
            task.start = True
            execution_result = manager.execute_task_command(tasks=[task], task_type="scan", command=task.start)
            result['changed'] = execution_result.changed
        else:
            # Stop scan task
            task.start = False
            execution_result = manager.execute_task_command(tasks=[task], task_type="scan", command=task.start)
            result['changed'] = execution_result.changed
    except ResourceInUseError as e:
        result['failed'] = True
        result['msg'] = str(e)
        gvm_module.fail_json(**result)
    except Exception as e:
        result['failed'] = True
        result['msg'] = str(f'Failed to manage GVM scan task {str(e)}')
        gvm_module.fail_json(**result)

    # Exit with result
    gvm_module.exit_json(**result)


def main():
    """
    Execute gvm_task module
    Returns:

    """
    run_module()


if __name__ == '__main__':
    """
    Module main
    """
    main()
