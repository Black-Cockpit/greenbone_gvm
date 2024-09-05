# Copyright: (c) 2024, Black-Cockpit <hasnimehdi@outlook.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import json
from typing import List

import xmltodict
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

from ..models.AuditModel import AuditModel
from ..models.ExecutionResult import ExecutionResult
from ..models.GvmAdminCredentialsModel import GvmAdminCredentialsModel
from ..utils.GvmUtils import is_success_response


class AuditsHandler(object):
    """
    Scan audits handler
     Args:
        audits (List[AuditModel])     : List of tasks
    """
    __slots__ = [
        'audits',
    ]

    def __init__(self, audits: List[AuditModel] = None):
        self.audits = []
        if audits is None:
            audits = []
        for audit in audits:
            self.audits.append(audit)

    def create_or_update_audit_tasks(self, socket: UnixSocketConnection,
                                     admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Create or update audit tasks
        :param admin_credentials: GVM admin credentials
        :param socket: GVM Unix domain socket
        :return:
        """
        with Gmp(connection=socket) as gmp:
            gmp.authenticate(admin_credentials.username, admin_credentials.password)

            # List existing schedules
            get_schedules_response = gmp.get_schedules()
            if is_success_response(xmltodict.parse(get_schedules_response), "get_schedules_response") is False:
                raise AssertionError(f"Failed to to get gvm schedules list")

            execution_result = ExecutionResult()

            existing_schedules = xmltodict.parse(get_schedules_response).get("get_schedules_response", {}).get(
                "schedule")

            # List targets
            get_targets_response = gmp.get_targets(filter_string="first=0 rows=100")
            if is_success_response(xmltodict.parse(get_targets_response), "get_targets_response") is False:
                raise AssertionError(f"Failed to to get gvm target list")

            existing_targets = xmltodict.parse(get_targets_response).get("get_targets_response", {}).get("target", {})

            # List configs
            get_configs_response = gmp.get_policies(details=True, preferences=False)
            if is_success_response(xmltodict.parse(get_configs_response), "get_configs_response") is False:
                raise AssertionError(f"Failed to to get gvm config list")

            existing_scan_config = xmltodict.parse(get_configs_response
                                                   ).get("get_configs_response", {}).get("config", {})

            # List scanners
            get_scanners_response = gmp.get_scanners()
            if is_success_response(xmltodict.parse(get_scanners_response), "get_scanners_response") is False:
                raise AssertionError(f"Failed to to get gvm scanner list")

            existing_scanners = xmltodict.parse(get_scanners_response
                                                ).get("get_scanners_response", {}).get("scanner", {})

            # List audit tasks
            get_tasks_response = gmp.get_audits(filter_string="first=0 rows=100")
            if is_success_response(xmltodict.parse(get_tasks_response), "get_tasks_response") is False:
                raise AssertionError(f"Failed to to get gvm audit tasks list")

            existing_tasks = xmltodict.parse(get_tasks_response
                                             ).get("get_tasks_response", {}).get("task", {})

            for audit in self.audits:
                audit_id = audit.get_audit_id(existing_tasks, audit.name)
                target_id = audit.get_target_id(existing_targets, audit.target_name)
                (scanner_id, scanner_type) = audit.get_scanners_id_and_type(existing_scanners, audit.scanner_name)
                policy_id = audit.get_policy_config_id(existing_scan_config, audit.policy_config_name)
                schedule_id = audit.get_schedule_id(existing_schedules, audit.schedule_name)

                schedule_periods = 0
                if audit.scan_once:
                    schedule_periods = 1

                if audit_id is None:
                    create_task_response = gmp.create_audit(name=audit.name,
                                                            schedule_id=schedule_id,
                                                            comment=audit.comment,
                                                            target_id=target_id,
                                                            policy_id=policy_id,
                                                            scanner_id=scanner_id,
                                                            schedule_periods=schedule_periods,
                                                            alterable=audit.alterable,
                                                            preferences=audit.build_preferences(scanner_type),
                                                            hosts_ordering=audit.get_hosts_ordering())
                    dic = xmltodict.parse(create_task_response)
                    if is_success_response(dic, "create_task_response") is False:
                        raise AssertionError(f"Failed to create audit task {audit.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True
                else:
                    modify_task_response = gmp.modify_audit(audit_id=audit_id,
                                                            preferences=audit.build_preferences(scanner_type),
                                                            alterable=audit.alterable,
                                                            scanner_id=scanner_id,
                                                            schedule_periods=schedule_periods,
                                                            policy_id=policy_id,
                                                            target_id=target_id,
                                                            schedule_id=schedule_id,
                                                            comment=audit.comment,
                                                            name=audit.name,
                                                            hosts_ordering=audit.get_hosts_ordering())
                    dic = xmltodict.parse(modify_task_response)
                    if is_success_response(dic, "modify_task_response") is False:
                        raise AssertionError(f"Failed to update audit task {audit.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True

            return execution_result

    def delete_audit_tasks(self, socket: UnixSocketConnection,
                           admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Delete audit tasks
        :param admin_credentials: GVM admin credentials
        :param socket: GVM Unix domain socket
        :return:
        """
        with Gmp(connection=socket) as gmp:
            gmp.authenticate(admin_credentials.username, admin_credentials.password)

            execution_result = ExecutionResult()

            # List audit tasks
            get_tasks_response = gmp.get_audits(filter_string="first=0 rows=100")
            if is_success_response(xmltodict.parse(get_tasks_response), "get_tasks_response") is False:
                return execution_result

            existing_tasks = xmltodict.parse(get_tasks_response
                                             ).get("get_tasks_response", {}).get("task", {})

            for audit in self.audits:
                audit_id = audit.get_audit_id(existing_tasks, audit.name)

                if audit_id is not None:
                    gmp.empty_trashcan()
                    delete_task_response = gmp.delete_task(task_id=audit_id, ultimate=True)

                    dic = xmltodict.parse(delete_task_response)
                    if is_success_response(dic, "delete_task_response") is False:
                        raise AssertionError(f"Failed to delete audit task {audit.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True

            return execution_result

    def start(self, socket: UnixSocketConnection, admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Start audit tasks
        :param admin_credentials: GVM admin credentials
        :param socket: GVM Unix domain socket
        :return:
        """
        with Gmp(connection=socket) as gmp:
            gmp.authenticate(admin_credentials.username, admin_credentials.password)

            execution_result = ExecutionResult()

            # List tasks
            get_tasks_response = gmp.get_audits(filter_string="first=0 rows=100")
            if is_success_response(xmltodict.parse(get_tasks_response), "get_tasks_response") is False:
                raise AssertionError(f"Failed to to get gvm tasks list")

            existing_tasks = xmltodict.parse(get_tasks_response).get("get_tasks_response", {}).get("task", {})

            for audit in self.audits:
                audit_id = audit.get_audit_id(existing_tasks, audit.name)

                if audit.start and audit_id is not None and audit.is_scheduled(existing_tasks) is False:
                    start_task_response = gmp.start_audit(audit_id)

                    dic = xmltodict.parse(start_task_response)
                    if is_success_response(dic, "start_task_response") is False:
                        raise AssertionError(f"Failed to start audit task {audit.name}: \n {dic}")

                    if execution_result.changed is False and audit.is_scheduled(existing_tasks) is False:
                        execution_result.changed = True
            return execution_result

    def stop(self, socket: UnixSocketConnection, admin_credentials: GvmAdminCredentialsModel):
        """
        Stop audit tasks
        :param admin_credentials: GVM admin credentials
        :param socket: GVM Unix domain socket
        :return:
        """
        with Gmp(connection=socket) as gmp:
            gmp.authenticate(admin_credentials.username, admin_credentials.password)

            # List tasks
            get_tasks_response = gmp.get_audits(filter_string="first=0 rows=100")
            if is_success_response(xmltodict.parse(get_tasks_response), "get_tasks_response") is False:
                raise AssertionError(f"Failed to to get gvm audit tasks list")

            execution_result = ExecutionResult()

            existing_tasks = xmltodict.parse(get_tasks_response).get("get_tasks_response", {}).get("task")

            for audit in self.audits:
                audit_id = audit.get_audit_id(existing_tasks, audit.name)

                if audit.start is False and audit_id is not None:
                    try:
                        gmp.stop_audit(audit_id)
                        if execution_result.changed is False:
                            execution_result.changed = True
                    except Exception as e:
                        print(f"Failed to stop audit task {audit.name}, {e}")
            return execution_result

    @classmethod
    def from_json(cls, json_string: str):
        if json_string is None or len(json_string) <= 0:
            return cls()

        json_dic = json.loads(json_string)
        return cls(**json_dic)
