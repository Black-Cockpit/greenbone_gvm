# Copyright: (c) 2024, Black-Cockpit <hasnimehdi@outlook.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import json
from typing import List

import xmltodict
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

from ..models.ExecutionResult import ExecutionResult
from ..models.GvmAdminCredentialsModel import GvmAdminCredentialsModel
from ..models.TaskModel import TaskModel
from ..utils.GvmUtils import is_success_response


class TasksHandler(object):
    """
    Scan tasks handler
     Args:
        tasks (List[TaskModel])     : List of tasks
    """
    __slots__ = [
        'tasks',
    ]

    def __init__(self, tasks: List[TaskModel] = None):
        self.tasks = []
        if tasks is None:
            tasks = []
        for task in tasks:
            self.tasks.append(task)

    def create_or_update_tasks(self, socket: UnixSocketConnection,
                               admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Create or update tasks
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
            get_configs_response = gmp.get_scan_configs(details=True, preferences=False)
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

            # List tasks
            get_tasks_response = gmp.get_tasks(filter_string="first=0 rows=100")
            if is_success_response(xmltodict.parse(get_tasks_response), "get_tasks_response") is False:
                raise AssertionError(f"Failed to to get gvm tasks list")

            existing_tasks = xmltodict.parse(get_tasks_response
                                             ).get("get_tasks_response", {}).get("task", {})

            for task in self.tasks:
                task_id = task.get_task_id(existing_tasks, task.name)
                target_id = task.get_target_id(existing_targets, task.target_name)
                (scanner_id, scanner_type) = task.get_scanners_id_and_type(existing_scanners, task.scanner_name)
                config_id = task.get_config_id(existing_scan_config, task.config_name)
                schedule_id = task.get_schedule_id(existing_schedules, task.schedule_name)

                schedule_periods = 0
                if task.scan_once:
                    schedule_periods = 1

                if task_id is None:
                    create_task_response = gmp.create_task(name=task.name,
                                                           schedule_id=schedule_id,
                                                           comment=task.comment,
                                                           target_id=target_id,
                                                           config_id=config_id,
                                                           scanner_id=scanner_id,
                                                           schedule_periods=schedule_periods,
                                                           alterable=task.alterable,
                                                           preferences=task.build_preferences(scanner_type),
                                                           hosts_ordering=task.get_hosts_ordering())
                    dic = xmltodict.parse(create_task_response)
                    if is_success_response(dic, "create_task_response") is False:
                        raise AssertionError(f"Failed to create task {task.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True
                else:
                    modify_task_response = gmp.modify_task(task_id=task_id,
                                                           preferences=task.build_preferences(scanner_type),
                                                           alterable=task.alterable,
                                                           scanner_id=scanner_id,
                                                           schedule_periods=schedule_periods,
                                                           config_id=config_id,
                                                           target_id=target_id,
                                                           schedule_id=schedule_id,
                                                           comment=task.comment,
                                                           name=task.name,
                                                           hosts_ordering=task.get_hosts_ordering())
                    dic = xmltodict.parse(modify_task_response)
                    if is_success_response(dic, "modify_task_response") is False:
                        raise AssertionError(f"Failed to update task {task.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True
            return execution_result

    def delete_tasks(self, socket: UnixSocketConnection,
                     admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Delete tasks
        :param admin_credentials: GVM admin credentials
        :param socket: GVM Unix domain socket
        :return:
        """
        with Gmp(connection=socket) as gmp:
            gmp.authenticate(admin_credentials.username, admin_credentials.password)

            execution_result = ExecutionResult()

            # List tasks
            get_tasks_response = gmp.get_tasks(filter_string="first=0 rows=100")
            if is_success_response(xmltodict.parse(get_tasks_response), "get_tasks_response") is False:
                return execution_result

            existing_tasks = xmltodict.parse(get_tasks_response
                                             ).get("get_tasks_response", {}).get("task", {})

            for task in self.tasks:
                task_id = task.get_task_id(existing_tasks, task.name)

                if task_id is not None:
                    gmp.empty_trashcan()
                    delete_task_response = gmp.delete_task(task_id=task_id, ultimate=True)

                    dic = xmltodict.parse(delete_task_response)
                    if is_success_response(dic, "delete_task_response") is False:
                        raise AssertionError(f"Failed to delete task {task.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True
            return execution_result

    def start(self, socket: UnixSocketConnection, admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Start tasks
        :param admin_credentials: GVM admin credentials
        :param socket: GVM Unix domain socket
        :return:
        """
        with Gmp(connection=socket) as gmp:
            gmp.authenticate(admin_credentials.username, admin_credentials.password)

            # List tasks
            get_tasks_response = gmp.get_tasks(filter_string="first=0 rows=100")
            if is_success_response(xmltodict.parse(get_tasks_response), "get_tasks_response") is False:
                raise AssertionError(f"Failed to to get gvm tasks list")

            execution_result = ExecutionResult()

            existing_tasks = xmltodict.parse(get_tasks_response
                                             ).get("get_tasks_response", {}).get("task", {})
            for task in self.tasks:
                task_id = task.get_task_id(existing_tasks, task.name)

                if task.start and task_id is not None:
                    start_task_response = gmp.start_task(task_id)
                    dic = xmltodict.parse(start_task_response)

                    if is_success_response(dic, "start_task_response") is False:
                        raise AssertionError(f"Failed to start task {task.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True

            return execution_result

    def stop(self, socket: UnixSocketConnection, admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Stop tasks
        :param admin_credentials: GVM admin credentials
        :param socket: GVM Unix domain socket
        :return:
        """
        with Gmp(connection=socket) as gmp:
            gmp.authenticate(admin_credentials.username, admin_credentials.password)

            # List tasks
            get_tasks_response = gmp.get_tasks(filter_string="first=0 rows=100")
            if is_success_response(xmltodict.parse(get_tasks_response), "get_tasks_response") is False:
                raise AssertionError(f"Failed to to get gvm tasks list")

            execution_result = ExecutionResult()

            existing_tasks = xmltodict.parse(get_tasks_response
                                             ).get("get_tasks_response", {}).get("task")
            for task in self.tasks:
                task_id = task.get_task_id(existing_tasks, task.name)
                if task.start is False and task_id is not None:
                    try:
                        gmp.stop_task(task_id)
                        if execution_result.changed is False:
                            execution_result.changed = True
                    except Exception as e:
                        print(f"Failed to stop task {task.name}, {e}")

            return execution_result

    @classmethod
    def from_json(cls, json_string: str):
        if json_string is None or len(json_string) <= 0:
            return cls()

        json_dic = json.loads(json_string)
        return cls(**json_dic)
