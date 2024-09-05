# Copyright: (c) 2024, Black-Cockpit <hasnimehdi@outlook.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from typing import List

import yaml
from os.path import exists
import json

from gvm.connections import UnixSocketConnection

from .AuditsHandler import AuditsHandler
from .CredentialsHandler import CredentialsHandler
from .SchedulesHandler import SchedulesHandler
from .TargetsHandler import TargetsHandler
from .TasksHandler import TasksHandler
from ..models.AuditModel import AuditModel
from ..models.CredentialsModel import CredentialsModel
from ..models.ExecutionResult import ExecutionResult
from ..models.GvmAdminCredentialsModel import GvmAdminCredentialsModel
from ..models.ScheduleModel import ScheduleModel
from ..models.TargetModel import TargetModel
from ..models.TaskModel import TaskModel


class GvmManager(object):
    """
    GVM manager
     Args:
        admin_credentials (GvmAdminCredentialsModel)    : GVM admin credentials
        socket (UnixSocketConnection)                   : Unix domain socket
    """

    __slots__ = [
        'socket',
        'admin_credentials'
    ]

    def __init__(self, socket: UnixSocketConnection, admin_credentials: GvmAdminCredentialsModel):
        self.socket = socket
        self.admin_credentials = admin_credentials

    def create_or_update_targets(self, targets: List[TargetModel] = None) -> ExecutionResult:
        """
        Create or update targets

        :param targets: List of targets (List[TargetModel])
        :return:
        """
        handler = TargetsHandler(targets)
        return handler.create_or_update_targets(self.socket, self.admin_credentials)

    def delete_targets(self, targets: List[TargetModel] = None) -> ExecutionResult:
        """
        Delete targets

        :param targets: List of targets (List[TargetModel])
        :return:
        """
        handler = TargetsHandler(targets)
        return handler.delete_targets(self.socket, self.admin_credentials)

    def create_or_update_credentials(self, credentials: List[CredentialsModel]) -> ExecutionResult:
        """
        Create or update credentials

        :param credentials : List of credentials (List[CredentialsModel])
        :return:
        """
        handler = CredentialsHandler(credentials)
        return handler.create_or_update_credentials(self.socket, self.admin_credentials)

    def delete_credentials(self, credentials: List[CredentialsModel]) -> ExecutionResult:
        """
        Delete credentials

        :param credentials : List of credentials (List[CredentialsModel])
        :return:
        """
        handler = CredentialsHandler(credentials)
        return handler.delete_credentials(self.socket, self.admin_credentials)

    def create_or_schedules(self, schedules: List[ScheduleModel] = None) -> ExecutionResult:
        """
        Create or update scan schedule

        :param schedules: List of schedules (List[ScheduleModel])
        :return:
        """
        handler = SchedulesHandler(schedules=schedules)
        return handler.create_or_update_schedules(self.socket, self.admin_credentials)

    def delete_schedules(self, schedules: List[ScheduleModel] = None) -> ExecutionResult:
        """
        Delete scan schedule

        :param schedules: List of schedules (List[ScheduleModel])
        :return:
        """
        handler = SchedulesHandler(schedules=schedules)
        return handler.delete_schedules(self.socket, self.admin_credentials)

    def create_or_update_tasks(self, tasks: List[TaskModel] = None) -> ExecutionResult:
        """
        Create or update scan tasks

        :param tasks: List of scan tasks (List[TaskModel])
        :return:
        """
        handler = TasksHandler(tasks)
        return handler.create_or_update_tasks(self.socket, self.admin_credentials)

    def delete_tasks(self, tasks: List[TaskModel] = None) -> ExecutionResult:
        """
        Delete scan tasks

        :param tasks: List of scan tasks (List[TaskModel])
        :return:
        """
        handler = TasksHandler(tasks)
        return handler.delete_tasks(self.socket, self.admin_credentials)

    def create_or_update_audits(self, audits: List[AuditModel] = None) -> ExecutionResult:
        """
        Create or update audit tasks

        :param audits: List of audits (List[AuditModel])
        :return:
        :return:
        """
        handler = AuditsHandler(audits=audits)
        return handler.create_or_update_audit_tasks(self.socket, self.admin_credentials)

    def delete_audits(self, audits: List[AuditModel] = None) -> ExecutionResult:
        """
        Delete audit tasks

        :param audits: List of audits (List[AuditModel])
        :return:
        :return:
        """
        handler = AuditsHandler(audits=audits)
        return handler.delete_audit_tasks(self.socket, self.admin_credentials)

    def execute_task_command(self, tasks: List[TaskModel] = None, audits: List[AuditModel] = None,
                             task_type: str = "scan", command: bool = False) -> ExecutionResult:
        """
        Start of stop scan tasks

        :param tasks: List of scan tasks (List[AuditMode])
        :param audits: List of audits (List[TaskModel])
        :param task_type: Type of the task, acceptable value are `scan` and `audit`
        :param command: Indicates whether to execute a start or a stop of the tasks
        :return:
        """
        if (task_type in ['scan', 'audit']) is False:
            raise ValueError(f"Invalid {task_type}, task_type should either scan or audit")

        if task_type == "scan":
            handler = TasksHandler(tasks=tasks)
        else:
            handler = AuditsHandler(audits=audits)
        if command is True:
            return handler.start(self.socket, self.admin_credentials)
        else:
            return handler.stop(self.socket, self.admin_credentials)

    @staticmethod
    def _read_config_to_json(path: str) -> str:
        """
        Read and convert yaml file to json
        :param path:
        :return:
        """
        if exists(path):
            with open(path, 'r') as file:
                yaml_conf = yaml.safe_load(file)
                return json.dumps(yaml_conf)
        else:
            raise FileNotFoundError(f"No such file {path}")
