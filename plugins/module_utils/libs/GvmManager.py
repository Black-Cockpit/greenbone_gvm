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
from ..models.CredentialsModel import CredentialsModel
from ..models.ExecutionResult import ExecutionResult
from ..models.GvmAdminCredentialsModel import GvmAdminCredentialsModel


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

    def create_or_update_targets(self, targets_config_path: str):
        """
        Create or update targets

        :param targets_config_path: Targets config path
        :return:
        """
        handler = TargetsHandler.from_json(self._read_config_to_json(targets_config_path))
        handler.create_or_update_targets(self.socket, self.admin_credentials)

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

    def create_or_schedules(self, schedules_config_path: str):
        """
        Create or update scan schedule

        :param schedules_config_path: Scan schedule config path
        :return:
        """
        handler = SchedulesHandler.from_json(self._read_config_to_json(schedules_config_path))
        handler.create_or_update_schedules(self.socket, self.admin_credentials)

    def create_or_update_tasks(self, tasks_config_path: str):
        """
        Create or update scan tasks

        :param tasks_config_path: Scan tasks config path
        :return:
        """
        handler = TasksHandler.from_json(self._read_config_to_json(tasks_config_path))
        handler.create_or_update_tasks(self.socket, self.admin_credentials)

    def create_or_update_audits(self, tasks_config_path: str):
        """
        Create or update audit tasks

        :param tasks_config_path: Audit tasks config path
        :return:
        """
        handler = AuditsHandler.from_json(self._read_config_to_json(tasks_config_path))
        handler.create_or_update_audit_tasks(self.socket, self.admin_credentials)

    def execute_task_command(self, tasks_config_path: str, task_type: str = "scan", command: bool = False):
        """
        Start of stop scan tasks

        :param task_type: Type of the task, acceptable value are `scan` and `audit`
        :param command: Indicates whether to execute a start or a stop of the tasks
        :param tasks_config_path: Scan tasks config path
        :return:
        """
        if (task_type in ['scan', 'audit']) is False:
            raise ValueError(f"Invalid {task_type}, task_type should either scan or audit")

        if task_type == "scan":
            handler = TasksHandler.from_json(self._read_config_to_json(tasks_config_path))
        else:
            handler = AuditsHandler.from_json(self._read_config_to_json(tasks_config_path))
        if command is True:
            handler.start(self.socket, self.admin_credentials)
        else:
            handler.stop(self.socket, self.admin_credentials)

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
