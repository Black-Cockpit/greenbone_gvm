from __future__ import annotations

import json

from gvm.protocols.gmp.requests.v225 import HostsOrdering


class AuditModel(object):
    """ audit model
    Args:
        name (str)                                      : Audit name
        comment (str)                                   : Description of the audit
        target_name (str)                               : Name of the target to be scanned
        schedule_name (str)                             : Schedule name to by applied
        scan_once (bool)                                : Indicates where to run the scan only one time.
        add_result_in_assets (bool)                     : Indicates whether to add result part of the assets or not,
                default is `true`
        alterable (bool)                                : Indicates whether the task is alterable or not
        auto_delete (bool)                              : Indicates whether to delete the scan reports of not
        auto_delete_data (int)                          : Number of maximum reports to keep, default 1. Ignored if
                auto_delete is set to false.
        scanner_name (str)                              : Scanner name to be used
        policy_config_name (str)                        : Policy config name to be used on the scan
        hosts_ordering (str)                            : Host ordering, default is sequential
        max_concurrency_executed_nvt_per_host (int)     : Maximum concurrent executed NVT per host, default is 4
        max_concurrency_scanned_host (int)              : Maximum concurrent scanned hosts, default is 20
        start (bool)                                    : Indicates whether to start the task or not. default is false.
    """

    __slots__ = [
        '_name',
        'comment',
        '_target_name',
        "schedule_name",
        "scan_once",
        'add_result_in_assets',
        'apply_overrides',
        '_min_quality_of_detection',
        'alterable',
        'auto_delete',
        '_auto_delete_data',
        '_scanner_name',
        '_policy_config_name',
        'hosts_ordering',
        'max_concurrency_executed_nvt_per_host',
        'max_concurrency_scanned_host',
        'start'
    ]

    def __init__(self, name: str = None, comment: str = None, target_name: str = None, schedule_name: str = None,
                 scan_once: bool = False, add_result_in_assets: bool = True, apply_overrides: bool = True,
                 min_quality_of_detection: int = 70, alterable: bool = False, auto_delete: bool = False,
                 auto_delete_data: int = 1, scanner_name: str = None, policy_config_name: str = None,
                 hosts_ordering: str = "sequential", max_concurrency_executed_nvt_per_host: int = 4,
                 max_concurrency_scanned_host: int = 20, start: bool = False):
        self.name = name
        self.comment = comment
        self.target_name = target_name
        self.schedule_name = schedule_name

        if scan_once is None:
            scan_once = True
        self.scan_once = scan_once

        if add_result_in_assets is None:
            add_result_in_assets = True
        self.add_result_in_assets = add_result_in_assets

        if apply_overrides is None:
            apply_overrides = True
        self.apply_overrides = apply_overrides

        self.min_quality_of_detection = min_quality_of_detection

        if alterable is None:
            alterable = False
        self.alterable = alterable

        self.auto_delete_data = auto_delete_data

        if auto_delete is None:
            auto_delete = False
        self.auto_delete = auto_delete

        self.scanner_name = scanner_name
        self.policy_config_name = policy_config_name

        if hosts_ordering is None:
            hosts_ordering = "sequential"
        self.hosts_ordering = hosts_ordering

        if max_concurrency_executed_nvt_per_host is None:
            max_concurrency_executed_nvt_per_host = 4
        self.max_concurrency_executed_nvt_per_host = max_concurrency_executed_nvt_per_host

        if max_concurrency_scanned_host is None:
            max_concurrency_scanned_host = 20
        self.max_concurrency_scanned_host = max_concurrency_scanned_host

        if start is None:
            start = False

        self.start = start

    @property
    def name(self) -> str | None:
        if self._name:
            return self._name
        return None

    @name.setter
    def name(self, name: str):
        if name is None or name == '' or name.isspace():
            raise ValueError("Name is required")
        self._name = name

    @property
    def target_name(self) -> str | None:
        if self._target_name:
            return self._target_name
        return None

    @target_name.setter
    def target_name(self, target_name: str):
        if target_name is None or target_name == '' or target_name.isspace() is True:
            raise ValueError("target_name is required")
        self._target_name = target_name

    @property
    def min_quality_of_detection(self) -> int | None:
        if self._min_quality_of_detection:
            return self._min_quality_of_detection
        return None

    @min_quality_of_detection.setter
    def min_quality_of_detection(self, min_quality_of_detection: int):
        if min_quality_of_detection:
            if min_quality_of_detection <= 0 or min_quality_of_detection > 100:
                raise ValueError("min_quality_of_detection should be between 1 and 100")
            self._min_quality_of_detection = min_quality_of_detection
        else:
            self._min_quality_of_detection = 70

    @property
    def auto_delete_data(self) -> int | None:
        if self._auto_delete_data:
            return self._auto_delete_data
        return None

    @auto_delete_data.setter
    def auto_delete_data(self, auto_delete_data: int):
        if auto_delete_data and auto_delete_data <= 0:
            raise ValueError("auto_delete_data should greater than or equal to 1")
        if auto_delete_data:
            self._auto_delete_data = auto_delete_data
        else:
            self._auto_delete_data = 1

    @property
    def scanner_name(self) -> str | None:
        if self._scanner_name:
            return self._scanner_name
        return None

    @scanner_name.setter
    def scanner_name(self, scanner_name: str):
        if scanner_name is None or scanner_name == '' or scanner_name.isspace():
            raise ValueError("scanner_name is required")
        self._scanner_name = scanner_name

    @property
    def policy_config_name(self) -> str | None:
        if self._policy_config_name:
            return self._policy_config_name
        return None

    @policy_config_name.setter
    def policy_config_name(self, policy_config_name: str):
        if policy_config_name is None or policy_config_name == '' or policy_config_name.isspace():
            raise ValueError("policy_config_name is required")
        self._policy_config_name = policy_config_name

    def get_hosts_ordering(self) -> HostsOrdering:
        """
        Get host ordering
        :return:
        """
        if self.hosts_ordering is None:
            return HostsOrdering.SEQUENTIAL
        if self.hosts_ordering == "reverse":
            return HostsOrdering.SEQUENTIAL
        elif self.hosts_ordering == "random":
            return HostsOrdering.RANDOM
        else:
            return HostsOrdering.SEQUENTIAL

    def build_preferences(self, scanner_type: str = None) -> dict:
        """
        Build props
        :param scanner_type:
        :return:
        """
        dic = dict()
        if self.apply_overrides:
            dic['apply_overrides'] = "1"
        else:
            dic['apply_overrides'] = "0"
        if self.auto_delete:
            dic['auto_delete'] = "keep"
            dic['auto_delete_data'] = str(self.auto_delete_data)
        else:
            dic['auto_delete'] = "no"

        dic['max_checks'] = str(self.max_concurrency_executed_nvt_per_host)
        dic['max_hosts'] = str(self.max_concurrency_scanned_host)
        dic['min_qod'] = str(self.min_quality_of_detection)
        if scanner_type and scanner_type is not None and scanner_type != '' and scanner_type.isspace() is False:
            dic['scanner_type'] = scanner_type
        dic['usage_type'] = "scan"

        return dic

    @staticmethod
    def get_scanners_id_and_type(scanners_list: dict, name: str) -> (str, str):
        """
        Get scanner id from list of GVM scanners
        :param name: Scanner name
        :param scanners_list: GVM scanners list
        :return:
        """
        if scanners_list is not None and len(scanners_list) > 0:
            if type(scanners_list) is list:
                for credentials in scanners_list:
                    if credentials.get("name") == name:
                        return credentials.get("@id"), credentials.get("type")
            elif type(scanners_list) is dict:
                if scanners_list.get("name") == name:
                    return scanners_list.get("@id"), scanners_list.get("type")

    @staticmethod
    def _get_entity_id(gvm_entities: dict, name: str) -> str:
        """
        Get entity id from list of GVM entities
        :param name: Config name
        :param gvm_entities: GVM entities list
        :return:
        """
        if gvm_entities is not None and len(gvm_entities) > 0:
            if type(gvm_entities) is list:
                for credentials in gvm_entities:
                    if credentials.get("name") == name:
                        return credentials.get("@id")
            elif type(gvm_entities) is dict:
                if gvm_entities.get("name") == name:
                    return gvm_entities.get("@id")

    def get_audit_id(self, task_list: dict, name: str) -> str:
        """
        Get config id from list of GVM scan tasks
        :param name: Task name
        :param task_list: GVM tasks list
        :return:
        """
        return self._get_entity_id(task_list, name)

    def get_policy_config_id(self, config_list: dict, name: str) -> str:
        """
        Get config id from list of GVM scan configs
        :param name: Config name
        :param config_list: GVM scan configs list
        :return:
        """
        return self._get_entity_id(config_list, name)

    def get_target_id(self, target_list: dict, name: str) -> str:
        """
        Get target id from list of GVM targets
        :param name: Target name
        :param target_list: GVM scan targets
        :return:
        """
        return self._get_entity_id(target_list, name)

    def get_schedule_id(self, schedules_list: dict, name: str) -> str:
        """
        Get schedule id from list of GVM scan schedule
        :param name: Schedule name
        :param schedules_list: GVM scan schedule
        :return:
        """
        return self._get_entity_id(schedules_list, name)

    def is_scheduled(self, targets: dict) -> bool:
        """
        Check if audit task is scheduled.
        :param targets: GVM targets
        :return:
        """
        if targets is not None and len(targets) > 0:
            if type(targets) is list:
                for target in targets:
                    if target.get("name") == self.name:
                        return target.get("schedule") is not None and type(target.get("schedule")) is dict \
                            and target.get("schedule").get("name") is not None and target.get("schedule").get(
                                "name") != ""
            elif type(targets) is dict:
                if targets.get("name") == self.name:
                    return targets.get("schedule") is not None and type(targets.get("schedule")) is dict \
                        and targets.get("schedule").get("name") is not None and targets.get("schedule").get(
                            "name") != ""

    @classmethod
    def from_json(cls, json_string: str):
        if json_string is None or len(json_string) <= 0:
            return cls()

        json_dic = json.loads(json_string)
        return cls(**json_dic)
