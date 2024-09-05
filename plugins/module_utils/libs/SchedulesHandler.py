# Copyright: (c) 2024, Black-Cockpit <hasnimehdi@outlook.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import json
from typing import List

import pytz
import xmltodict
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

from ..exceptions.ResourceInUseError import ResourceInUseError
from ..models.ExecutionResult import ExecutionResult
from ..models.GvmAdminCredentialsModel import GvmAdminCredentialsModel
from ..models.ScheduleModel import ScheduleModel
from ..utils.GvmUtils import is_success_response


class SchedulesHandler(object):
    """
    schedules handler
     Args:
        schedules (List[ScheduleModel])     : List of schedules
    """

    __slots__ = [
        'schedules',
    ]

    def __init__(self, schedules: List[ScheduleModel] = None):
        self.schedules = []
        if schedules is None:
            schedules = []
        for schedule in schedules:
            self.schedules.append(schedule)

    def create_or_update_schedules(self, socket: UnixSocketConnection,
                                   admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Create or update schedules
        :param admin_credentials: GVM admin credentials
        :param socket: GVM Unix domain socket
        :return:
        """
        with Gmp(connection=socket) as gmp:
            gmp.authenticate(admin_credentials.username, admin_credentials.password)

            # List existing schedules
            get_schedules_response = gmp.get_schedules()
            if is_success_response(xmltodict.parse(get_schedules_response), "get_schedules_response") is False:
                raise AssertionError(f"Failed to to get gvm credentials list")

            existing_schedules = xmltodict.parse(get_schedules_response).get("get_schedules_response", {}).get(
                "schedule")

            execution_result = ExecutionResult()

            for schedule in self.schedules:
                time_zone = pytz.UTC
                if schedule.time_zone:
                    time_zone = schedule.time_zone
                schedule_id = schedule.get_schedule_id(existing_schedules)
                if schedule_id is None:
                    create_schedule_response = gmp.create_schedule(name=schedule.name,
                                                                   comment=schedule.comment,
                                                                   timezone=time_zone,
                                                                   icalendar=schedule.to_ical())
                    dic = xmltodict.parse(create_schedule_response)
                    if is_success_response(dic, "create_schedule_response") is False:
                        raise AssertionError(f"Failed to create schedule {schedule.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True
                else:
                    modify_schedule_response = gmp.modify_schedule(schedule_id=schedule_id,
                                                                   icalendar=schedule.to_ical(),
                                                                   timezone=time_zone,
                                                                   comment=schedule.comment,
                                                                   name=schedule.name)
                    dic = xmltodict.parse(modify_schedule_response)
                    if is_success_response(dic, "modify_schedule_response") is False:
                        raise AssertionError(f"Failed to update schedule {schedule.name}: \n {dic}")

                    if execution_result.changed is False:
                        if schedule.is_in_use(existing_schedules):
                            execution_result.warning_message = f"Schedule {schedule.name} is already in use, some of the property will be ignored and will not be updated."
                        execution_result.changed = True

            return execution_result

    def delete_schedules(self, socket: UnixSocketConnection,
                         admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Delete schedules
        :param admin_credentials: GVM admin credentials
        :param socket: GVM Unix domain socket
        :return:
        """
        with Gmp(connection=socket) as gmp:
            gmp.authenticate(admin_credentials.username, admin_credentials.password)

            execution_result = ExecutionResult(changed=False)

            # List existing schedules
            get_schedules_response = gmp.get_schedules()
            if is_success_response(xmltodict.parse(get_schedules_response), "get_schedules_response") is False:
                return execution_result

            existing_schedules = xmltodict.parse(get_schedules_response).get("get_schedules_response", {}).get(
                "schedule")

            for schedule in self.schedules:
                if schedule.is_in_use(existing_schedules):
                    raise ResourceInUseError(f"Schedule {schedule.name} is in use and can not be deleted")

                schedule_id = schedule.get_schedule_id(existing_schedules)

                if schedule_id is not None:
                    gmp.empty_trashcan()
                    delete_schedule_response = gmp.delete_schedule(schedule_id=schedule_id, ultimate=True)

                    dic = xmltodict.parse(delete_schedule_response)
                    if is_success_response(dic, "delete_schedule_response") is False:
                        raise AssertionError(f"Failed to delete schedule {schedule.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True

            return execution_result

    @classmethod
    def from_json(cls, json_string: str):
        if json_string is None or len(json_string) <= 0:
            return cls()

        json_dic = json.loads(json_string)
        return cls(**json_dic)
