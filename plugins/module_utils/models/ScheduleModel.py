from __future__ import annotations

import json

import pytz
from icalendar import Calendar, Event
from dateutil import parser

from .ScheduleRecurrenceModel import ScheduleRecurrenceModel
from ..utils.DataValidator import is_parsable_to_date, is_valid_time_zone


class ScheduleModel(object):
    """ Schedule model
    Args:
        name (str)                                  : Schedule name
        comment (str)                               : Description of the schedule
        time_zone (str)                             : Valid time zone info, default is UTC
        first_run_at (str)                          : Start date time, any format is accepted
        run_util (str)                              : End date time, any format is accepted
        recurrence (ScheduleRecurrenceModel | None) : Schedule recurrence
    """

    __slots__ = [
        '_name',
        'comment',
        "_time_zone",
        '_first_run_at',
        '_port_range',
        '_run_util',
        '_recurrence'
    ]

    def __init__(self, name: str = None, comment: str = None, time_zone: str = "UTC", first_run_at: str = None,
                 run_util: str = None, recurrence: ScheduleRecurrenceModel | None = None):
        self.name = name
        self.comment = comment
        if time_zone is None or time_zone == '' or time_zone.isspace():
            self.time_zone = "UTC"
        else:
            self.time_zone = time_zone

        self.first_run_at = first_run_at
        self.run_util = run_util
        if recurrence:
            self.recurrence = ScheduleRecurrenceModel.from_json(json.dumps(recurrence))
        else:
            self.recurrence = None

    @property
    def name(self) -> str | None:
        if self._name:
            return self._name
        return None

    @name.setter
    def name(self, name: str):
        if name is None or name == '' or name.isspace():
            raise ValueError("Schedule name is required")
        self._name = name

    @property
    def time_zone(self) -> str | None:
        if self._time_zone:
            return self._time_zone
        return None

    @time_zone.setter
    def time_zone(self, time_zone: str):
        if time_zone:
            if is_valid_time_zone(time_zone) is False:
                valid_timezone = ','.join(pytz.all_timezones)
                raise ValueError(f"Invalid timezone {time_zone}, time_zone should be one of {valid_timezone}")
            self._time_zone = time_zone
        else:
            self._time_zone = None

    @property
    def first_run_at(self) -> str | None:
        if self._first_run_at:
            return self._first_run_at
        return None

    @first_run_at.setter
    def first_run_at(self, first_run_at: str):
        if first_run_at is None or first_run_at == '' or first_run_at.isspace():
            raise ValueError("first_run_at is required")
        if is_parsable_to_date(first_run_at) is False:
            raise ValueError("Failed to parse first_run_at to datetime")
        self._first_run_at = first_run_at

    @property
    def run_util(self) -> str | None:
        if self._run_util:
            return self._run_util
        return None

    @run_util.setter
    def run_util(self, run_util: str):
        if run_util and run_util.isspace() is False and is_parsable_to_date(run_util) is False:
            raise ValueError("Failed to parse run_util to datetime")
        self._run_util = run_util

    @property
    def recurrence(self) -> ScheduleRecurrenceModel | None:
        if self._recurrence:
            return self._recurrence
        return None

    @recurrence.setter
    def recurrence(self, recurrence: ScheduleRecurrenceModel):
        if recurrence:
            self._recurrence = recurrence
        else:
            self._recurrence = None

    def to_ical(self) -> bytes:
        event = Event()
        start_datetime = parser.parse(self.first_run_at)
        event.add("dtstart", start_datetime)
        event.add('uid', f"{str(start_datetime.timestamp()).replace('.', '')}")

        if self.run_util and self.run_util.isspace() is False:
            event.add("dtend", parser.parse(self.run_util))

        if self.recurrence:
            event.add('rrule', self._recurrence.get_rrule())

        if self.comment and self.comment.isspace() is False:
            event.add("description", self.comment)
            event.add("summary", self.comment)

        calendar = Calendar()
        calendar.add('prodid', '-//Greenbone.net//NONSGML Greenbone Security Manager 22.6.0//EN')
        calendar.add('version', '2.0')
        calendar.add_component(event)
        return calendar.to_ical()

    def get_schedule_id(self, schedules: dict):
        """
        Get schedule id from list of GVM schedules
        :param schedules: GVM schedules
        :return:
        """
        if schedules is not None and len(schedules) > 0:
            if type(schedules) is list:
                for schedule in schedules:
                    if schedule.get("name") == self.name:
                        return schedule.get("@id")
            elif type(schedules) is dict:
                if schedules.get("name") == self.name:
                    return schedules.get("@id")

    @classmethod
    def from_json(cls, json_string: str):
        if json_string is None or len(json_string) <= 0:
            return cls()

        json_dic = json.loads(json_string)
        return cls(**json_dic)
