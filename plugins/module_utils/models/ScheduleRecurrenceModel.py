from __future__ import annotations

import json
from typing import List

from .CalendarEventRuleModel import CalendarEventRuleModel


class ScheduleRecurrenceModel(object):
    """ Schedule recurrence model
       Args:
           frequency (str)           : Schedule frequency, supported value are HOURLY, DAILY, WEEKLY, MONTHLY and YEARLY
           interval (int)            : Schedule interval
           days_of_week (list[str])  : Days of week, supported values are 'We', 'Th', 'Fr','Sa', 'Su', 'Mo' and 'Tu'
           days_of_month (list[int]) : Day of the month between 1 and 31.
       """

    __slots__ = [
        '_frequency',
        '_interval',
        "_days_of_week",
        '_first_run_at',
        '_days_of_month'
    ]

    _SUPPORTED_FREQUENCIES = [
        "HOURLY",
        "DAILY",
        "WEEKLY",
        "MONTHLY",
        "YEARLY"
    ]

    _SUPPORTED_DAYS_OD_WEEK = ['We', 'Th', 'Fr', 'Sa', 'Su', 'Mo', 'Tu']

    def __init__(self, frequency: str = None, interval: int = None, days_of_week: List[str] = None,
                 days_of_month: List[int] = None):
        self.days_of_week = days_of_week
        self.days_of_month = days_of_month
        self.frequency = frequency
        self.interval = interval

    @property
    def frequency(self):
        return self._frequency

    @frequency.setter
    def frequency(self, frequency: str):
        if (frequency in self._SUPPORTED_FREQUENCIES) is False:
            raise ValueError(f"Frequency should be one of the values {', '.join(self._SUPPORTED_FREQUENCIES)}")
        self._frequency = frequency

    @property
    def interval(self) -> int | None:
        if self._interval:
            return self._interval
        return None

    @interval.setter
    def interval(self, interval: int):
        self._interval = interval

    @property
    def days_of_week(self) -> List[str]:
        if self._days_of_week:
            return self._days_of_week
        return []

    @days_of_week.setter
    def days_of_week(self, days_of_week: List[str]):
        if days_of_week and len(days_of_week) > 0:
            for day in days_of_week:
                if (day in self._SUPPORTED_DAYS_OD_WEEK) is False:
                    supported_values = ', '.join(self._SUPPORTED_DAYS_OD_WEEK)
                    raise ValueError(
                        f"Invalid value {day}, days of week should be one of the values {supported_values}")
        self._days_of_week = days_of_week

    @property
    def days_of_month(self) -> List[int]:
        if self._days_of_month:
            return self._days_of_month
        return []

    @days_of_month.setter
    def days_of_month(self, days_of_month: List[int]):
        if days_of_month:
            for day in days_of_month:
                if day <= 0 or day > 31:
                    raise ValueError(f"Invalid day number {day}, days_of_month values should be between 1 and 31")
        self._days_of_month = days_of_month

    def get_rrule(self) -> dict:
        """
        Get calendar rule event
        :return:
        """
        event = CalendarEventRuleModel()
        if self.frequency == "HOURLY" or self.frequency == "DAILY" or self.frequency == "WEEKLY" \
                or self.frequency == "MONTHLY" or self.frequency == "YEARLY":
            event.freq = self.frequency.lower()
        if self.interval and self.interval > 0:
            event.interval = self.interval
        if self.frequency == "WEEKLY" and self.days_of_week and len(self.days_of_week) > 0:
            week_days = []
            for day in self.days_of_week:
                week_days.append(day.upper())
            event.byweekday = week_days
        if self.frequency == "MONTHLY" and self.days_of_month and len(self.days_of_month) > 0:
            event.bymonthday = self.days_of_month

        return event.get_rule()

    @classmethod
    def from_json(cls, json_string: str):
        if json_string is None or len(json_string) <= 0:
            return cls()

        json_dic = json.loads(json_string)
        return cls(**json_dic)
