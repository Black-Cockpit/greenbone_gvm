from __future__ import annotations

from typing import List


class CalendarEventRuleModel(object):
    """ Schedule recurrence model
        Refer to https://dateutil.readthedocs.io/en/stable/rrule.html
       Args:
           freq (str)                       : Schedule frequency
           interval (int)                   : Description of the target
           bymonth (int)                    : List of IP addresses, networks or hostnames ro exclude from the scan
           bymonthday: (list[int])          : List of month days
           byweekday: (list[str])           : List if week days
       """

    __slots__ = [
        '_freq',
        '_interval',
        '_bymonth',
        "_bymonthday",
        '_byday'
    ]

    def __init__(self, freq: str = None, interval: int = None, bymonth: int = None, bymonthday: List[int] = None,
                 byweekday: List[str] = None):
        if freq:
            self.freq = freq
        self.interval = interval
        self.bymonth = bymonth
        self.bymonthday = bymonthday
        self.byweekday = byweekday

    @property
    def freq(self) -> str | None:
        if self._freq:
            return self._freq
        return None

    @freq.setter
    def freq(self, freq: str):
        if freq is None or freq == '' or freq.isspace():
            raise ValueError("freq is required")
        self._freq = freq

    @property
    def interval(self) -> int | None:
        if self._interval:
            return self._interval
        return None

    @interval.setter
    def interval(self, interval: int):
        self._interval = interval

    @property
    def bymonth(self) -> int | None:
        if self._bymonth:
            return self._bymonth
        return None

    @bymonth.setter
    def bymonth(self, bymonth: int):
        self._bymonth = bymonth

    @property
    def bymonthday(self) -> List[int] | None:
        if self._bymonthday:
            return self._bymonthday
        return None

    @bymonthday.setter
    def bymonthday(self, bymonthday: List[int]):
        self._bymonthday = bymonthday

    @property
    def byweekday(self) -> List[str] | None:
        if self._byday:
            return self._byday
        return None

    @byweekday.setter
    def byweekday(self, byweekday: List[str]):
        self._byday = byweekday

    def get_rule(self) -> dict:
        """
        Get event rule
        :return:
        """
        if hasattr(self, '__dict__'):
            return vars(self)
        else:
            rule = dict()
            for slot in self.__slots__:
                if getattr(self, slot):
                    rule[str(slot).replace("_", "")] = getattr(self, slot)
            return rule
