# Copyright: (c) 2024, Black-Cockpit <hasnimehdi@outlook.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

class ExecutionResult(object):
    """
    Execution result model

    Args:
        changed (bool): Indicate if the resource is changed or not
        warning_message (str): Warning message
    """

    __slots__ = [
        'changed',
        'warning_message',
    ]

    def __init__(self, changed: bool = False, warning_message: str = None):
        self.changed = changed
        self.warning_message = warning_message
