# Copyright: (c) 2024, Black-Cockpit <hasnimehdi@outlook.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)
class ResourceInUseError(Exception):
    """Exception raised for deletion or modification of resource in use."""

    def __init__(self, message):
        super().__init__(message)