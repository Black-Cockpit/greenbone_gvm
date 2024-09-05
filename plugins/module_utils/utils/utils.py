# Copyright: (c) 2024, Black-Cockpit <hasnimehdi@outlook.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os


def is_windows() -> bool:
    """
    Check if system is windows
    :return:
    """
    return os.name == 'nt'