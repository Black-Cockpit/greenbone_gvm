import os


def is_windows() -> bool:
    """
    Check if system is windows
    :return:
    """
    return os.name == 'nt'