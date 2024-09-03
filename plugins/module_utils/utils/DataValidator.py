import pytz
import validators
from netaddr import valid_nmap_range
from dateutil import parser


def is_valid_domain_or_ip_or_network(_input: str) -> bool:
    """
    Check if input is a domain, ip address or a network
    :param _input:
    :return:
    """
    return _input is not None and _input != '' and _input.isspace() is False and \
        (validators.domain(_input) is True or validators.ipv4(_input) is True or validators.ipv6(_input) is True or
         validators.ipv4_cidr(_input) is True or validators.ipv6_cidr(_input) is True or is_ip_range(_input) is True)


def is_global_ip_or_global_cidr(_input: str) -> bool:
    """
    Check if input is a global address or cidr
    :param _input:
    :return:
    """
    return _input is None or _input == '' or _input.isspace() is True or _input.startswith("0.0.0.0")


def is_ip_range(_input: str) -> bool:
    """
    Validate ip range format
    Example of valid range: 10.0.0.1-20
    :param _input:
    :return:
    """
    if _input is not None:
        ip_range = _input.split("-")
        if len(ip_range) != 2:
            return False
        return valid_nmap_range(_input)
    else:
        return False


def is_valid_port(_input: int) -> bool:
    """
    Check if port is valid
    Note; Port 0 is excluded
    :param _input:
    :return:
    """
    return _input is not None and validators.between(_input, 1, 65353) is True


def is_parsable_to_date(_input: str) -> bool:
    """
    Check if input is parsable to datetime
    :param _input: datetime string
    :return:
    """
    try:
        _ = parser.parse(_input)
        return True
    except Exception as e:
        print(f'Failed to parse {_input} to datetime {e}')
        return False


def is_valid_time_zone(_input: str) -> bool:
    """
    Check if a valid input is a valid timezone
    :param _input: time zone
    :return:
    """
    try:
        _ = pytz.timezone(_input)
        return True
    except Exception as e:
        print(f'Invalid timezone value {_input}, {e}')
        return False
