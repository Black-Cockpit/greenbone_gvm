# Copyright: (c) 2024, Black-Cockpit <hasnimehdi@outlook.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import json
from typing import List, Optional
from gvm.protocols.gmp.requests.v225 import AliveTest

from ..utils.data_validator import is_valid_domain_or_ip_or_network, is_global_ip_or_global_cidr, is_valid_port


def _get_alive_test(alive_test: str) -> AliveTest:
    """
    Get alive test

    :param alive_test: Alive test
    :return:
    """
    if alive_test is None:
        return AliveTest.SCAN_CONFIG_DEFAULT
    if alive_test == "ICMP_PING":
        return AliveTest.ICMP_PING
    if alive_test == "TCP_ACK_SERVICE_PING":
        return AliveTest.TCP_ACK_SERVICE_PING
    if alive_test == "TCP_SYN_SERVICE_PING":
        return AliveTest.TCP_SYN_SERVICE_PING
    if alive_test == "ARP_PING":
        return AliveTest.ARP_PING
    if alive_test == "ICMP_PING":
        return AliveTest.ICMP_PING
    if alive_test == "ICMP_AND_TCP_ACK_SERVICE_PING":
        return AliveTest.ICMP_AND_TCP_ACK_SERVICE_PING
    if alive_test == "ICMP_AND_ARP_PING":
        return AliveTest.ICMP_AND_ARP_PING
    if alive_test == "TCP_ACK_SERVICE_AND_ARP_PING":
        return AliveTest.TCP_ACK_SERVICE_AND_ARP_PING
    if alive_test == "ICMP_TCP_ACK_SERVICE_AND_ARP_PING":
        return AliveTest.ICMP_TCP_ACK_SERVICE_AND_ARP_PING
    if alive_test == "CONSIDER_ALIVE":
        return AliveTest.CONSIDER_ALIVE
    else:
        return AliveTest.SCAN_CONFIG_DEFAULT


class TargetModel(object):
    """ Target model
    Args:
        name (str)                              : Target name
        hosts (List[str])                       : List of IP addresses, networks or hostnames to scan
        comment (str)                           : Description of the target
        exclude_hosts (List[str])               : List of IP addresses, networks or hostnames ro exclude from the scan
        allow_simultaneous_ips (bool)           : Allow scanning from different source IPs
        port_range (List[int])                  : List of ports to be scanned
        port_list_name (str)                    : Port list name
        alive_test (AliveTest)                  : Alive test type
        reverse_lookup_only (bool)              : Allow reverse lookup only
        reverse_lookup_unify (bool)             : Unify reverse lookup
        reverse_lookup_unify (bool)             : Unify reverse lookup
        credentials_name (str)                  : SSH key name
        ssh_port (int)                          : SSH port
    """

    __slots__ = [
        '_name',
        '_hosts',
        'comment',
        "_exclude_hosts",
        'allow_simultaneous_ips',
        '_port_range',
        'port_list_name',
        'alive_test',
        'reverse_lookup_only',
        'reverse_lookup_unify',
        'credentials_name',
        '_ssh_port'
    ]

    def __init__(self, name: str = None, hosts: List[str] = None, comment: Optional[str] = None,
                 exclude_hosts: Optional[List[str]] = None, allow_simultaneous_ips: bool = True,
                 port_range: Optional[List[int]] = None, port_list_name: str = None,
                 alive_test: Optional[str] = AliveTest.SCAN_CONFIG_DEFAULT,
                 reverse_lookup_only: Optional[bool] = False, reverse_lookup_unify: Optional[bool] = False,
                 credentials_name: Optional[str] = None, ssh_port: Optional[int] = 22) -> None:
        self.name = name
        self.hosts = hosts
        self.comment = comment
        self.exclude_hosts = exclude_hosts
        self.allow_simultaneous_ips = allow_simultaneous_ips
        self.port_range = port_range
        self.port_list_name = port_list_name

        self.alive_test = _get_alive_test(alive_test)

        self.reverse_lookup_only = reverse_lookup_only
        self.reverse_lookup_unify = reverse_lookup_unify
        self.credentials_name = credentials_name

        if ssh_port is None:
            ssh_port = 22
        self.ssh_port = ssh_port

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name: str):
        if name is None or name == '' or name.isspace():
            raise ValueError("Target name is required")
        self._name = name

    @property
    def hosts(self):
        return self._hosts

    @hosts.setter
    def hosts(self, hosts: List[str]):
        if hosts is None or len(hosts) <= 0:
            raise ValueError("Target hosts is required")

        for host in hosts:
            if is_valid_domain_or_ip_or_network(host) is False or is_global_ip_or_global_cidr(host):
                raise ValueError(f"{host} is not a valid domain, ip or cidr")
        self._hosts = hosts

    @property
    def exclude_hosts(self):
        return self._exclude_hosts

    @exclude_hosts.setter
    def exclude_hosts(self, exclude_hosts: Optional[List[str]] = None):
        if exclude_hosts is not None and len(exclude_hosts) > 0:
            for host in exclude_hosts:
                if is_valid_domain_or_ip_or_network(host) is False or is_global_ip_or_global_cidr(host):
                    raise ValueError(f"{host} is not a valid domain, ip or cidr")
            self._exclude_hosts = exclude_hosts
        else:
            self._exclude_hosts = None

    @property
    def port_range(self):
        return self._port_range

    @port_range.setter
    def port_range(self, port_range: Optional[List[int]] = None):
        if port_range is not None and len(port_range) > 0:
            for port in port_range:
                if is_valid_port(port) is False:
                    raise ValueError(f"{port} is not a valid port, the port number should be between 1 and 65353")
            self._port_range = port_range
        else:
            self._port_range = None

    @property
    def ssh_port(self):
        return self._ssh_port

    @ssh_port.setter
    def ssh_port(self, ssh_port: int):
        if is_valid_port(ssh_port) is False:
            raise ValueError(f"{ssh_port} is not a valid  ssh port, the port number should be between 1 and 65353")
        self._ssh_port = ssh_port

    def get_ports_list_id(self, ports_list: dict) -> str:
        """
        Get ports list id
        :param ports_list: GVM ports list
        :return:
        """
        if ports_list is not None and len(ports_list) > 0:
            if type(ports_list) is list:
                for ports in ports_list:
                    if ports.get("name") is not None and ports.get("name") == self.port_list_name:
                        return ports.get("@id")
            elif type(ports_list) is dict:
                if ports_list.get("name") is not None and ports_list.get("name") == self.port_list_name:
                    return ports_list.get("@id")

    def get_target_id(self, targets: dict):
        """
        Get target id from list of GVM targets
        :param targets: GVM targets
        :return:
        """
        if targets is not None and len(targets) > 0:
            if type(targets) is list:
                for target in targets:
                    if target.get("name") == self.name:
                        return target.get("@id")
            elif type(targets) is dict:
                if targets.get("name") == self.name:
                    return targets.get("@id")

    @staticmethod
    def get_credentials_id(credentials_list: dict, name: str) -> (str, str):
        """
        Get credentials id from list of GVM credentials
        :param name: Credentials name
        :param credentials_list: GVM credentials list
        :return:
        """
        if credentials_list is not None and len(credentials_list) > 0:
            if type(credentials_list) is list:
                for credentials in credentials_list:
                    if credentials.get("name") == name:
                        return credentials.get("@id"), credentials.get("type")
            elif type(credentials_list) is dict:
                if credentials_list.get("name") == name:
                    return credentials_list.get("@id"), credentials_list.get("type")

    def is_in_use(self, targets: dict) -> bool:
        """
        Check if target is used by a scan task or audit
        :param targets: GVM targets
        :return:
        """
        if targets is not None and len(targets) > 0:
            if type(targets) is list:
                for target in targets:
                    if target.get("name") == self.name:
                        return target.get("in_use") is not None and target.get("in_use") != "" \
                            and int(target.get("in_use")) >= 1
            elif type(targets) is dict:
                if targets.get("name") == self.name:
                    return targets.get("in_use") is not None and targets.get("in_use") != "" \
                        and int(targets.get("in_use")) >= 1

    @classmethod
    def from_json(cls, json_string: str):
        if json_string is None or len(json_string) <= 0:
            return cls()

        json_dic = json.loads(json_string)
        return cls(**json_dic)
