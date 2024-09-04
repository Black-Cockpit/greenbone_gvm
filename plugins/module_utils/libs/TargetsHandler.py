import json
from typing import List

import xmltodict
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmp.requests.v225 import CredentialType

from ..exceptions.ResourceInUseError import ResourceInUseError
from ..models.ExecutionResult import ExecutionResult
from ..models.GvmAdminCredentialsModel import GvmAdminCredentialsModel
from ..models.TargetModel import TargetModel
from ..utils.GvmUtils import is_success_response


class TargetsHandler(object):
    """
    Targets handler
     Args:
        targets (List[TargetModel])     : List of targets
    """
    __slots__ = [
        'targets',
    ]

    def __init__(self, targets: List[TargetModel] = None):
        self.targets = []
        if targets is None:
            targets = []
        for target in targets:
            self.targets.append(target)

    def create_or_update_targets(self, socket: UnixSocketConnection,
                                 admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Create or update targets
        :param admin_credentials: GVM admin credentials
        :param socket: GVM Unix domain socket
        :return:
        """
        with Gmp(connection=socket) as gmp:
            gmp.authenticate(admin_credentials.username, admin_credentials.password)

            # List existing credentials
            get_credentials_response = gmp.get_credentials()
            if is_success_response(xmltodict.parse(get_credentials_response), "get_credentials_response") is False:
                raise AssertionError(f"Failed to to get gvm credentials list")

            execution_result = ExecutionResult()

            existing_credentials = xmltodict.parse(get_credentials_response).get("get_credentials_response", {}).get(
                "credential")

            # List targets
            target_list_response = gmp.get_targets(filter_string="first=0 rows=100")
            if is_success_response(xmltodict.parse(target_list_response), "get_targets_response") is False:
                raise AssertionError(f"Failed to to get gvm target list")

            existing_targets = xmltodict.parse(target_list_response).get("get_targets_response", {}).get("target", {})

            # List available ports
            ports_list_response = gmp.get_port_lists()
            if is_success_response(xmltodict.parse(ports_list_response), "get_port_lists_response") is False:
                raise AssertionError(f"Failed to to get gvm port list")

            ports_list = xmltodict.parse(ports_list_response).get("get_port_lists_response", {}).get("port_list", {})

            if ports_list is None:
                raise AssertionError(f"Failed to to extract gvm port list")

            # Create or update targets
            for target in self.targets:
                target_ports_list_id = target.get_ports_list_id(ports_list)
                target_id = target.get_target_id(existing_targets)

                credentials_id = None
                credentials_type = None

                if target.credentials_name and target.credentials_name != '':
                    credentials_id, credentials_type = target.get_credentials_id(existing_credentials,
                                                                                 target.credentials_name)

                ssh_credential_id = None
                esxi_credential_id = None
                smb_credential_id = None
                snmp_credential_id = None

                if credentials_type == CredentialType.SNMP.value:
                    snmp_credential_id = credentials_id
                elif credentials_type == CredentialType.USERNAME_SSH_KEY.value or \
                        credentials_type == CredentialType.PASSWORD_ONLY.value or \
                        credentials_type == CredentialType.USERNAME_PASSWORD.value:
                    ssh_credential_id = credentials_id
                elif credentials_type == CredentialType.PGP_ENCRYPTION_KEY.value or \
                        credentials_type == CredentialType.SMIME_CERTIFICATE.value or \
                        credentials_type == CredentialType.CLIENT_CERTIFICATE.value:
                    smb_credential_id = credentials_id

                if target_ports_list_id is None and (target.port_range is None or len(target.port_range) <= 0):
                    raise AssertionError(f"Either port list id or port range is needed to create a target")

                if target_id is None:
                    create_target_response = gmp.create_target(name=target.name,
                                                               comment=target.comment,
                                                               hosts=target.hosts,
                                                               exclude_hosts=target.exclude_hosts,
                                                               allow_simultaneous_ips=target.allow_simultaneous_ips,
                                                               port_list_id=target_ports_list_id,
                                                               port_range=target.port_range,
                                                               alive_test=target.alive_test,
                                                               reverse_lookup_only=target.reverse_lookup_only,
                                                               reverse_lookup_unify=target.reverse_lookup_unify,
                                                               ssh_credential_port=target.ssh_port,
                                                               ssh_credential_id=ssh_credential_id,
                                                               esxi_credential_id=esxi_credential_id,
                                                               smb_credential_id=smb_credential_id,
                                                               snmp_credential_id=snmp_credential_id)
                    dic = xmltodict.parse(create_target_response)
                    if is_success_response(dic, "create_target_response") is False:
                        raise AssertionError(f"Failed to create target {target.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True
                else:
                    if target.is_in_use(existing_targets):
                        modify_target_response = gmp.modify_target(target_id=target_id,
                                                                   name=target.name,
                                                                   comment=target.comment,
                                                                   alive_test=target.alive_test)
                    else:
                        modify_target_response = gmp.modify_target(target_id=target_id,
                                                                   name=target.name,
                                                                   hosts=target.hosts,
                                                                   comment=target.comment,
                                                                   exclude_hosts=target.exclude_hosts,
                                                                   allow_simultaneous_ips=target.allow_simultaneous_ips,
                                                                   port_list_id=target_ports_list_id,
                                                                   alive_test=target.alive_test,
                                                                   reverse_lookup_only=target.reverse_lookup_only,
                                                                   reverse_lookup_unify=target.reverse_lookup_unify,
                                                                   ssh_credential_port=target.ssh_port,
                                                                   ssh_credential_id=ssh_credential_id,
                                                                   esxi_credential_id=esxi_credential_id,
                                                                   smb_credential_id=smb_credential_id,
                                                                   snmp_credential_id=snmp_credential_id)
                    dic = xmltodict.parse(modify_target_response)
                    if is_success_response(dic, "modify_target_response") is False:
                        raise AssertionError(f"Failed to modify target {target.name}: \n {dic}")

                    if execution_result.changed is False:
                        if target.is_in_use(existing_credentials):
                            execution_result.warning_message = f"Target {target.name} is already in use, some of the property will be ignored and will not be updated."
                        execution_result.changed = True
            return execution_result


    def delete_targets(self, socket: UnixSocketConnection,
                                 admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Delete targets
        :param admin_credentials: GVM admin credentials
        :param socket: GVM Unix domain socket
        :return:
        """
        with Gmp(connection=socket) as gmp:
            gmp.authenticate(admin_credentials.username, admin_credentials.password)

            execution_result = ExecutionResult(changed=False)

            # List targets
            target_list_response = gmp.get_targets(filter_string="first=0 rows=100")
            if is_success_response(xmltodict.parse(target_list_response), "get_targets_response") is False:
                return execution_result

            existing_targets = xmltodict.parse(target_list_response).get("get_targets_response", {}).get("target", {})

            # Delete targets
            for target in self.targets:
                if target.is_in_use(existing_targets):
                    raise ResourceInUseError(f"Target {target.name} is in use and can not be deleted")

                target_id = target.get_target_id(existing_targets)

                if target_id is not None:
                    gmp.empty_trashcan()
                    delete_target_response = gmp.delete_target(target_id=target_id,ultimate=True)

                    dic = xmltodict.parse(delete_target_response)
                    if is_success_response(dic, "delete_target_response") is False:
                        raise AssertionError(f"Failed to delete target {target.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True
            return execution_result

    @classmethod
    def from_json(cls, json_string: str):
        if json_string is None or len(json_string) <= 0:
            return cls()

        json_dic = json.loads(json_string)
        return cls(**json_dic)
