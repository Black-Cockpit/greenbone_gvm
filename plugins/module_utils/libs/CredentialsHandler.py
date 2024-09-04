import json
from typing import List

import xmltodict
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

from ..exceptions.ResourceInUseError import ResourceInUseError
from ..models.CredentialsModel import CredentialsModel
from ..models.ExecutionResult import ExecutionResult
from ..models.GvmAdminCredentialsModel import GvmAdminCredentialsModel
from ..utils.GvmUtils import is_success_response


class CredentialsHandler(object):
    """
    Credentials handler
     Args:
        credentials (List[CredentialsModel])     : List of credentials
    """
    __slots__ = [
        'credentials',
    ]

    def __init__(self, credentials: List[CredentialsModel] = None):
        self.credentials = []
        if credentials is None:
            credentials = []
        for item in credentials:
            self.credentials.append(item)

    def create_or_update_credentials(self, socket: UnixSocketConnection,
                                     admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Create or update credentials
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

            existing_credentials = xmltodict.parse(get_credentials_response).get("get_credentials_response", {}).get(
                "credential")

            execution_result = ExecutionResult()

            for credentials in self.credentials:
                credentials_id = credentials.get_credentials_id(existing_credentials)
                if credentials_id is None:
                    create_credential_response = gmp.create_credential(name=credentials.name,
                                                                       comment=credentials.comment,
                                                                       credential_type=credentials.credential_type,
                                                                       password=credentials.password,
                                                                       community=credentials.community,
                                                                       key_phrase=credentials.key_phrase,
                                                                       public_key=credentials.get_public_key(),
                                                                       private_key=credentials.get_private_key(),
                                                                       certificate=credentials.get_certificate(),
                                                                       allow_insecure=credentials.allow_insecure,
                                                                       auth_algorithm=credentials.auth_algorithm,
                                                                       privacy_password=credentials.privacy_password,
                                                                       privacy_algorithm=credentials.privacy_algorithm,
                                                                       login=credentials.login)
                    dic = xmltodict.parse(create_credential_response)
                    if is_success_response(dic, "create_credential_response") is False:
                        raise AssertionError(f"Failed to create credentials {credentials.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True

                else:
                    modify_credential_response = gmp.modify_credential(credential_id=credentials_id,
                                                                       name=credentials.name,
                                                                       comment=credentials.comment,
                                                                       password=credentials.password,
                                                                       community=credentials.community,
                                                                       key_phrase=credentials.key_phrase,
                                                                       public_key=credentials.get_public_key(),
                                                                       private_key=credentials.get_private_key(),
                                                                       certificate=credentials.get_certificate(),
                                                                       allow_insecure=credentials.allow_insecure,
                                                                       auth_algorithm=credentials.auth_algorithm,
                                                                       privacy_password=credentials.privacy_password,
                                                                       privacy_algorithm=credentials.privacy_algorithm,
                                                                       login=credentials.login)
                    dic = xmltodict.parse(modify_credential_response)
                    if is_success_response(dic, "modify_credential_response") is False:
                        raise AssertionError(f"Failed to update credentials {credentials.name}: \n {dic}")

                    if execution_result.changed is False:
                        if credentials.is_in_use(existing_credentials):
                            execution_result.warning_message = f"Credentials {credentials.name} is already in use, some of the property will be ignored and will not be updated."
                        execution_result.changed = True
            return execution_result

    def delete_credentials(self, socket: UnixSocketConnection,
                           admin_credentials: GvmAdminCredentialsModel) -> ExecutionResult:
        """
        Delete credentials
        :param admin_credentials: GVM admin credentials
        :param socket: GVM Unix domain socket
        :return:
         """
        with Gmp(connection=socket) as gmp:

            gmp.authenticate(admin_credentials.username, admin_credentials.password)

            execution_result = ExecutionResult(changed=False)

            # List existing credentials
            get_credentials_response = gmp.get_credentials()
            if is_success_response(xmltodict.parse(get_credentials_response), "get_credentials_response") is False:
                return execution_result

            existing_credentials = xmltodict.parse(get_credentials_response).get("get_credentials_response", {}).get(
                "credential")

            for credentials in self.credentials:
                if credentials.is_in_use(existing_credentials):
                    raise ResourceInUseError(f"Credentials {credentials.name} is in use and not be deleted")

                credentials_id = credentials.get_credentials_id(existing_credentials)
                if credentials_id is not None:
                    delete_credential_response = gmp.delete_credential(credential_id=credentials_id, ultimate=True)
                    dic = xmltodict.parse(delete_credential_response)
                    if is_success_response(dic, "delete_credential_response") is False:
                        raise AssertionError(f"Failed to update credentials {credentials.name}: \n {dic}")

                    if execution_result.changed is False:
                        execution_result.changed = True

            return execution_result

    @classmethod
    def from_json(cls, json_string: str):
        if json_string is None or len(json_string) <= 0:
            return cls()

        json_dic = json.loads(json_string)
        return cls(**json_dic)
