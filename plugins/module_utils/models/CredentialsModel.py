from __future__ import annotations

import json
from typing import Optional
from base64 import b64decode

from gvm.protocols.gmp.requests.v225 import CredentialType, SnmpAuthAlgorithm, SnmpPrivacyAlgorithm


def _get_credentials_type(credential_type: str) -> CredentialType:
    """
    Get credentials type

    :param credential_type: Credentials type
    :return:
    """
    if credential_type is None:
        return CredentialType.USERNAME_PASSWORD
    if credential_type == "CLIENT_CERTIFICATE":
        return CredentialType.CLIENT_CERTIFICATE
    if credential_type == "SNMP":
        return CredentialType.SNMP
    if credential_type == "USERNAME_PASSWORD":
        return CredentialType.USERNAME_PASSWORD
    if credential_type == "USERNAME_SSH_KEY":
        return CredentialType.USERNAME_SSH_KEY
    if credential_type == "SMIME_CERTIFICATE":
        return CredentialType.SMIME_CERTIFICATE
    if credential_type == "PGP_ENCRYPTION_KEY":
        return CredentialType.PGP_ENCRYPTION_KEY
    if credential_type == "PASSWORD_ONLY":
        return CredentialType.PASSWORD_ONLY
    else:
        return CredentialType.USERNAME_PASSWORD


def get_auth_algorithm(auth_algorithm: str) -> SnmpAuthAlgorithm | None:
    """
    Get SNMP auth algorithm from name

    :param auth_algorithm: SNMP auth algorithm name
    :return:
    """
    if auth_algorithm is not None and auth_algorithm == "MD5":
        return SnmpAuthAlgorithm.MD5
    if auth_algorithm is not None and auth_algorithm == "SHA1":
        return SnmpAuthAlgorithm.SHA1
    else:
        return None


def get_privacy_algorithm(privacy_algorithm: str) -> SnmpPrivacyAlgorithm | None:
    """
    Get SNMP privacy algorithm from name

    :param privacy_algorithm: SNMP privacy algorithm name
    :return:
    """
    if privacy_algorithm is not None and privacy_algorithm == "AES":
        return SnmpPrivacyAlgorithm.AES
    if privacy_algorithm is not None and privacy_algorithm == "DES":
        return SnmpPrivacyAlgorithm.DES
    else:
        return None


class CredentialsModel(object):
    """ Target model
        Args:
            name (str)                                  : Name of the new credential
            credential_type (CredentialType)            : The credential type.
            comment (str)                               : Description of the credential
            allow_insecure (bool)                       : Whether to allow insecure use of the credential

            certificate_base64 (str)                           : Certificate for the credential.
                Required for client-certificate and smime credential types.

            key_phrase (str)                            : Key passphrase for the private key.
                Used for the username+ssh-key credential type.

            private_key_base64 (str)                      : Private key to use for login. Required for usk credential
                type. Also used for the cc credential type. The supported key types (dsa, rsa, ecdsa, ...) and
                formats (PEM, PKC#12, OpenSSL, ...) depend on your installed GnuTLS version.

            login (str)                                 : Username for the credential. Required for username+password,
                username+ssh-key and snmp credential type.

            password (str)                              : Password for the credential. Used for username+password
                and snmp credential types.

            auth_algorithm (SnmpAuthAlgorithm)          : The SNMP authentication algorithm. Required for snmp
                credential type.
            community (str)                             : The SNMP community
            privacy_algorithm (SnmpPrivacyAlgorithm)    : The SNMP privacy algorithm
            privacy_password (str)                      : The SNMP privacy password
            public_key_base64 (str)                     : GP public key in *armor* plain text format. Required
                for pgp credential type.
        """

    __slots__ = [
        '_name',
        '_credential_type',
        'comment',
        "allow_insecure",
        'certificate_base64',
        'key_phrase',
        'private_key_base64',
        'login',
        'password',
        'auth_algorithm',
        'community',
        'privacy_algorithm',
        'privacy_password',
        'public_key_base64'
    ]

    def __init__(self, name: str = None, credential_type: Optional[str] = None,
                 comment: Optional[str] = None, allow_insecure: Optional[bool] = None,
                 certificate_base64: Optional[str] = None, key_phrase: Optional[str] = None,
                 private_key_base64: Optional[str] = None, login: Optional[str] = None, password: Optional[str] = None,
                 auth_algorithm: Optional[str] = None, community: Optional[str] = None,
                 privacy_algorithm: str = None, privacy_password: Optional[str] = None,
                 public_key_base64: Optional[str] = None):
        self.name = name
        self.allow_insecure = allow_insecure
        self.login = login
        self.password = password
        self.private_key_base64 = private_key_base64
        self.comment = comment
        self.certificate_base64 = certificate_base64
        self.key_phrase = key_phrase
        self.community = community
        self.privacy_password = privacy_password
        self.public_key_base64 = public_key_base64
        self.auth_algorithm = get_auth_algorithm(auth_algorithm)
        self.privacy_algorithm = get_privacy_algorithm(privacy_algorithm)
        self.credential_type = _get_credentials_type(credential_type)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name: str):
        if name is None or name == '' or name.isspace():
            raise ValueError("Target name is required")
        self._name = name

    @property
    def credential_type(self):
        return self._credential_type

    @credential_type.setter
    def credential_type(self, credential_type: CredentialType):
        if credential_type is None:
            raise ValueError("Credentials type is required")

        if credential_type == CredentialType.USERNAME_PASSWORD:
            if self.login is None or self.login == '' or self.login.isspace() or self.password is None or \
                    self.password == '' or self.login.isspace():
                raise ValueError("Login and password are required")
        elif credential_type == CredentialType.CLIENT_CERTIFICATE:
            if self.get_private_key() is None or self.get_private_key() == '' or self.get_private_key().isspace() or \
                    self.get_certificate() is None or self.get_certificate() == '' or self.get_certificate().isspace():
                raise ValueError("Private key and certificate are required")
        elif credential_type == CredentialType.USERNAME_SSH_KEY:
            if self.get_private_key() is None or self.get_private_key() == '' or self.get_private_key().isspace() or \
                    self.login is None or self.login == '' or self.login.isspace():
                raise ValueError("Login and private key are required")
        elif credential_type == CredentialType.PASSWORD_ONLY:
            if self.password is None or self.password == '' or self.login.isspace():
                raise ValueError("Password are required")
        self._credential_type = credential_type

    def get_public_key(self):
        """
        Decode public key

        :return:
        """
        if self.public_key_base64 is not None and self.public_key_base64 != '' and self.public_key_base64.isspace() is False:
            try:
                return b64decode(self.public_key_base64, validate=True).decode("utf-8")
            except Exception as e:
                raise ValueError(f"Invalid public key base64 format, {e}")

    def get_certificate(self):
        """
        Decode certificate

        :return:
        """
        if self.certificate_base64 is not None and self.certificate_base64 != '' \
                and self.certificate_base64.isspace() is False:
            try:
                return b64decode(self.certificate_base64, validate=True).decode("utf-8")
            except Exception as e:
                raise ValueError(f"Invalid certificate base64 format, {e}")

    def get_private_key(self) -> str:
        """
        Get private key

        :return:
        """
        if self.private_key_base64 is not None and self.private_key_base64 != '' \
                and self.private_key_base64.isspace() is False:
            try:
                return b64decode(self.private_key_base64, validate=True).decode("utf-8")
            except Exception as e:
                raise ValueError(f"Invalid private key base64 format, {e}")

    def get_credentials_id(self, credentials_list: dict):
        """
        Get credentials id from list of GVM credentials

        :param credentials_list: GVM credentials list
        :return:
        """
        if credentials_list is not None and len(credentials_list) > 0:
            if type(credentials_list) is list:
                for credentials in credentials_list:
                    if credentials.get("name") == self.name:
                        return credentials.get("@id")
            elif type(credentials_list) is dict:
                if credentials_list.get("name") == self.name:
                    return credentials_list.get("@id")

    def is_in_use(self, credentials: dict) -> bool:
        """
        Check if credential is used by another resource
        :param credentials: GVM credentials
        :return:
        """
        if credentials is not None and len(credentials) > 0:
            if type(credentials) is list:
                for credential in credentials:
                    if credential.get("name") == self.name:
                        return credential.get("in_use") is not None and credential.get("in_use") != "" \
                            and int(credential.get("in_use")) >= 1
            elif type(credentials) is dict:
                if credentials.get("name") == self.name:
                    return credentials.get("in_use") is not None and credentials.get("in_use") != "" \
                        and int(credentials.get("in_use")) >= 1

    @classmethod
    def from_json(cls, json_string: str):
        if json_string is None or len(json_string) <= 0:
            return cls()

        json_dic = json.loads(json_string)
        return cls(**json_dic)
