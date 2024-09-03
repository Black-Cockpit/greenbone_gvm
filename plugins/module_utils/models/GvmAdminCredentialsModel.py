class GvmAdminCredentialsModel:
    """ GVM admin credentials model
       Args:
           username (str)   : Username
           password (str)   : Password
       """

    __slots__ = [
        'username',
        'password'
    ]

    def __init__(self, username: str, password: str):
        if username is None or username == '' or username.isspace():
            raise ValueError("Username is required")
        if password is None or password == '' or password.isspace():
            raise ValueError("Password is required")

        self.username = username
        self.password = password
