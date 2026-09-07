from .registry import parse_file


def parse_entra_signin_file(path):
    return parse_file(path, "entra_signin")
