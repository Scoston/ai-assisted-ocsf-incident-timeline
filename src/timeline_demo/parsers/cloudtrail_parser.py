from .registry import parse_file


def parse_cloudtrail_file(path):
    return parse_file(path, "cloudtrail")
