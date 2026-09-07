from .registry import parse_file


def parse_crowdstrike_detection_file(path):
    return parse_file(path, "crowdstrike_detection")
