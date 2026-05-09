import datetime


def get_current_timestamp() -> int:
    return int(datetime.datetime.now(datetime.UTC).timestamp())


__all__ = ["get_current_timestamp"]
