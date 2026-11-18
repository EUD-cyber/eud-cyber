"""Retired local handoff compatibility module. No key, ticket or login state."""


def issue(*args, **kwargs):
    raise ValueError('Lab Mode needs no activation link. Open the dashboard directly.')


def consume(*args, **kwargs):
    return False
