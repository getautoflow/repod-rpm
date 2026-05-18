import os
from slowapi import Limiter
from slowapi.util import get_remote_address

_auth_rate = os.getenv("AUTH_RATELIMIT_PER_MINUTE", "10")
auth_limit = f"{_auth_rate}/minute"

limiter = Limiter(key_func=get_remote_address, default_limits=[])
