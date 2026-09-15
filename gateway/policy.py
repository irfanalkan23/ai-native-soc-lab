"""Policy engine and input validation for bounded Splunk search queries.

This module enforces strict security boundaries on parameters before any query
can be sent to Splunk. Callers cannot submit arbitrary SPL, change indices,
modify endpoints, or pass unbound parameter types.
"""

from dataclasses import dataclass
from typing import Tuple, Union


class PolicyValidationError(ValueError):
    """Raised when request parameters violate deterministic security policies."""
    pass


ALLOWED_QUERY_TYPES = frozenset({"encoded_powershell_matches"})
ALLOWED_HOSTS = frozenset({"DC01"})

MIN_MINUTES = 1
MAX_MINUTES = 60

MIN_LIMIT = 1
MAX_LIMIT = 50

ALLOWED_FIELDS: Tuple[str, ...] = (
    "_time",
    "host",
    "User",
    "Image",
    "CommandLine",
    "ParentImage",
    "ParentCommandLine",
)


@dataclass(frozen=True)
class SearchRequest:
    """Immutable data container representing a policy-validated search request.

    Invariants are enforced upon construction in __post_init__ to prevent callers
    from creating an unvalidated or policy-violating request instance.
    """
    query_type: str
    host: str
    minutes: int
    limit: int

    def __post_init__(self) -> None:
        """Enforce validation boundaries on all fields during instantiation."""
        # Validate query_type
        if type(self.query_type) is not str:
            raise PolicyValidationError(
                f"Invalid query_type type: expected str, got {type(self.query_type).__name__}"
            )
        if self.query_type not in ALLOWED_QUERY_TYPES:
            raise PolicyValidationError(
                f"Unauthorized query_type '{self.query_type}'. Allowed: {sorted(ALLOWED_QUERY_TYPES)}"
            )

        # Validate host
        if type(self.host) is not str:
            raise PolicyValidationError(
                f"Invalid host type: expected str, got {type(self.host).__name__}"
            )
        if self.host not in ALLOWED_HOSTS:
            raise PolicyValidationError(
                f"Unauthorized host '{self.host}'. Allowed: {sorted(ALLOWED_HOSTS)}"
            )

        # Validate minutes (strictly int, reject bool)
        if type(self.minutes) is not int:
            raise PolicyValidationError(
                f"Invalid minutes type: expected int, got {type(self.minutes).__name__}"
            )
        if not (MIN_MINUTES <= self.minutes <= MAX_MINUTES):
            raise PolicyValidationError(
                f"Parameter 'minutes' must be between {MIN_MINUTES} and {MAX_MINUTES}, got {self.minutes}"
            )

        # Validate limit (strictly int, reject bool)
        if type(self.limit) is not int:
            raise PolicyValidationError(
                f"Invalid limit type: expected int, got {type(self.limit).__name__}"
            )
        if not (MIN_LIMIT <= self.limit <= MAX_LIMIT):
            raise PolicyValidationError(
                f"Parameter 'limit' must be between {MIN_LIMIT} and {MAX_LIMIT}, got {self.limit}"
            )


def validate_search_request(
    query_type: str,
    host: str,
    minutes: int,
    limit: int,
) -> SearchRequest:
    """Validate caller parameters against deterministic boundaries and return SearchRequest.

    Fails closed by raising PolicyValidationError on any boundary violation.
    Type checks explicitly disallow boolean coercion (e.g. isinstance(True, int)).
    """
    return SearchRequest(
        query_type=query_type,
        host=host,
        minutes=minutes,
        limit=limit,
    )


def build_allowlisted_spl(request: SearchRequest) -> str:
    """Construct an allowlisted SPL query strictly from a validated SearchRequest.

    Defense-in-depth: Re-validates all parameters against policy boundaries.
    Callers cannot supply arbitrary SPL or alter query structure under any circumstances.
    """
    if not isinstance(request, SearchRequest):
        raise PolicyValidationError(
            f"Expected SearchRequest instance, got {type(request).__name__}"
        )

    # Invariant assertion (defense-in-depth check)
    if request.query_type not in ALLOWED_QUERY_TYPES:
        raise PolicyValidationError(f"Unauthorized query type: {request.query_type}")
    if request.host not in ALLOWED_HOSTS:
        raise PolicyValidationError(f"Unauthorized host: {request.host}")
    if type(request.minutes) is not int or not (MIN_MINUTES <= request.minutes <= MAX_MINUTES):
        raise PolicyValidationError(f"Invalid minutes parameter: {request.minutes}")
    if type(request.limit) is not int or not (MIN_LIMIT <= request.limit <= MAX_LIMIT):
        raise PolicyValidationError(f"Invalid limit parameter: {request.limit}")

    return (
        f'search index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
        f'host="{request.host}" earliest="-{request.minutes}m" "<EventID>1</EventID>" '
        '| rex field=_raw "<Data Name=\'Image\'>(?<Image>[^<]+)" '
        '| rex field=_raw "<Data Name=\'CommandLine\'>(?<CommandLine>[^<]+)" '
        '| rex field=_raw "<Data Name=\'ParentImage\'>(?<ParentImage>[^<]+)" '
        '| rex field=_raw "<Data Name=\'ParentCommandLine\'>(?<ParentCommandLine>[^<]+)" '
        '| rex field=_raw "<Data Name=\'User\'>(?<User>[^<]+)" '
        r'| where match(Image, "(?i)\\\\powershell\.exe$") '
        r'| where match(CommandLine, "(?i)(^|\\s)-(encodedcommand|enc)\\b") '
        f'| head {request.limit} '
        '| table _time host User Image CommandLine ParentImage ParentCommandLine'
    )
