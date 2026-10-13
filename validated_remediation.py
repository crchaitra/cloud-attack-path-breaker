
from access_validation import validate_legitimate_paths
from multi_remediation import find_multi_edge_remediation


def find_validated_multi_edge_remediation(
    cloud,
    entry_point,
    protected_asset,
    legitimate_paths=None,
    max_removals=3,
):
    """
    Validate required access before searching for a safe
    multi-connection remediation.
    """

    if legitimate_paths is None:
        legitimate_paths = []

    # Validate required access against the original graph.
    validate_legitimate_paths(cloud, legitimate_paths)

    # Run the search and return its result dictionary.
    return find_multi_edge_remediation(
        cloud,
        entry_point,
        protected_asset,
        legitimate_paths=legitimate_paths,
        max_removals=max_removals,
    )
