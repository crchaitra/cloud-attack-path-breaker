
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
    Validate legitimate access paths before searching
    for a safe multi-edge security remediation.
    """

    if legitimate_paths is None:
        legitimate_paths = []

    # Step 1: Check required paths against the original graph.
    validate_legitimate_paths(cloud, legitimate_paths)

    # Step 2: Search for a remediation only after validation.
    return find_multi_edge_remediation(
        cloud,
        entry_point,
        protected_asset,
        legitimate_paths=legitimate_paths,
        max_removals=max_removals,
    )
