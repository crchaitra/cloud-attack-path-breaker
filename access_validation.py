
def validate_legitimate_paths(cloud, legitimate_paths):
    """
    Verify that every configured legitimate path consists
    of existing connections in the correct order.

    Returns True when all paths are valid.
    Raises ValueError when a path is invalid.
    """

    if not isinstance(legitimate_paths, list):
        raise ValueError("Legitimate paths must be a list.")

    for path in legitimate_paths:
        if not isinstance(path, list) or len(path) < 2:
            raise ValueError(
                "Each legitimate path must contain at least "
                "two resource IDs."
            )

        for resource_id in path:
            if resource_id not in cloud:
                raise ValueError(
                    f"Legitimate path references unknown resource: "
                    f"{resource_id}"
                )

        for source, target in zip(path, path[1:]):
            if not cloud.has_edge(source, target):
                raise ValueError(
                    f"Legitimate path contains a missing connection: "
                    f"{source} -> {target}"
                )

    return True


def legitimate_access_preserved_strict(
    original_graph,
    simulated_graph,
    legitimate_paths,
):
    """
    Validate the required paths in the original graph, then
    check that every required connection remains after a fix.
    """

    validate_legitimate_paths(original_graph, legitimate_paths)

    for path in legitimate_paths:
        for source, target in zip(path, path[1:]):
            if not simulated_graph.has_edge(source, target):
                return False

    return True
