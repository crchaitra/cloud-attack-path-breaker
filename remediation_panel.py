
import streamlit as st

from main import recommend_remediations
from validated_remediation import (
    find_validated_multi_edge_remediation,
)


def show_remediation_panel(
    cloud,
    entry_point,
    protected_asset,
    legitimate_paths=None,
):
    if legitimate_paths is None:
        legitimate_paths = []

    st.subheader("🛠️ Remediation Recommendations")
    st.write(
        "These are recommendations for a local simulation. "
        "They do not change a real cloud account."
    )

    # OPTION 1: Remove one connection
    st.markdown("### Option 1: Block one connection")

    recommendations, _, _ = recommend_remediations(
        cloud,
        entry_point,
        protected_asset,
        legitimate_paths,
    )

    if recommendations:
        for number, item in enumerate(recommendations, start=1):
            st.write(
                f"**Suggestion {number}:** Remove "
                f"`{item['source']}` → `{item['target']}`"
            )
            st.write(
                f"Attack paths eliminated: "
                f"{item['paths_eliminated']}"
            )
    else:
        st.info(
            "No safe, beneficial single-connection fix was found."
        )

    # OPTION 2: Remove multiple connections
    st.markdown("### Option 2: Block multiple connections")

    try:
        result = find_validated_multi_edge_remediation(
            cloud,
            entry_point,
            protected_asset,
            legitimate_paths=legitimate_paths,
            max_removals=3,
        )

        if result is None:
            st.warning(
                "No safe solution was found within the search limit."
            )
            return

        # The search returns a dictionary, not a tuple.
        removed_connections = result["removed_connections"]
        paths_before = result["paths_before"]
        paths_after = result["paths_after"]
        access_preserved = result["legitimate_access_preserved"]
        removals_count = result["removals_count"]

        if not access_preserved:
            st.error(
                "The proposed changes do not preserve required access."
            )
            return

        st.write(f"Attack paths before: {len(paths_before)}")
        st.write(f"Attack paths after: {len(paths_after)}")
        st.write(f"Connections to remove: {removals_count}")

        if paths_after:
            st.warning(
                "Some attack paths remain after the proposed changes."
            )
        else:
            st.success(
                "All discovered attack paths are blocked in the "
                "simulation, and configured legitimate access "
                "is preserved."
            )

        if removed_connections:
            st.write("**Connections to remove:**")
            for connection in removed_connections:
                st.write(
                    f"- `{connection['source']}` → "
                    f"`{connection['target']}` "
                    f"(Type: {connection['type']})"
                )
        else:
            st.write("No connection removals are needed.")

    except ValueError as error:
        st.error(f"Required access validation failed: {error}")
    except Exception as error:
        st.error(f"Could not display remediation results: {error}")
