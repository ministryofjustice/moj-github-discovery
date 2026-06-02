"""Explain and verify how alert_metrics determines repository archive status.

This file contains focused unit tests for build_archive_status_lookup(). The
tests confirm that the helper first uses the bulk organisation repository
listing, then falls back to per-repository lookups only when required.
"""

# Import the helper under test from the alert metrics script.
from scripts.alert_metrics import build_archive_status_lookup

# Import the shared fake HTTP client used throughout the test suite.
from tests.conftest import MockHttpClient


class TestBuildArchiveStatusLookup:
    # This test proves the happy path where the bulk org listing already
    # contains every repository we care about, so no per-repo API calls are
    # needed.
    def test_uses_bulk_org_listing_when_repo_present(self):
        # Build a fake client whose paginated org listing contains both target
        # repositories with their archived flags.
        client = MockHttpClient(
            {
                # This fixture matches the exact path requested by
                # build_archive_status_lookup() for the org-wide repository list.
                "/orgs/myorg/repos?type=all&sort=pushed": [
                    # This repo should be classified as archived.
                    {"full_name": "myorg/archived-repo", "archived": True},
                    # This repo should be classified as non-archived.
                    {"full_name": "myorg/active-repo", "archived": False},
                ]
            }
        )

        # Execute the helper against the two repos we want status for.
        result = build_archive_status_lookup(
            # Pass the mocked client so no real network traffic occurs.
            client,
            # Use a fake organisation name that matches the fixture path.
            "myorg",
            # Request statuses for both repos present in the bulk response.
            ["myorg/archived-repo", "myorg/active-repo"],
        )

        # Confirm the helper converted the GitHub archived booleans into the
        # exported string values expected by the alert metrics output.
        assert result == {
            "myorg/archived-repo": "archived",
            "myorg/active-repo": "non_archived",
        }
        # Confirm only the org-wide paginated call was made.
        assert client.calls == [
            ("GET_PAGINATED", "/orgs/myorg/repos?type=all&sort=pushed")
        ]

    # This test covers the fallback path where one requested repo is missing
    # from the bulk org listing, so the helper must fetch that repo directly.
    def test_falls_back_to_individual_repo_lookup_when_missing_from_bulk_results(self):
        # Build a fake client where the org listing contains only one of the
        # requested repos and the second repo is available via a direct GET.
        client = MockHttpClient(
            {
                # The bulk listing only includes the active repository.
                "/orgs/myorg/repos?type=all&sort=pushed": [
                    {"full_name": "myorg/active-repo", "archived": False}
                ],
                # The missing archived repository is available from the direct
                # repository endpoint used by the fallback logic.
                "/repos/myorg/archived-repo": {
                    "full_name": "myorg/archived-repo",
                    "archived": True,
                },
            }
        )

        # Execute the helper for both repos so the second one must be resolved
        # through the fallback path.
        result = build_archive_status_lookup(
            # Use the fake client with the two staged responses above.
            client,
            # Keep the same fake org so the fixture paths match.
            "myorg",
            # Ask for one repo present in bulk results and one that is missing.
            ["myorg/active-repo", "myorg/archived-repo"],
        )

        # Confirm both repositories end up with the correct exported archive
        # status values, regardless of which fetch path produced them.
        assert result == {
            "myorg/active-repo": "non_archived",
            "myorg/archived-repo": "archived",
        }
        # Confirm the helper first used the bulk listing and then issued one
        # targeted GET for the repo that was not found there.
        assert client.calls == [
            ("GET_PAGINATED", "/orgs/myorg/repos?type=all&sort=pushed"),
            ("GET", "/repos/myorg/archived-repo"),
        ]
