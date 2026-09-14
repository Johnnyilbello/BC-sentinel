from __future__ import annotations

"""Fixed B6-5.1 passive Guided Resolution capability provider.

The provider intentionally has no execute/apply/remediate API.  Its only job in
B6-5.1 is to expose a truthful, side-effect-free snapshot of what Home may show
and what remains unavailable until later safety gates are accepted.
"""

from typing import Final

from sentinel import guided_resolution_provider_loader as boundary
from sentinel import home_guided_resolution as guided

PROVIDER_NAME: Final[str] = "BC Sentinel Guided Resolution passive provider"
PROVIDER_PROFILE: Final[str] = "v0.11.0-beta.6-b65.1-passive-provider"
PROVIDER_PROVENANCE: Final[str] = "builtin:guided_resolution_passive_capability_boundary_v1"


class PassiveGuidedResolutionProvider:
    name = PROVIDER_NAME
    profile = PROVIDER_PROFILE
    provenance = PROVIDER_PROVENANCE

    def capabilities(self) -> dict:
        return {
            "schema": boundary.CAPABILITY_SCHEMA,
            "accepted": True,
            "available": True,
            "side_effect_free_probe": True,
            "execution_available": False,
            "automatic_action": False,
            "destructive_authority": False,
            "actions": [
                {
                    "action_id": guided.ACTION_REVIEW_DETAILS,
                    "available": True,
                    "mutates_system": False,
                    "reason": "Passive evidence review is available and does not modify the system.",
                },
                {
                    "action_id": "QUARANTINE",
                    "available": False,
                    "mutates_system": True,
                    "reason": "Unavailable until reversible plan, rollback, confirmation and live acceptance are proven.",
                },
                {
                    "action_id": "REPAIR",
                    "available": False,
                    "mutates_system": True,
                    "reason": "Unavailable until a dedicated live remediation provider is verified.",
                },
                {
                    "action_id": "DELETE",
                    "available": False,
                    "mutates_system": True,
                    "reason": "Destructive action is not authorized in B6-5.1.",
                },
                {
                    "action_id": "TERMINATE_PROCESS",
                    "available": False,
                    "mutates_system": True,
                    "reason": "Process-control authority is not authorized in B6-5.1.",
                },
                {
                    "action_id": "TRUST_OR_ALLOWLIST",
                    "available": False,
                    "mutates_system": True,
                    "reason": "Trust/allowlist mutation is not authorized in B6-5.1.",
                },
            ],
            "future_mutation_safety": {
                "explicit_confirmation_required": True,
                "rollback_required": True,
                "journal_required": True,
                "target_revalidation_required": True,
            },
        }


def create_provider() -> PassiveGuidedResolutionProvider:
    return PassiveGuidedResolutionProvider()
