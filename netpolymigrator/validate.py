import logging

logger = logging.getLogger(__name__)

def validate_network_policy(network_policy):
    """Validates a network policy."""
    if not network_policy or not isinstance(network_policy, dict):
        logger.warning("Invalid network policy: must be a non-empty dict")
        return False

    # Check that the network policy has required fields
    required_fields = ["apiVersion", "kind", "metadata", "spec"]
    for field in required_fields:
        if field not in network_policy:
            logger.warning(f"Invalid network policy: missing required field '{field}'")
            return False

    # Check that the apiVersion is supported
    supported_versions = ["networking.k8s.io/v1", "networking.k8s.io/v1beta1"]
    if network_policy["apiVersion"] not in supported_versions:
        logger.warning(f"Invalid network policy: unsupported apiVersion '{network_policy['apiVersion']}'")
        return False

    # Check that the kind is NetworkPolicy
    if network_policy["kind"] != "NetworkPolicy":
        logger.warning(f"Invalid network policy: unsupported kind '{network_policy['kind']}'")
        return False

    # Check that the metadata has a name field
    if "name" not in network_policy["metadata"]:
        logger.warning("Invalid network policy: metadata missing 'name' field")
        return False

    # Check that the spec field is not empty
    if not network_policy.get("spec"):
        logger.warning("Invalid network policy: spec field must be non-empty")
        return False

    # Check that the policy types field is not empty
    if not network_policy["spec"].get("policyTypes"):
        logger.warning("Invalid network policy: policyTypes field must be non-empty")
        return False

    # Check that the podSelector.matchLabels field meets the naming requirements
    for egress_rule in network_policy["spec"].get("egress", []):
        for to_rule in egress_rule.get("to", []):
            if "podSelector" in to_rule and "matchLabels" in to_rule["podSelector"]:
                for label_key in to_rule["podSelector"]["matchLabels"]:
                    if not label_key.isalnum() and "-" not in label_key and "_" not in label_key and "." not in label_key:
                        logger.warning(f"Invalid network policy: podSelector.matchLabels field has invalid label key '{label_key}'")
                        return False

    return True