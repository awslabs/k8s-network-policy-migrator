import os
import sys
import yaml
import argparse
import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from validate import validate_network_policy
from utils import validate_np

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def get_policy_files(input_path):
    """Get a list of policy files from the input path."""
    policy_files = []

    if os.path.isfile(input_path):
        policy_files.append(input_path)
    elif os.path.isdir(input_path):
        for file_name in os.listdir(input_path):
            if file_name.endswith(".yaml") or file_name.endswith(".yml"):
                policy_files.append(os.path.join(input_path, file_name))
    else:
        raise ValueError(f"Invalid input path: {input_path}")

    return policy_files


def apply_kubernetes_network_policies(network_policies, namespace, dry_run=False):
    """Applies network policies to a Kubernetes cluster."""
    applied_network_policies = []

    for network_policy_dict in network_policies:
        network_policy_name = network_policy_dict["metadata"]["name"]
        logger.info(f"Validating policy {network_policy_name}")

        if validate_network_policy(network_policy_dict):
            logger.info(f"Applying policy {network_policy_name}")
            if apply_network_policy(network_policy_dict, namespace, dry_run=dry_run):
                applied_network_policies.append(network_policy_dict)
        else:
            logger.warning(f"Skipping invalid policy {network_policy_name}")

    return applied_network_policies


def apply_network_policy(network_policy, namespace, dry_run=False):
    """Applies a network policy to a Kubernetes cluster."""
    # Create a Kubernetes client.
    config.load_kube_config()
    api = client.NetworkingV1Api()

    # Apply the network policy to the cluster.
    try:
        if dry_run:
            api.create_namespaced_network_policy(namespace, network_policy, dry_run='All')
            logger.info("Dry run: Network policy applied successfully")
        else:
            api.create_namespaced_network_policy(namespace, network_policy)
            logger.info("Network policy applied successfully")
    except ApiException as e:
        logger.error("Error applying network policy: %s", e)
        return False

    return True


def store_applied_network_policies(applied_network_policies):
    with open("applied_network_policies.yaml", "w") as outfile:
        yaml.dump_all(iter(applied_network_policies), outfile)


def main():
    parser = argparse.ArgumentParser(description='Apply network policies to a Kubernetes cluster.')
    parser.add_argument('--input', type=str, required=True, help='Path to the input network policy file or directory.')
    parser.add_argument('--namespace', type=str, default="default", help='Kubernetes namespace where the network policies should be applied.')
    parser.add_argument('--dry-run', action='store_true', help='Preview the changes without actually applying them.')
    args = parser.parse_args()

    # Read the policy files and validate them
    k8s_network_policies = []
    try:
        for policy_file in get_policy_files(args.input):
            with open(policy_file) as f:
                network_policy_dict = yaml.safe_load(f)
                if validate_network_policy(network_policy_dict):
                    k8s_network_policies.append(network_policy_dict)
                else:
                    logger.warning(f"Skipping invalid policy {network_policy_dict['metadata']['name']}")
    except Exception as e:
        logger.error("Error reading policy files: %s", e)
        sys.exit(1)

    # Apply the policies to the cluster
    if args.dry_run:
        logger.info("Previewing network policy changes (dry-run)")
        config.load_kube_config()
        api = client.NetworkingV1Api()
        preview_policies = []
        try:
            for network_policy_dict in k8s_network_policies:
                network_policy_name = network_policy_dict["metadata"]["name"]
                logger.info(f"Validating policy {network_policy_name}")
                preview_policy = client.V1NetworkPolicy(
                    api_version="networking.k8s.io/v1",
                    kind="NetworkPolicy",
                    metadata=network_policy_dict["metadata"],
                    spec=network_policy_dict["spec"]
                )
                preview_policies.append(preview_policy)

            preview = api.create_namespaced_network_policy(
                args.namespace, client.V1NetworkPolicyList(items=preview_policies), dry_run="All"
            )

            if preview.status:
                logger.info("Changes preview successful.")
            else:
                logger.info("Changes preview failed.")
        except ApiException as e:
            logger.error("Error previewing network policy changes: %s", e)
            sys.exit(1)

    else:
        logger.info("Applying network policy changes")
        try:
            applied_network_policies = apply_kubernetes_network_policies(k8s_network_policies, args.namespace)
            store_applied_network_policies(applied_network_policies)
            # Validate the Demo App Network policy
            validate_np()
        except Exception as e:
            logger.error("Error applying network policies: %s", e)
            sys.exit(1)

        logger.info("Network policy changes applied successfully")

if __name__ == "__main__":
    # Call the main function
    main()