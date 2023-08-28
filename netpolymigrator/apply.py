# Import necessary modules
import os
import sys
import yaml
import argparse
import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from validate import validate_network_policy
from utils import validate_np

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_namespace_if_not_exists(api, namespace):
    """Create a namespace if it doesn't exist."""
    try:
        api.read_namespace(name=namespace)
        logger.info(f"Namespace {namespace} already exists.")
    except ApiException as e:
        if e.status == 404:
            api.create_namespace(client.V1Namespace(
                api_version="v1",
                kind="Namespace",
                metadata=client.V1ObjectMeta(name=namespace)
            ))
            logger.info(f"Created namespace {namespace}")

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
        network_policy_name = network_policy_dict['metadata']['name']
        logger.info(f"Validating policy {network_policy_name}")

        if validate_network_policy(network_policy_dict):
            logger.info(f"Applying policy {network_policy_name}")
            if apply_network_policy(network_policy_dict, namespace, dry_run):
                applied_network_policies.append(network_policy_dict)
        else:
            logger.warning(f"Skipping invalid policy {network_policy_name}")
    return applied_network_policies

def apply_network_policy(network_policy, namespace, dry_run=False):
    """Applies a network policy to a Kubernetes cluster."""
    config.load_kube_config()
    api = client.NetworkingV1Api()

    # Explicitly set the namespace in the network policy object to match the namespace in the API call
    network_policy['metadata']['namespace'] = namespace

    try:
        if dry_run:
            api.create_namespaced_network_policy(namespace, network_policy, dry_run='All')
            logger.info(f"Dry run: Network policy '{network_policy['metadata']['name']}' would be applied.")
        else:
            api.create_namespaced_network_policy(namespace, network_policy)
            logger.info(f"Network policy '{network_policy['metadata']['name']}' applied successfully.")
    except ApiException as e:
        logger.error(f"Error applying network policy '{network_policy['metadata']['name']}': {e}")
        return False
    return True

def save_applied_policies_to_file(applied_policies, file_path):
    """Save applied network policies to a file."""
    with open(file_path, 'w') as f:
        yaml.dump_all(applied_policies, f)
    logger.info(f"Saved applied network policies to {file_path}")

def main():
    parser = argparse.ArgumentParser(description='Apply network policies to a Kubernetes cluster.')
    parser.add_argument('--input', type=str, required=True, help='Path to the input network policy file or directory.')
    parser.add_argument('--namespace', type=str, default='default', help='Kubernetes namespace where the network policies will be applied.')
    parser.add_argument('--dry-run', action='store_true', help='Preview the changes without actually applying them.')
    args = parser.parse_args()

    # Initialize Kubernetes API client
    config.load_kube_config()
    api = client.NetworkingV1Api()
    core_api = client.CoreV1Api()

    # Create namespace if it doesn't exist
    create_namespace_if_not_exists(core_api, args.namespace)

    # Read and validate policy files
    k8s_network_policies = []
    for policy_file in get_policy_files(args.input):
        with open(policy_file, 'r') as f:
            network_policy_dict = yaml.safe_load(f)
            if validate_network_policy(network_policy_dict):
                k8s_network_policies.append(network_policy_dict)
            else:
                logger.warning(f"Skipping invalid policy {network_policy_dict['metadata']['name']}")

    # Apply the network policies
    applied_policies = apply_kubernetes_network_policies(k8s_network_policies, args.namespace, args.dry_run)

    # Save applied policies to a file for future rollback
    save_applied_policies_to_file(applied_policies, 'applied_network_policies.yaml')

if __name__ == "__main__":
    main()
