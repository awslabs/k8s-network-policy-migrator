import kubernetes
from kubernetes import config
import yaml
import argparse
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def roll_back_network_policy(network_policy, namespace, dry_run=False):
    """Rolls back a network policy in a Kubernetes cluster."""
    # Create a Kubernetes client.
    config.load_kube_config()
    client = kubernetes.client.NetworkingV1Api()

    network_policy_name = network_policy["metadata"]["name"]

    # Delete the network policy object.
    try:
        if dry_run:
            logger.info(f"Dry run: Network policy '{network_policy_name}' would be rolled back in namespace '{namespace}'")
        else:
            client.delete_namespaced_network_policy(network_policy_name, namespace)
            logger.info(f"Network policy '{network_policy_name}' rolled back successfully in namespace '{namespace}'")
    except kubernetes.client.rest.ApiException as e:
        logger.error(f"Error rolling back network policy '{network_policy_name}' in namespace '{namespace}': {e}")
        return False

    return True

def load_applied_network_policies(file_path):
    with open(file_path, "r") as infile:
        return list(yaml.safe_load_all(infile))

def main():
    parser = argparse.ArgumentParser(description='Roll back applied network policies in a Kubernetes cluster.')
    parser.add_argument('--namespace', type=str, default="default", help='Kubernetes namespace where the network policies should be rolled back.')
    parser.add_argument('--applied-network-policies-file', type=str, default="applied_network_policies.yaml", help='Path to the file with applied network policies.')
    parser.add_argument('--dry-run', action='store_true', help='Preview the changes without actually applying them.')
    args = parser.parse_args()

    if not os.path.isfile(args.applied_network_policies_file):
        logger.error(f"Cannot find the applied network policies file '{args.applied_network_policies_file}'. Please check the file path.")
        return

    applied_network_policies = load_applied_network_policies(args.applied_network_policies_file)
    
    if not applied_network_policies:
        logger.info("No applied network policies found to roll back.")
        return

    logger.info(f"Rolling back {len(applied_network_policies)} applied network policies in namespace '{args.namespace}'...")
    for network_policy in applied_network_policies:
        roll_back_network_policy(network_policy, args.namespace, args.dry_run)

if __name__ == '__main__':
    main()