# Import the required modules
import kubernetes
from kubernetes import config
import yaml
import argparse
import os
import logging

# Configure logging to output messages with a specific format and level
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define a function to roll back a single network policy
def roll_back_network_policy(network_policy, namespace, dry_run=False):
    """
    Rolls back a network policy in a Kubernetes cluster.

    Args:
    - network_policy (dict): The network policy to roll back.
    - namespace (str): The Kubernetes namespace where the policy exists.
    - dry_run (bool): Whether to perform a dry run.
    """
    # Load Kubernetes config and create a client instance
    config.load_kube_config()
    client = kubernetes.client.NetworkingV1Api()

    # Extract the name of the network policy from its metadata
    network_policy_name = network_policy["metadata"]["name"]

    # Attempt to delete the network policy
    try:
        if dry_run:
            # If dry run, log what would be done without making actual changes
            logger.info(f"Dry run: Network policy '{network_policy_name}' would be rolled back in namespace '{namespace}'")
        else:
            # Actually delete the network policy
            client.delete_namespaced_network_policy(network_policy_name, namespace)
            logger.info(f"Network policy '{network_policy_name}' rolled back successfully in namespace '{namespace}'")
    except kubernetes.client.rest.ApiException as e:
        # Log any errors encountered during the deletion
        logger.error(f"Error rolling back network policy '{network_policy_name}' in namespace '{namespace}': {e}")
        return False

    return True

# Define a function to load network policies from a YAML file
def load_applied_network_policies(file_path):
    """Load the list of applied network policies from a file."""
    with open(file_path, "r") as infile:
        return list(yaml.safe_load_all(infile))

# Define the main function
def main():
    """Main function that parses arguments and orchestrates the rollback."""
    # Create an argument parser and define the command-line arguments
    parser = argparse.ArgumentParser(description='Roll back applied network policies in a Kubernetes cluster.')
    parser.add_argument('--namespace', type=str, default="default", help='Kubernetes namespace where the network policies should be rolled back.')
    parser.add_argument('--applied-network-policies-file', type=str, default="applied_network_policies.yaml", help='Path to the file with applied network policies.')
    parser.add_argument('--dry-run', action='store_true', help='Preview the changes without actually applying them.')
    args = parser.parse_args()

    # Check if the file containing applied network policies exists
    if not os.path.isfile(args.applied_network_policies_file):
        logger.error(f"Cannot find the applied network policies file '{args.applied_network_policies_file}'. Please check the file path.")
        return

    # Load the applied network policies from the file
    applied_network_policies = load_applied_network_policies(args.applied_network_policies_file)
    
    # If no applied network policies are found, exit the script
    if not applied_network_policies:
        logger.info("No applied network policies found to roll back.")
        return

    # Log the number of network policies to be rolled back and proceed to roll them back
    logger.info(f"Rolling back {len(applied_network_policies)} applied network policies in namespace '{args.namespace}'...")
    for network_policy in applied_network_policies:
        roll_back_network_policy(network_policy, args.namespace, args.dry_run)

# Entry point for the script
if __name__ == '__main__':
    main()
