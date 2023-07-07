import os
import sys
import yaml
import argparse
import logging
from kubernetes import client, config
from utils import (detect_custom_network_policy_type, run_tests)
from validate import validate_network_policy
from calico_utils import convert_calico_network_policy
from cilium_utils import convert_cilium_network_policy

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def validate_k8s_policy(k8s_policy):
    """
    Validate a Kubernetes native NetworkPolicy using the Kubernetes API.
    """
    try:
        config.load_kube_config()
        api_instance = client.NetworkingV1Api()
        namespace = k8s_policy["metadata"]["namespace"]

        api_response = api_instance.create_namespaced_network_policy(namespace, k8s_policy, dry_run='All')
        logger.info(f"Validation passed for the policy: {k8s_policy['metadata']['name']}")
        return True
    except Exception as e:
        logger.error(f"Validation error: {e}")
        return False

def convert(args):
    """
    Convert custom network policies to Kubernetes native network policies.
    """
    # Ensure that the input folder exists
    if not os.path.isdir(args.input):
        logger.error(f"Input folder '{args.input}' does not exist.")
        sys.exit(1)

    # Create the output folder if it does not exist
    os.makedirs(args.output, exist_ok=True)

    # Initialize the counter for the number of converted policies
    num_converted_policies = 0

    # Initialize the list to store validation errors
    validation_errors = []

    # Loop over each custom network policy folder in the input folder
    custom_network_policy_folders = [folder for folder in os.listdir(args.input) if os.path.isdir(os.path.join(args.input, folder))]
    for folder in custom_network_policy_folders:
        policy_type_folder = os.path.join(args.input, folder)

        # Loop over each policy file in the current custom network policy folder
        for policy_file in os.listdir(policy_type_folder):
            policy_file_path = os.path.join(policy_type_folder, policy_file)

            # Skip if the current file is not a regular file
            if not os.path.isfile(policy_file_path):
                continue

            # Load the policy from the YAML file
            with open(policy_file_path, "r") as f:
                policy = yaml.safe_load(f)

            try:
                # Determine the custom network policy type
                custom_network_policy_type = detect_custom_network_policy_type()

                # Convert the policy to a Kubernetes native NetworkPolicy
                if custom_network_policy_type == "calico":
                    k8s_policies = [convert_calico_network_policy(policy)]
                    output_policy_type_folder = os.path.join(args.output, "calico_converted")
                elif custom_network_policy_type == "cilium":
                    k8s_policies = convert_cilium_network_policy(policy)
                    output_policy_type_folder = os.path.join(args.output, "cilium_converted")
                else:
                    continue

                # Create the output folder for the current custom network policy type if it does not exist
                os.makedirs(output_policy_type_folder, exist_ok=True)

                for k8s_policy in k8s_policies:
                    # Validate the converted policy
                    if not validate_network_policy(k8s_policy):
                        validation_errors.append(f"Validation failed for the policy: {policy['metadata']['name']}")
                    else:
                        if not args.dry_run:
                        # Save the converted policy to a YAML file
                        output_file = os.path.join(output_policy_type_folder, f"{policy['metadata']['name']}_k8s.yaml")
                        with open(output_file, "w") as f:
                            yaml.safe_dump(k8s_policy, f)
            
                    # Increment the counter for the number of converted policies
                    num_converted_policies += 1

                    # Log that the policy was successfully converted
                    logger.info(f"Converted policy '{policy['metadata']['name']}' to Kubernetes native NetworkPolicy.")

                    # Validate the converted policy using the Kubernetes API
                    if not validate_k8s_policy(k8s_policy):
                        validation_errors.append(f"Validation failed for the policy using Kubernetes API: {policy['metadata']['name']}")
                    else:
                        logger.info(f"Validation passed for the policy using Kubernetes API: {policy['metadata']['name']}")

            except Exception as e:
                logger.error(f"Failed to convert policy: {policy_file_path}. Error: {e}")
                continue

        # Log the number of converted policies
        logger.info(f"Converted {num_converted_policies} custom NetworkPolicies to Kubernetes native NetworkPolicies and saved them in '{args.output}' folder.")

        # Log any validation errors
        if validation_errors:
            logger.error("\n".join(validation_errors))

def main():
    # Set up the argument parser
    parser = argparse.ArgumentParser(description="NetPolyMigrator")
    subparsers = parser.add_subparsers(dest="command", required=True)
    convert_parser = subparsers.add_parser("convert", help="Convert custom network policies to Kubernetes native network policies")
    convert_parser.add_argument("--input", type=str, required=True, help="Path to the folder containing the collected custom NetworkPolicies.")
    convert_parser.add_argument("--output", type=str, default="converted_network_policies", help="Path to the folder where the converted Kubernetes native NetworkPolicies will be saved.")
    convert_parser.add_argument("--dry-run", action='store_true', help="Enable dry run mode")
    
    # Parse the arguments
    args = parser.parse_args()

    # Call the appropriate function based on the subcommand
    if args.command == "convert":
        convert(args)
    else:
        logger.error(f"Invalid command: {args.command}")
           
if __name__ == "__main__":
    # Call the main function
    main()