import os
import yaml
import argparse
import logging
import tempfile
from utils import detect_custom_network_policy_type, collect_network_policies

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def collect(args):
    # Detect the custom network policy type (Calico or Cilium)
    custom_network_policy_type = detect_custom_network_policy_type()

    # If no custom network policy type is found, exit the script
    if custom_network_policy_type not in ("calico", "cilium"):
        logger.error("No supported custom NetworkPolicy CRD found.")
        return

    # Collect custom network policies
    network_policies = collect_network_policies(custom_network_policy_type=custom_network_policy_type)

    # Create the output folder if it does not exist
    output_folder = os.path.join(args.output, custom_network_policy_type)
    os.makedirs(output_folder, exist_ok=True)

    # Save each custom network policy to a separate file in the specified output folder
    for policy in network_policies:
        policy_name = policy["metadata"]["name"]
        if "namespace" in policy["metadata"]:
            policy_namespace = policy["metadata"]["namespace"]
            output_file = os.path.join(output_folder, f"{policy_namespace}_{policy_name}.yaml")
        else:
            subfolder = "global_policies" if custom_network_policy_type == "calico" else "clusterwide_policies"
            os.makedirs(os.path.join(output_folder, subfolder), exist_ok=True)
            output_file = os.path.join(output_folder, subfolder, f"{custom_network_policy_type}_clusterwide_{policy_name}.yaml")

        if args.dry_run:
            logger.info(f'Dry run: Would write policy to {output_file}')
        else:
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                yaml.safe_dump(policy, temp_file)

            os.chmod(temp_file.name, 0o400)
            os.rename(temp_file.name, output_file)

    # Log the number of collected network policies and the output folder path
    logger.info(f"Collected {len(network_policies)} {custom_network_policy_type} NetworkPolicies and saved to '{output_folder}' folder.")

def main():
    # Create the command-line argument parser
    parser = argparse.ArgumentParser(description="NetPolyMigrator")

    # Create subparsers for each command
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Create the parser for the collect command
    collect_parser = subparsers.add_parser("collect", help="Collect custom network policies")
    collect_parser.add_argument("--output", type=str, default="collected_network_policies", help="Output folder for the collected custom NetworkPolicies.")
    collect_parser.add_argument("--dry-run", action='store_true', help='Perform a dry run without making any changes')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Execute the appropriate command based on the subcommand
    if args.command == "collect":
        try:
            collect(args)
        except Exception as e:
            logger.error("Error during collect command execution: %s", e)
    else:
        logger.error(f"Invalid command: {args.command}")

if __name__ == "__main__":
    # Call the main function
    main()