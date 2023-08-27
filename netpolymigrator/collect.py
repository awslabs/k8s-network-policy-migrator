# Import necessary modules
import os
import yaml
import argparse
import logging
import tempfile
from utils import detect_custom_network_policy_type, collect_network_policies

# Configure logging settings
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Function to save a network policy to a file in YAML format
def save_policy(policy, output_file):
    """Save a network policy to a file in YAML format."""
    try:
        # Use a temporary file to initially save the policy
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            yaml.safe_dump(policy, temp_file)
        
        # Change file permissions to read-only
        os.chmod(temp_file.name, 0o400)
        
        # Rename the temporary file to the final output file
        os.rename(temp_file.name, output_file)
        
    except Exception as e:
        # Log any errors that occur during the saving process
        logger.error(f"An error occurred while saving the policy: {e}")

# Function to collect existing network policies
def collect(args):
    """Collect existing network policies and save them to an output directory."""
    try:
        # Detect the type of custom network policy (either Calico or Cilium)
        custom_network_policy_type = detect_custom_network_policy_type()
        
        # Check if a supported custom network policy type is found
        if custom_network_policy_type not in ("calico", "cilium"):
            logger.error("No supported custom NetworkPolicy CRD found.")
            return

        # Log the start of the collection process
        logger.info("Collecting network policies...")
        
        # Collect the custom network policies
        network_policies = collect_network_policies(custom_network_policy_type=custom_network_policy_type)
        
        # Check if any network policies were found
        if not network_policies:
            logger.info("No network policies found.")
            return

        # Create the output directory for saving collected policies
        output_folder = os.path.join(args.output, custom_network_policy_type)
        os.makedirs(output_folder, exist_ok=True)

        # Iterate over each collected policy to save it
        for policy in network_policies:
            policy_name = policy["metadata"]["name"]
            
            # Determine the namespace of the policy, if it exists
            if "namespace" in policy["metadata"]:
                policy_namespace = policy["metadata"]["namespace"]
                output_file = os.path.join(output_folder, f"{policy_namespace}_{policy_name}.yaml")
            else:
                # For global or cluster-wide policies
                subfolder = "global_policies" if custom_network_policy_type == "calico" else "clusterwide_policies"
                os.makedirs(os.path.join(output_folder, subfolder), exist_ok=True)
                output_file = os.path.join(output_folder, subfolder, f"{custom_network_policy_type}_clusterwide_{policy_name}.yaml")
            
            # If it's a dry run, just log the output file name
            if args.dry_run:
                logger.info(f'Dry run: Would write policy to {output_file}')
            else:
                # Actually save the policy to the output file
                save_policy(policy, output_file)
        
        # Log a summary of the collection process
        logger.info(f"Collected {len(network_policies)} {custom_network_policy_type} NetworkPolicies and saved to '{output_folder}' folder.")
    
    except Exception as e:
        # Log any errors that occur during the collection process
        logger.error(f"An error occurred during the collection process: {e}")

# Entry point of the script
def main():
    # Configure the argument parser
    parser = argparse.ArgumentParser(description="NetPolyMigrator")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Arguments for the "collect" command
    collect_parser = subparsers.add_parser("collect", help="Collect custom network policies")
    collect_parser.add_argument("--output", type=str, default="collected_network_policies", help="Output folder for the collected custom NetworkPolicies.")
    collect_parser.add_argument("--dry-run", action='store_true', help='Perform a dry run without making any changes')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Perform the appropriate action based on the command
    if args.command == "collect":
        collect(args)
    else:
        logger.error(f"Invalid command: {args.command}")

# Run the script
if __name__ == "__main__":
    main()