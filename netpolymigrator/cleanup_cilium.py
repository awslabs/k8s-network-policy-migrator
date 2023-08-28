import subprocess  # Import the subprocess module for executing shell commands
import time  # Import the time module for time-related functions
import logging  # Import the logging module for logging

# Configure logging settings
logging.basicConfig(filename='cleanup.log', level=logging.INFO)

# Function to delete CRDs based on a keyword
def delete_crd_by_keyword(keyword):
    try:
        # Get all CustomResourceDefinitions (CRDs) and decode the output
        crds = subprocess.check_output(["kubectl", "get", "crd", "-A", "-o", "name"]).decode("utf-8").split("\n")
        # Filter CRDs containing the keyword
        keyword_crds = [crd for crd in crds if keyword.lower() in crd.lower()]

        # Check if any CRDs with the keyword were found
        if not keyword_crds:
            logging.info(f"No CRDs found with the keyword '{keyword}'")
            return

        # Loop through each CRD and attempt to delete it
        for crd in keyword_crds:
            # Retry the delete operation up to 3 times if it fails
            for _ in range(3):
                try:
                    subprocess.check_output(["kubectl", "delete", crd])
                    logging.info(f"CRD {crd} removed successfully")
                    break  # Exit the loop if successful
                except subprocess.CalledProcessError as e:
                    logging.error(f"Error deleting CRD {crd}: {e}")
                    time.sleep(5)  # Wait for 5 seconds before retrying
    except subprocess.CalledProcessError as e:
        logging.error(f"Error retrieving CRDs: {e}")

# Function to clean up Cilium
def cleanup_cilium():
    try:
        # Delete the demo application and Cilium network policies
        subprocess.check_output(["kubectl", "delete", "-f", "../netpolymigrator/example-apps/demo-app.yaml"])
        subprocess.check_output(["kubectl", "delete", "-f", "../netpolymigrator/example-apps/cilium-np.yaml"])
        
        # Delete the Cilium DaemonSet
        subprocess.check_output(["kubectl", "delete", "daemonset", "cilium", "-n", "kube-system"])
        logging.info("Cilium DaemonSet removed successfully")
        
        # Uninstall Cilium using Helm
        subprocess.check_output(["helm", "delete", "cilium", "-n", "kube-system"])
        logging.info("Uninstalled cilium using helm")

        # Delete CRDs related to Cilium
        delete_crd_by_keyword("cilium")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error during cleanup: {e}")

# Main function
def main():
    try:
        cleanup_cilium()  # Call the cleanup_cilium function
    except KeyboardInterrupt:
        logging.info("Cleanup interrupted by user. Exiting...")

# Entry point for the script
if __name__ == "__main__":
    main()
