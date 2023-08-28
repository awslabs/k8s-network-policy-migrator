# Import necessary modules
import subprocess
import time
import logging

# Initialize logging to write logs to 'cleanup.log' file with INFO level
logging.basicConfig(filename='cleanup.log', level=logging.INFO)

# Define function to delete Custom Resource Definitions (CRDs) based on a keyword
def delete_crd_by_keyword(keyword):
    try:
        # Retrieve the list of CRDs in the Kubernetes cluster
        crds = subprocess.check_output(["kubectl", "get", "crd", "-A", "-o", "name"]).decode("utf-8").split("\n")
        
        # Filter CRDs that contain the specified keyword
        keyword_crds = [crd for crd in crds if keyword.lower() in crd.lower()]

        # If no CRDs match the keyword, log this information
        if not keyword_crds:
            logging.info(f"No CRDs found with the keyword '{keyword}'")
            return

        # Loop through each CRD to delete it
        for crd in keyword_crds:
            # Retry up to 3 times in case of failure
            for _ in range(3):
                try:
                    # Delete the CRD
                    subprocess.check_output(["kubectl", "delete", crd])
                    logging.info(f"CRD {crd} removed successfully")
                    break  # Exit the retry loop if deletion is successful
                except subprocess.CalledProcessError as e:
                    # Log any errors that occur
                    logging.error(f"Error deleting CRD {crd}: {e}")
                    time.sleep(5)  # Wait 5 seconds before retrying

    except subprocess.CalledProcessError as e:
        logging.error(f"Error retrieving CRDs: {e}")

# Define function to cleanup Calico resources
def cleanup_calico():
    try:
        # Delete Calico installation
        subprocess.check_output(["kubectl", "delete", "installation.operator.tigera.io", "default"])
        logging.info("Deleted installation.operator.tigera.io default")

        # Wait for all resources in each namespace to be deleted
        for namespace in ["calico-apiserver", "calico-system", "tigera-operator"]:
            subprocess.check_output(["kubectl", "delete", "--all", "-n", namespace, "pod,svc,deploy"])
            while True:
                resources = subprocess.check_output(["kubectl", "get", "all", "-n", namespace]).decode("utf-8")
                if "No resources found" in resources:
                    break
                logging.info(f"Waiting for resources in {namespace} to be deleted...")
                time.sleep(5)  # Wait 5 seconds before re-checking

        # Delete CRDs related to Calico and Tigera
        delete_crd_by_keyword("projectcalico")
        delete_crd_by_keyword("tigera")

        # Delete namespaces
        for namespace in ["calico-apiserver", "calico-system", "tigera-operator"]:
            subprocess.check_output(["kubectl", "delete", "namespace", namespace])
            logging.info(f"Deleted namespace {namespace}")

        # Delete demo application and Calico network policy
        subprocess.check_output(["kubectl", "delete", "-f", "../netpolymigrator/example-apps/demo-app.yaml"])
        subprocess.check_output(["kubectl", "delete", "-f", "../netpolymigrator/example-apps/calico-np.yaml"])
        logging.info("Deleted demo-app.yaml and calico-np.yaml deployments")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error during cleanup: {e}")

# Main function to initiate cleanup
def main():
    try:
        cleanup_calico()
    except KeyboardInterrupt:
        logging.info("Cleanup interrupted by user. Exiting...")

# Entry point of the script
if __name__ == "__main__":
    main()
