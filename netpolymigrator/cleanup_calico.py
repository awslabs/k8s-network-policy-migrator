import subprocess
import time
import logging

# Set up logging
logging.basicConfig(filename='cleanup.log', level=logging.INFO)

def delete_crd_by_keyword(keyword):
    try:
        crds = subprocess.check_output(["kubectl", "get", "crd", "-A", "-o", "name"]).decode("utf-8").split("\n")
        keyword_crds = [crd for crd in crds if keyword.lower() in crd.lower()]

        if not keyword_crds:
            logging.info(f"No CRDs found with the keyword '{keyword}'")
            return

        for crd in keyword_crds:
            for _ in range(3):  # Retry up to 3 times
                try:
                    subprocess.check_output(["kubectl", "delete", crd])
                    logging.info(f"CRD {crd} removed successfully")
                    break
                except subprocess.CalledProcessError as e:
                    logging.error(f"Error deleting CRD {crd}: {e}")
                    time.sleep(5)  # Wait for 5 seconds before retrying

    except subprocess.CalledProcessError as e:
        logging.error(f"Error retrieving CRDs: {e}")

def cleanup_calico():
    try:
        subprocess.check_output(["kubectl", "delete", "installation.operator.tigera.io", "default"])
        logging.info("Deleted installation.operator.tigera.io default")

        # Wait until all resources in the calico-system namespace are deleted
        while True:
            resources = subprocess.check_output(["kubectl", "get", "all", "-n", "calico-system"]).decode("utf-8")
            if "No resources found" in resources:
                break
            logging.info("Waiting for resources in calico-system to be deleted...")
            time.sleep(5)

        subprocess.check_output(["helm", "delete", "calico"])
        logging.info("Uninstalled calico using helm")

        for namespace in ["calico-system", "calico-apiserver", "tigera-operator"]:
            subprocess.check_output(["kubectl", "delete", "namespace", namespace])
            logging.info(f"Deleted namespace {namespace}")

        delete_crd_by_keyword("projectcalico")
        delete_crd_by_keyword("tigera")

        subprocess.check_output(["kubectl", "delete", "-f", "../netpolymigrator/example-apps/demo-app.yaml"])
        subprocess.check_output(["kubectl", "delete", "-f", "../netpolymigrator/example-apps/calico-np.yaml"])
        logging.info("Deleted demo-app.yaml and calico-np.yaml deployments")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error during cleanup: {e}")

def main():
    try:
        cleanup_calico()
    except KeyboardInterrupt:
        logging.info("Cleanup interrupted by user. Exiting...")
        return

if __name__ == "__main__":
    main()
