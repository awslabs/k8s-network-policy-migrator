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

def cleanup_cilium():
    try:
        subprocess.check_output(["kubectl", "delete", "-f", "../netpolymigrator/example-apps/demo-app.yaml"])
        subprocess.check_output(["kubectl", "delete", "-f", "../netpolymigrator/example-apps/cilium-np.yaml"])
        subprocess.check_output(["kubectl", "delete", "daemonset", "cilium", "-n", "kube-system"])
        logging.info("Cilium DaemonSet removed successfully")

        subprocess.check_output(["helm", "delete", "cilium", "-n", "kube-system"])
        logging.info("Uninstalled cilium using helm")

        delete_crd_by_keyword("cilium")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error during cleanup: {e}")

def main():
    try:
        cleanup_cilium()
    except KeyboardInterrupt:
        logging.info("Cleanup interrupted by user. Exiting...")
        return

if __name__ == "__main__":
    main()
