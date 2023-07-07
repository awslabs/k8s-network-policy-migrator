import logging
from utils import detect_custom_network_policy_type, validate_np
import subprocess

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
namespace = "npmigrator-test"
endpoint_cilium = "deathstar.npmigrator-test.svc.cluster.local/v1/"

def prereq():
    # Detect the custom network policy type (Calico or Cilium)
    custom_network_policy_type = detect_custom_network_policy_type()
    try:
        # Install the Demo App
        logger.info("Install Demo App")
        # Run the kubectl apply command.
        subprocess.check_output(["kubectl", "apply", "-f", "../netpolymigrator/example-apps/demo-app.yaml"])
        logger.info("Installed Demo App successfully")

        # Install the NetworkPolicy
        if "calico" == custom_network_policy_type:
            subprocess.check_output(["kubectl", "apply", "-f", "../netpolymigrator/example-apps/calico-np.yaml"])
            logger.info("Installed calico network policy")
        elif "cilium" == custom_network_policy_type:
            subprocess.check_output(["kubectl", "apply", "-f", "../netpolymigrator/example-apps/cilium-np.yaml"])
            logger.info("Installed cilium network policy")
        else:
            logger.error("No supported custom NetworkPolicy CRD found.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error in setting up Demo App: {e}")

    # Validate connectivity
    validate_np()
    logger.info("prereq completed successfully")

if __name__ == "__main__":
    # Call the prereq function
    prereq()
