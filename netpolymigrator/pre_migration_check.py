# This script performs a set of prerequisites needed before you migrate your network policies
# It detects which type of custom network policy you're using (Calico or Cilium)
# Installs a demo application and its corresponding network policies, and then validates that everything is working as expected
# Cleans up created objects

# Import necessary modules
import logging
from utils import detect_custom_network_policy_type, validate_np
import subprocess

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define namespace and demo app endpoint for validation
namespace = "npmigrator-test"
endpoint_demoapp = "demo-svc.npmigrator-test.svc.cluster.local"

def cleanup():
    """
    Function to clean up created objects.
    """
    try:
        # Deleting demo app
        subprocess.check_call(["kubectl", "delete", "-f", "../netpolymigrator/example-apps/demo-app.yaml"])
        
        # Deleting calico network policy if it exists
        try:
            subprocess.check_call(["kubectl", "get", "networkpolicies.projectcalico.org", "demo-app-ingress-rule"])
            subprocess.check_call(["kubectl", "delete", "-f", "../netpolymigrator/example-apps/calico-np.yaml"])
        except subprocess.CalledProcessError:
            logger.warning("Calico network policy not found. Skipping deletion.")
        
        # Deleting cilium network policy if it exists
        try:
            subprocess.check_call(["kubectl", "get", "networkpolicies.cilium.io", "demo-app-ingress-rule"])
            subprocess.check_call(["kubectl", "delete", "-f", "../netpolymigrator/example-apps/cilium-np.yaml"])
        except subprocess.CalledProcessError:
            logger.warning("Cilium network policy not found. Skipping deletion.")
        
        logger.info("Cleanup successful.")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Cleanup failed: {e}")

def pre_migration_check():
    """
    Function to perform pre-migration checks.
    """

    try:
        # Step 1: Detect the custom network policy type (Calico or Cilium)
        custom_network_policy_type = detect_custom_network_policy_type()

        # Step 2: Install the Demo App
        logger.info("Installing Demo App")
        subprocess.check_output(["kubectl", "apply", "-f", "../netpolymigrator/example-apps/demo-app.yaml"])
        logger.info("Installed Demo App successfully")

        # Step 3: Install the NetworkPolicy
        if custom_network_policy_type == "calico":
            subprocess.check_output(["kubectl", "apply", "-f", "../netpolymigrator/example-apps/calico-np.yaml"])
            logger.info("Installed Calico network policy")
        elif custom_network_policy_type == "cilium":
            subprocess.check_output(["kubectl", "apply", "-f", "../netpolymigrator/example-apps/cilium-np.yaml"])
            logger.info("Installed Cilium network policy")
        else:
            logger.error("No supported custom NetworkPolicy CRD found.")
            return

        # Step 4: Validate Network Policies
        if validate_np(namespace, endpoint_demoapp):
            logger.info("All network policies validated successfully.")
        else:
            logger.error("NetworkPolicy test failed")
            raise Exception("Network Policy Validation failed!!")

    except Exception as e:
        logger.error(f"An error occurred: {e}")
    
    finally:
        # Step 5: Cleanup
        cleanup()

if __name__ == "__main__":
    # Call the pre_migration_check function
    pre_migration_check()
