import argparse
import logging
import os
import subprocess
import sys
import yaml
from kubernetes import client, config

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")
logger = logging.getLogger(__name__)
namespace = "npmigrator-test"
endpoint_demoapp = "demo-svc.npmigrator-test.svc.cluster.local"

def parse_args():
    parser = argparse.ArgumentParser(description="Network policy converter and tester.")
    parser.add_argument("-o", "--output", type=str, help="Output folder to store converted network policies.", default="output")
    parser.add_argument("-v", "--verbosity", type=int, help="Logging verbosity level. Higher values for more verbose logging.", default=1)
    return parser.parse_args()


def set_logging_level(verbosity):
    if verbosity >= 3:
        logger.setLevel(logging.DEBUG)
    elif verbosity == 2:
        logger.setLevel(logging.INFO)
    elif verbosity == 1:
        logger.setLevel(logging.WARNING)
    else:
        logger.setLevel(logging.ERROR)


def detect_custom_network_policy_type():
    try:
        # Load Kubernetes configuration
        config.load_kube_config()

        # Initialize API client
        api_client = client.ApiClient()

        # Get CRDs
        crd_api = client.CustomObjectsApi(api_client)
        crd_list = crd_api.list_cluster_custom_object("apiextensions.k8s.io", "v1", "customresourcedefinitions")

        # Check for Calico and Cilium CRDs
        calico_global_crd = "globalnetworkpolicies.crd.projectcalico.org"
        calico_crd = "networkpolicies.crd.projectcalico.org"
        cilium_crd = "ciliumnetworkpolicies.cilium.io"
        cilium_clusterwide_crd = "ciliumclusterwidenetworkpolicies.cilium.io"

        # Initialize custom_network_policy_type
        custom_network_policy_type = None

        # Iterate over CRDs to find the custom network policy type
        for crd in crd_list["items"]:
            if crd["metadata"]["name"] == calico_global_crd or crd["metadata"]["name"] == calico_crd:
                custom_network_policy_type = "calico"
                break
            elif crd["metadata"]["name"] == cilium_crd or crd["metadata"]["name"] == cilium_clusterwide_crd:
                custom_network_policy_type = "cilium"
                break

        if custom_network_policy_type is None:
            logger.error("No custom network policy type detected.")
        else:
            logger.info(f"Custom network policy type detected: {custom_network_policy_type}")

        return custom_network_policy_type

    except Exception as e:
        logger.error(f"Error detecting custom network policy type: {e}")
        return None


def collect_network_policies(custom_network_policy_type):
    # Load Kubernetes configuration
    config.load_kube_config()

    # Initialize API client
    api_client = client.ApiClient()

    # Initialize CustomObjectsApi
    custom_objects_api = client.CustomObjectsApi(api_client)

    # Collect network policies based on custom_network_policy_type
    if custom_network_policy_type == "calico":
        # Get Calico network policies
        calico_policies = custom_objects_api.list_cluster_custom_object("crd.projectcalico.org", "v1", "networkpolicies")
        calico_global_policies = custom_objects_api.list_cluster_custom_object("crd.projectcalico.org", "v1", "globalnetworkpolicies")

        # Combine Calico network policies and global network policies
        all_calico_policies = calico_policies["items"] + calico_global_policies["items"]

        return all_calico_policies

    elif custom_network_policy_type == "cilium":
        # Get Cilium network policies
        cilium_policies = custom_objects_api.list_cluster_custom_object("cilium.io", "v2", "ciliumnetworkpolicies")
        cilium_clusterwide_policies = custom_objects_api.list_cluster_custom_object("cilium.io", "v2", "ciliumclusterwidenetworkpolicies")

        # Combine Cilium network policies and cluster-wide network policies
        all_cilium_policies = cilium_policies["items"] + cilium_clusterwide_policies["items"]

        return all_cilium_policies

    else:
        print("Invalid custom network policy type provided.")
        return []

# Implement conversion logic for Calico to Kubernetes native network policy
def convert_calico_network_policy_to_k8s_native_network_policy(calico_policy):
    k8s_network_policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": calico_policy["metadata"]["name"], "namespace": calico_policy["metadata"]["namespace"]}, "spec": {"podSelector": {"matchLabels": calico_policy["spec"]["ingress"][0]["from"]["selector"]}}, "policyTypes": ["Ingress"], "ingress": []}

    # Check if the Calico policy is namespace-scoped or global
    if "namespace" in calico_policy["metadata"]:
        k8s_network_policy["metadata"]["namespace"] = calico_policy["metadata"]["namespace"]
    else:
        k8s_network_policy["metadata"]["labels"] = {
            "calico-policy-type": "global"
        }

    # Handle selectors
    if "spec" in calico_policy and "selector" in calico_policy["spec"]:
        k8s_network_policy["spec"]["podSelector"] = {
            "matchLabels": calico_policy["spec"]["selector"]
        }

    # Handle ingress rules
    if "spec" in calico_policy and "ingress" in calico_policy["spec"]:
        k8s_network_policy["spec"]["ingress"] = []
        for rule in calico_policy["spec"]["ingress"]:
            k8s_rule = {}
            if "source" in rule:
                k8s_rule["from"] = []
                if "selector" in rule["source"]:
                    k8s_rule["from"].append({"podSelector": {"matchLabels": rule["source"]["selector"]}})
                if "nets" in rule["source"]:
                    k8s_rule["from"].append({"ipBlock": {"cidr": rule["source"]["nets"][0]}})

            if "action" in rule and rule["action"].lower() == "allow":
                k8s_network_policy["spec"]["ingress"].append(k8s_rule)

    # Handle egress rules
    if "spec" in calico_policy and "egress" in calico_policy["spec"]:
        k8s_network_policy["spec"]["egress"] = []
        for rule in calico_policy["spec"]["egress"]:
            k8s_rule = {}
            if "destination" in rule:
                k8s_rule["to"] = []
                if "selector" in rule["destination"]:
                    k8s_rule["to"].append({"podSelector": {"matchLabels": rule["destination"]["selector"]}})
                if "nets" in rule["destination"]:
                    k8s_rule["to"].append({"ipBlock": {"cidr": rule["destination"]["nets"][0]}})

            if "action" in rule and rule["action"].lower() == "allow":
                k8s_network_policy["spec"]["egress"].append(k8s_rule)

            # Add traffic filtering based on HTTP and DNS metadata here
            if "action" in rule and rule["action"].lower() == "allow":
                k8s_network_policy["spec"]["egress"].append(k8s_rule)

    return k8s_network_policy

# Implement  conversion logic for Cilium to Kubernetes native network policy
def convert_cilium_network_policy_to_k8s_native_network_policy(cilium_policy):
    k8s_network_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": cilium_policy["metadata"]["name"],
            "namespace": cilium_policy["metadata"]["namespace"]
        },
        "spec": {
            "podSelector": {
                "matchLabels": cilium_policy.get("spec", {}).get("endpointSelector", {}).get("matchLabels", {})
            },
            "policyTypes": ["Ingress"],
            "ingress": []
        }
    }

    # Check if the Cilium policy is namespace-scoped or global
    if "namespace" in cilium_policy["metadata"]:
        k8s_network_policy["metadata"]["namespace"] = cilium_policy["metadata"]["namespace"]
    else:
        k8s_network_policy["metadata"]["labels"] = {
            "cilium-policy-type": "global"
        }
        print(f"Global policy detected: {cilium_policy['metadata']['name']}")
        return None

    # Handle selectors
    if "spec" in cilium_policy and "endpointSelector" in cilium_policy["spec"]:
        k8s_network_policy["spec"]["podSelector"] = {
            "matchLabels": cilium_policy["spec"]["endpointSelector"].get("matchLabels", {})
        }

    # Handle ingress rules
    if "spec" in cilium_policy and "ingress" in cilium_policy["spec"]:
        k8s_network_policy["spec"]["ingress"] = []
        for rule in cilium_policy["spec"]["ingress"]:
            k8s_rule = {
                "from": [],
                "ports": []
            }
            if "toPort" in rule:
                k8s_rule["ports"].append({"protocol": "TCP", "port": rule["toPort"]})
            if "fromEndpoints" in rule:
                k8s_rule["from"] = []
                for endpoint in rule["fromEndpoints"]:
                    k8s_rule["from"].append({"podSelector": {"matchLabels": endpoint.get("matchLabels", {})}})
            if "fromCIDR" in rule:
                k8s_rule["from"] = [{"ipBlock": {"cidr": cidr}} for cidr in rule["fromCIDR"]]
            if "fromServiceAccount" in rule:
                k8s_rule["from"].append({"namespaceSelector": {"matchLabels": {}}, "podSelector": {"matchLabels": {}}})

            k8s_network_policy["spec"]["ingress"].append(k8s_rule)

    # Handle egress rules
    if "spec" in cilium_policy and "egress" in cilium_policy["spec"]:
        k8s_network_policy["spec"]["egress"] = []
        for rule in cilium_policy["spec"]["egress"]:
            k8s_rule = {}
            if "toEndpoints" in rule:
                k8s_rule["to"] = []
                for endpoint in rule["toEndpoints"]:
                    k8s_rule["to"].append({"podSelector": {"matchLabels": endpoint.get("matchLabels", {})}})
            if "toCIDR" in rule:
                k8s_rule["to"] = [{"ipBlock": {"cidr": cidr}} for cidr in rule["toCIDR"]]
            if "toServiceAccount" in rule:
                k8s_rule["to"].append({"namespaceSelector": {"matchLabels": {}}, "podSelector": {"matchLabels": {}}})

            k8s_network_policy["spec"]["egress"].append(k8s_rule)

    return k8s_network_policy

def load_kube_config():
    config.load_kube_config()

def save_to_local_storage(network_policies, output_folder):
    os.makedirs(output_folder, exist_ok=True)
    for policy in network_policies:
        policy_name = policy["metadata"]["name"]
        policy_namespace = policy["metadata"]["namespace"]
        output_file = os.path.join(output_folder, f"{policy_namespace}_{policy_name}.yaml")

        with open(output_file, "w") as f:
            yaml.safe_dump(policy, f)

def read_network_policy(policy_file):
    """Reads a network policy file and returns a dictionary of the policy."""
    with open(policy_file) as f:
        policy = yaml.safe_load(f)
    return policy

def build_test_dictionary(policy):
    """Builds a dictionary of the test cases for the network policy."""
    test_dictionary = {
        "ingress": [],
        "egress": []
    }
    for rule in policy["spec"].get("ingress", []):
        test_dictionary["ingress"].append(rule)
    for rule in policy["spec"].get("egress", []):
        test_dictionary["egress"].append(rule)
    return test_dictionary

def build_test(policy):
    """Builds a test for the network policy."""
    test_dictionary = build_test_dictionary(policy)
    for rule in test_dictionary["ingress"]:
        for port in rule.get("ports", []):
            test_case = {
                "name": "test_ingress_{}".format(port["protocol"]),
                "command": "kubectl exec test-pod --command nc -z localhost {}".format(port["port"]),
                "expected_result": "Failure"
            }
            yield test_case
    for rule in test_dictionary["egress"]:
        for port in rule.get("ports", []):
            test_case = {
                "name": "test_egress_{}".format(port["protocol"]),
                "command": "kubectl exec test-pod --command nc -z localhost {}".format(port["port"]),
                "expected_result": "Failure"
            }
            yield test_case

def run_tests(output_dir):
    """
    Run tests on the converted policies.
    """
    logger.info("Running tests on the converted policies...")

    # Load the test policies
    test_policies_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_policies")
    test_policies = []
    for filename in os.listdir(test_policies_dir):
        if filename.endswith(".yaml"):
            with open(os.path.join(test_policies_dir, filename), "r") as f:
                test_policies.append(yaml.safe_load(f))

    # Loop over each converted policy and run the tests
    for policy_type_folder in ["calico_converted", "cilium_converted"]:
        converted_policy_dir = os.path.join(output_dir, policy_type_folder)
        for filename in os.listdir(converted_policy_dir):
            if filename.endswith(".yaml"):
                with open(os.path.join(converted_policy_dir, filename), "r") as f:
                    policy = yaml.safe_load(f)

                    # Check that the policy is valid
                    if not validate_network_policy(policy):
                        logger.warning(f"Invalid policy: {policy['metadata']['name']}")
                        continue

                    logger.info("Running tests for policy: {}".format(policy["metadata"]["name"]))  # <-- fix is here

                    # Loop over each test policy and run the tests
                    for test_policy in test_policies:
                        if not validate_network_policy(test_policy):
                            logger.warning(f"Invalid test policy: {test_policy['metadata']['name']}")
                            continue

                        result = test_policy_applies_to_policy(test_policy, policy)
                        if result:
                            logger.info(f"Test passed: {test_policy['metadata']['name']} applies to {policy['metadata']['name']}")
                        else:
                            logger.warning(f"Test failed: {test_policy['metadata']['name']} does not apply to {policy['metadata']['name']}")

    logger.info("Tests completed.")

def check_connectivity(pod_labels, namespace, endpoint):
    conn_check = False
    try:
        # Check the connectivity
        pod_name = subprocess.check_output(["kubectl", "get", "pod", "-n", namespace, "-l", pod_labels, "-o", "name"]).decode('utf-8').strip().split('\n')
        logger.info(f"pod name: {pod_name[0]}")
        v_output = subprocess.check_output(["kubectl", "exec", "-n", namespace, "-it", pod_name[0], "--", "curl", "--max-time", "5", endpoint]).decode('utf-8').strip().split('\n')
        logger.info(v_output)
        conn_check = True
    except subprocess.CalledProcessError as e:
        logger.error(f"Error checking connectivity for {endpoint} App: {e}")

    return conn_check

def validate_np():
    # Test Scenario 1
    conn_status_1 = check_connectivity("app=client-one", namespace, endpoint_demoapp)
    
    # Test Scenario2
    conn_status_2 = check_connectivity("app=client-two", namespace, endpoint_demoapp)
    
    if conn_status_1 and not(conn_status_2):
        logger.info("Tested NetworkPolices successfully")
    else:
        logger.error("NetworkPolicy test failed")
        raise Exception("Network Policy Validation failed!!")
