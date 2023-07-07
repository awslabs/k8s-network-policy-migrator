import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

unsup_features = ["order", "serviceAccountSelector", "http", "icmp", "notICMP", "notProtocol", "notNets", "notPorts", "notSelector", "serviceAccounts", "services"]

# Implement  conversion logic for Calico to Kubernetes native network policy
def convert_calico_network_policy(calico_policy):
    k8s_network_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": calico_policy["metadata"]["name"],
            "namespace": calico_policy["metadata"]["namespace"],
        },
        "spec": {
            "policyTypes": []
        },
    }

    spec = calico_policy["spec"]
    # Handle selectors
    if "selector" in spec:
        kv = parse_labels(spec["selector"])
        k8s_network_policy["spec"]["podSelector"] = {
            "matchLabels": {kv[0] : kv[1]}
        }

    check_for_unsup_features(spec)

    # Handle ingress rules
    if "ingress" in spec:
        k8s_network_policy["spec"]["ingress"] = []
        for rule in spec["ingress"]:
            if "Allow" != rule["action"]:
                raise Exception(f"Calico NetworkPolicy has unsupported ingress action - {rule['action']}")
            
            check_for_unsup_features(rule)
            
            k8s_rule = {}
            if "source" in rule:
                check_for_unsup_features(rule["source"])
                k8s_rule["from"] = []
                if "namespaceSelector" in rule["source"]:
                    kv = parse_labels(rule["source"]["namespaceSelector"])
                    k8s_rule["from"].append({"namespaceSelector": {"matchLabels": {kv[0] : kv[1]}}})
                    
                if "selector" in rule["source"]:
                    kv = parse_labels(rule["source"]["selector"])
                    k8s_rule["from"].append({"podSelector": {"matchLabels": {kv[0] : kv[1]}}})

                if "nets" in rule["source"]:
                    k8s_rule["from"].append({"ipBlock": {"cidr": rule["source"]["nets"][0]}})

            ports = convert_ports(rule)
            if len(ports) > 0:
                k8s_rule["ports"] = ports

            if "action" in rule and rule["action"].lower() == "allow":
                k8s_network_policy["spec"]["ingress"].append(k8s_rule)
                k8s_network_policy["spec"]["policyTypes"].append("Ingress")

    # Handle egress rules
    if "spec" in calico_policy and "egress" in calico_policy["spec"]:
        k8s_network_policy["spec"]["egress"] = []
        for rule in calico_policy["spec"]["egress"]:
            if "Allow" != rule["action"]:
                raise Exception(f"Calico NetworkPolicy has unsupported egress action - {rule['action']}")
            
            check_for_unsup_features(rule)
            
            k8s_rule = {}
            if "destination" in rule:
                check_for_unsup_features(rule["destination"])
                k8s_rule["to"] = []
                if "namespaceSelector" in rule["destination"]:
                    kv = parse_labels(rule["destination"]["namespaceSelector"])
                    k8s_rule["to"].append({"namespaceSelector": {"matchLabels": {kv[0] : kv[1]}}})

                if "selector" in rule["destination"]:
                    kv = parse_labels(rule["destination"]["selector"])
                    k8s_rule["to"].append({"podSelector": {"matchLabels": {kv[0] : kv[1]}}})

                if "nets" in rule["destination"]:
                    k8s_rule["to"].append({"ipBlock": {"cidr": rule["destination"]["nets"][0]}})

                ports = convert_ports(rule)
                if len(ports) > 0:
                    k8s_rule["ports"] = ports

            if "action" in rule and rule["action"].lower() == "allow":
                k8s_network_policy["spec"]["egress"].append(k8s_rule)
                k8s_network_policy["spec"]["policyTypes"].append("Egress")

    return k8s_network_policy

def convert_ports(rule):
    if "protocol" in rule and rule["protocol"] != "TCP":
        raise Exception(f"Calico NetworkPolicy has unsupported protocol - {rule['protocol']}")

    if "destination" in rule and rule["destination"].get("ports"):
        return [
            {
                "protocol": rule["protocol"] if "protocol" in rule else None,
                "port": port,
            }for port in rule["destination"]["ports"]
        ]
    
    return []

def parse_labels(labels):
    kv = labels.split('==')
    return [kv[0].strip(), kv[1].replace("'", "").strip()]

def check_for_unsup_features(input):
    for unsup in unsup_features:
        if unsup in input:
            logger.error("Conversion is not supported due to missing support in upstream NetworkPolicy")
            raise Exception(f"Calico NetworkPolicy has unsupported attribute - {unsup}")
        