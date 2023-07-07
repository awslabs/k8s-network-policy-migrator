import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ing_unsup_features = ["fromRequires", "fromServices", "icmps", "ingressDeny"]
eg_unsup_features = ["toRequires", "toServices", "toFQDNs", "icmps","toGroups", "egressDeny"]

# Implement  conversion logic for Cilium to Kubernetes native network policy
def convert_cilium_network_policy(cilium_policy):
    rtn_list = []
    specs = []
    if cilium_policy.get("specs"):
        specs = cilium_policy.get("specs")
    else:
        specs.append(cilium_policy["spec"])

    for spec in specs:
        k8s_network_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": cilium_policy["metadata"]["name"] + ("" if len(rtn_list) == 0 else ("-"+str(len(rtn_list)))),
                "namespace": cilium_policy["metadata"]["namespace"] if cilium_policy["metadata"].get("namespace") else "default",
            },
            "spec": {
                "policyTypes": []
            },
        }
        # Handle endpoint selectors
        if "endpointSelector" in spec:
            k8s_network_policy["spec"]["podSelector"] = {
                "matchLabels": spec["endpointSelector"]["matchLabels"]
            }

        # Handle ingress rules
        convert_ingress_rules(spec, k8s_network_policy)

        # Handle egress rules
        convert_egress_rules(spec, k8s_network_policy)

        rtn_list.append(k8s_network_policy)

    return rtn_list

# Handle ingress rules
def convert_ingress_rules(spec, k8s_network_policy):
    ingress_rule_exists = False
    if spec.get("ingress"):
        k8s_network_policy["spec"]["ingress"] = []
        for rule in spec["ingress"]:
            k8s_rule = {}

            for ing_unsup in ing_unsup_features:
                if ing_unsup in rule:
                    logger.error(f"Conversion is not supported due to missing support in upstream NetworkPolicy - {ing_unsup}")
                    raise Exception(f"CiliumNetworkPolicy has unsupported attribute - {ing_unsup}")
            
            if "fromEndpoints" in rule:
                k8s_rule["from"] = []
                for endpoint in rule["fromEndpoints"]:
                    if endpoint.get("matchLabels"):
                        k8s_rule["from"].append({"podSelector": {"matchLabels": endpoint["matchLabels"]}})
                    else:
                        k8s_rule["from"].append({"podSelector": {}})

            if "toPorts" in rule:
                ports = process_to_ports(rule)
                if len(ports) > 0:
                    k8s_rule["ports"] = ports
                
            if "fromEntities" in rule:
                for entity in rule["fromEntities"]:
                    if entity in ["world", "all"]:
                        k8s_rule["from"] = []
                        k8s_rule["from"].append({"ipBlock": {"cidr":"0.0.0.0/0"}})
                        break
                    else:
                        logger.error(f"this entity is not supported: {entity}")
                        raise Exception(f"CiliumNetworkPolicy has unsupported attribute - fromEntities({entity})")
                    
            if "fromCIDRSet" in rule:
                cidr_set = []
                for cidr in rule["fromCIDRSet"]:
                    cidr_var = {"ipBlock": {"cidr": cidr["cidr"]}}
                    if cidr.get("except"):
                        cidr_var["ipBlock"]["except"] = cidr["except"]

                    cidr_set.append(cidr_var)
                
                k8s_rule["from"] = cidr_set

            elif "fromCIDR" in rule:
                k8s_rule["from"] = [{"ipBlock": {"cidr": cidr}} for cidr in rule["fromCIDR"]]

            ingress_rule_exists = True
            k8s_network_policy["spec"]["ingress"].append(k8s_rule)

        if ingress_rule_exists == True:
            k8s_network_policy["spec"]["policyTypes"].append("Ingress")
    
def convert_egress_rules(spec, k8s_network_policy):
    # Handle egress rules
    egress_rule_exists = False
    if spec.get("egress"):
        k8s_network_policy["spec"]["egress"] = []
        for rule in spec["egress"]:
            k8s_rule = {}

            for eg_unsup in eg_unsup_features:
                if eg_unsup in rule:
                    logger.error(f"Conversion is not supported due to missing support in upstream NetworkPolicy - {eg_unsup}")
                    raise Exception(f"CiliumNetworkPolicy has unsupported attribute - {eg_unsup}")
            
            if "toEndpoints" in rule:
                k8s_rule["to"] = []
                for endpoint in rule["toEndpoints"]:
                    if endpoint.get("matchLabels"):
                        k8s_rule["to"].append({"podSelector": {"matchLabels": endpoint["matchLabels"]}})
                    else:
                        k8s_rule["to"].append({"podSelector": {}})

            if "toCIDRSet" in rule:
                cidr_set = []
                for cidr in rule["toCIDRSet"]:
                    cidr_var = {"ipBlock": {"cidr": cidr["cidr"]}}
                    if cidr.get("except"):
                        cidr_var["ipBlock"]["except"] = cidr["except"]

                    cidr_set.append(cidr_var)
                
                k8s_rule["to"] = cidr_set

            elif "toCIDR" in rule:
                k8s_rule["to"] = [{"ipBlock": {"cidr": cidr}} for cidr in rule["toCIDR"]]

            if "toPorts" in rule:
                ports = process_to_ports(rule)
                if len(ports) > 0:
                    k8s_rule["ports"] = ports
            
            if "toEntities" in rule:
                for entity in rule["toEntities"]:
                    if entity in ["world", "all"]:
                        k8s_rule["to"].append({"ipBlock": {"cidr":"0.0.0.0/0"}})
                    else:
                        logger.error(f"this entity is not supported: {entity}")
                        raise Exception(f"CiliumNetworkPolicy has unsupported attribute - toEntities({entity})")

            egress_rule_exists = True
            k8s_network_policy["spec"]["egress"].append(k8s_rule)
        
        if egress_rule_exists == True:
            k8s_network_policy["spec"]["policyTypes"].append("Egress")
    
def process_to_ports(rule):
    ports = []
    for pvar in rule["toPorts"]:
        if "rules" in pvar or "listener" in pvar or "originatingTLS" in pvar:
            logger.error("toPorts is not supported")
            raise Exception("CiliumNetworkPolicy has unsupported attribute - toPorts")
        
        ports = [
            {
                "protocol": port["protocol"] if "protocol" in port else None,
                "port": int(port["port"]) if "port" in port else None,
            }for port in pvar["ports"]
        ]

    return ports
