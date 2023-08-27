# netpolymigrator

`netpolymigrator` is a tool to migrate Calico and Cilium network policies to Kubernetes native network policies.


## Requirements

- Python 3
- kubectl
- Helm 3 (optional)

## Usage

1. Clone this repository
```
git clone git@github.com:awslabs/k8s-network-policy-migrator.git
```

2. Go into netpolymigrator/bin directory
```
cd netpolymigrator/bin/
```

3. Update permissions on the executable
   
```
chmod +x netpol_migrator.sh
```

4. Run the `netpol_migrator.sh` script with one of the following commands:
```
./netpol_migrator.sh [pre_migration_check|collect|convert|apply|rollback|cleanup]
```


## How to run different commands

### Pre-Migration Check

- **`pre_migration_check`:** 
* Performs a set of prerequisites needed before you migrate your network policies. It detects which type of custom network policy you're using (Calico or Cilium), installs a demo application and its corresponding network policies, and then validates that everything is working as expected. Also cleans up created objects

```
./netpol_migrator.sh pre_migration_check
```

**Output for Pre-Migration-Check**
```
Pre-migration check...
2023-08-26 20:25:22,250 [INFO]: Custom network policy type detected: calico
2023-08-26 20:25:22,250 [INFO]: Installing Demo App
2023-08-26 20:25:24,427 [INFO]: Installed Demo App successfully
2023-08-26 20:25:25,643 [INFO]: Installed Calico network policy
2023-08-26 20:25:26,415 [INFO]: pod name: pod/client-one-5d96c56dfb-h9t6b
2023-08-26 20:25:27,926 [INFO]: ['<!DOCTYPE html>\r', '<html>\r', '<head>\r', '<title>Welcome to nginx!</title>\r', '<style>\r', 'html { color-scheme: light dark; }\r', 'body { width: 35em; margin: 0 auto;\r', 'font-family: Tahoma, Verdana, Arial, sans-serif; }\r', '</style>\r', '</head>\r', '<body>\r', '<h1>Welcome to nginx!</h1>\r', '<p>If you see this page, the nginx web server is successfully installed and\r', 'working. Further configuration is required.</p>\r', '\r', '<p>For online documentation and support please refer to\r', '<a href="http://nginx.org/">nginx.org</a>.<br/>\r', 'Commercial support is available at\r', '<a href="http://nginx.com/">nginx.com</a>.</p>\r', '\r', '<p><em>Thank you for using nginx.</em></p>\r', '</body>\r', '</html>']
2023-08-26 20:25:27,926 [INFO]: Test scenario 1 passed
2023-08-26 20:25:28,702 [INFO]: pod name: pod/client-two-f489dcf7b-5msqf
command terminated with exit code 28
2023-08-26 20:25:35,203 [ERROR]: Error checking connectivity for demo-svc.npmigrator-test.svc.cluster.local App: Command '['kubectl', 'exec', '-n', 'npmigrator-test', '-it', 'pod/client-two-f489dcf7b-5msqf', '--', 'curl', '--max-time', '5', 'demo-svc.npmigrator-test.svc.cluster.local']' returned non-zero exit status 28.
2023-08-26 20:25:35,203 [INFO]: Test scenario 2 passed
2023-08-26 20:25:35,203 [INFO]: All network policies validated successfully.
namespace "npmigrator-test" deleted
service "demo-svc" deleted
deployment.apps "demo-app" deleted
deployment.apps "client-one" deleted
deployment.apps "client-two" deleted
Error from server (NotFound): networkpolicies.projectcalico.org "demo-app-ingress-rule" not found
2023-08-26 20:25:42,894 [WARNING]: Calico network policy not found. Skipping deletion.
error: the server doesn't have a resource type "networkpolicies"
2023-08-26 20:25:43,763 [WARNING]: Cilium network policy not found. Skipping deletion.
2023-08-26 20:25:43,763 [INFO]: Cleanup successful.
```

### Collect
- **`collect`:** 
* Collects your existing Calico and Cilium network policies and stores them in a directory called `collected_network_policies`

```
./netpol_migrator.sh collect
```

**Output for Collect**
```
Collecting network policies...
2023-08-26 20:28:21,728 [INFO]: Custom network policy type detected: calico
2023-08-26 20:28:21,729 [INFO]: Collecting network policies...
2023-08-26 20:28:22,573 [INFO]: Collected 2 calico NetworkPolicies and saved to 'collected_network_policies/calico' folder
```

### Convert

- **`convert`:** 
* Converts your existing Calico and Cilium network policies to kubernetes native network policy and stores them in a directory called `converted_network_policies`. Make sure to provide the required `--input` argument, for example:

```
./netpol_migrator.sh convert --input collected_network_policies
```

**Output for convert**
```
Converting network policies...
2023-08-26 20:28:32,175 [INFO]: Custom network policy type detected: calico
2023-08-26 20:28:32,178 [INFO]: Converted policy 'default.allow-nginx-ingress' to Kubernetes native NetworkPolicy.
2023-08-26 20:28:32,943 [INFO]: Validation passed for the policy: default.allow-nginx-ingress
2023-08-26 20:28:32,945 [INFO]: Validation passed for the policy using Kubernetes API: default.allow-nginx-ingress
2023-08-26 20:28:34,182 [INFO]: Custom network policy type detected: calico
2023-08-26 20:28:34,185 [INFO]: Converted policy 'default.allow-busybox-egress' to Kubernetes native NetworkPolicy.
2023-08-26 20:28:34,935 [INFO]: Validation passed for the policy: default.allow-busybox-egress
2023-08-26 20:28:34,936 [INFO]: Validation passed for the policy using Kubernetes API: default.allow-busybox-egress
2023-08-26 20:28:34,936 [INFO]: Converted 2 namespace-scoped Calico NetworkPolicies to Kubernetes native NetworkPolicies and saved them in 'converted_network_policies' folder.
```


**NOTE:** Before `apply` function you can run `pre_migration_check` just to make sure everything is working as expected

### Apply

- **`apply`:**
* Applies the converted network policies to your cluster. You will be prompted to select which subfolder to use (`cilium_converted` or `calico_converted`). Example usage:

  ```
  ./netpol_migrator.sh apply
  ```

**Output for Apply**
```
Which subfolder do you want to use for applying the network policies?
1. cilium_converted
2. calico_converted
Enter your choice (1 or 2): 2
Applying network policies from calico_converted...
2023-08-26 20:42:09,645 [INFO]: Namespace default already exists.
2023-08-26 20:42:09,648 [INFO]: Validating policy default.allow-nginx-ingress
2023-08-26 20:42:09,649 [INFO]: Applying policy default.allow-nginx-ingress
2023-08-26 20:42:10,411 [INFO]: Network policy 'default.allow-nginx-ingress' applied successfully.
2023-08-26 20:42:10,412 [INFO]: Validating policy default.allow-busybox-egress
2023-08-26 20:42:10,412 [INFO]: Applying policy default.allow-busybox-egress
2023-08-26 20:42:11,192 [INFO]: Network policy 'default.allow-busybox-egress' applied successfully.
2023-08-26 20:42:11,195 [INFO]: Saved applied network policies to applied_network_policies.yaml
```

### Rollback
- **`rollback`:**
* Rolls back the applied network policies. Make sure to provide the required `--applied-network-policies-file` argument, for example:

  ```
  ./netpol_migrator.sh rollback --applied-network-policies-file applied_network_policies.yaml
  ```

**Output for Rollback**
```
2023-08-26 20:43:06,727 - INFO - Rolling back 2 applied network policies in namespace 'default'...
2023-08-26 20:43:07,563 - INFO - Network policy 'default.allow-nginx-ingress' rolled back successfully in namespace 'default'
2023-08-26 20:43:08,326 - INFO - Network policy 'default.allow-busybox-egress' rolled back successfully in namespace 'default'
```

### Cleanup
- **`cleanup`:** 
* Cleans up resources related to the CNI provider you are using (either Calico or Cilium). You will be prompted to select which CNI provider to clean up. 
Example usage:

  ```
  ./netpol_migrator.sh cleanup
  ```

### Validate

- **`validate`:** 
* Validates the statements shared below
  ```
  ./netpol_migrator.sh validate
  ```

**NOTE:**
* checks if the network policy is a non-empty dictionary,If not, it logs a warning and returns False
* checks if the network policy contains all the required fields: "apiVersion", "kind", "metadata", and "spec". If any of these fields are missing, it logs a warning and returns False
* checks if the apiVersion of the network policy is either "networking.k8s.io/v1" or "networking.k8s.io/v1beta1". If not, it logs a warning and returns False
* checks if the kind of the network policy is "NetworkPolicy". If not, it logs a warning and returns False
* checks if the metadata of the network policy contains the 'name' field. If not, it logs a warning and returns False
* checks if the spec field of the network policy is non-empty. If not, it logs a warning and returns False
* checks if the policyTypes field of the spec is non-empty. If not, it logs a warning and returns False
* For each egress rule in the network policy, it checks if the podSelector.matchLabels field meets the naming requirements (alphanumeric characters, hyphen, underscore, or dot). If not, it logs a warning and returns False


## Contributing
* Guidelines on how to contribute to the project.

## License
* This tool is released under the [Apache 2.0](LICENSE).
