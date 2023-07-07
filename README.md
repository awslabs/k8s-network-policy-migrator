# netpolymigrator

`netpolymigrator` is a tool to migrate Calico and Cilium network policies to Kubernetes native network policies.


## Requirements

- Python 3
- kubectl
- Helm 3 (optional)

## Usage

1. Clone this repository
```
git clone git@ssh.gitlab.aws.dev:sganjiha/netpolymigrator.git
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
./netpol_migrator.sh [collect|convert|apply|rollback|cleanup]
```


**The available commands are:**

- `collect`: Collects your existing Calico and Cilium network policies and stores them in a directory called `collected_network_policies`

```
./netpol_migrator.sh collect
```

- `setup_environment`: Installs demo app and a network policy based on what is running on the cluster (Calico or Cilium)

```
./netpol_migrator.sh setup_environment
```

- `convert`: Converts your existing Calico and Cilium network policies to kubernetes native network policy and stores them in a directory called `converted_network_policies`. Make sure to provide the required `--input` argument, for example:

```
./netpol_migrator.sh convert --input collected_network_policies
```

- `apply`: Applies the converted network policies to your cluster. You will be prompted to select which subfolder to use (`cilium_converted` or `calico_converted`). Example usage:

  ```
  ./netpol_migrator.sh apply
  ```

- `rollback`: Rolls back the applied network policies. Make sure to provide the required `--applied-network-policies-file` argument, for example:

  ```
  ./netpol_migrator.sh rollback --applied-network-policies-file applied_network_policies.yaml
  ```

- `validate`: validates the statements shared below
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


- `cleanup`: Cleans up resources related to the CNI provider you are using (either Calico or Cilium). You will be prompted to select which CNI provider to clean up. Example usage:

  ```
  ./netpol_migrator.sh cleanup
  ```

## Contributing
* Guidelines on how to contribute to the project.

## License
* This tool is released under the [Apache 2.0](LICENSE).
