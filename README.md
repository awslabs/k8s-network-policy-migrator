# netpolymigrator

`netpolymigrator` is a tool to migrate Calico and Cilium network policies to Kubernetes native network policies. 

AWS EKS has Network Policy support through the [VPC CNI.](https://github.com/aws/amazon-vpc-cni-k8s) Review the [EKS User Guide](https://docs.aws.amazon.com/eks/latest/userguide/[[network policy page name]].html) for more information. 


## Requirements

- Python 3
- kubectl
- Helm 3 (optional)

## Usage

1. Clone this repository

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

- `setup_environment`: Installs a demo app and network policy based on what is running on the cluster (Calico or Cilium)

```
./netpol_migrator.sh setup_environment
```

- `convert`: Converts your existing Calico and Cilium network policies to kubernetes native network policy and stores them in a directory called `converted_network_policies`. Make sure to provide a directory of policies with the required `--input` argument, for example:

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

The validator checks:
* The network policy is a non-empty dictionary. 
* The network policy contains all the required fields: "apiVersion", "kind", "metadata", and "spec". 
* The apiVersion of the network policy is either "networking.k8s.io/v1" or "networking.k8s.io/v1beta1". 
* The kind of the network policy is "NetworkPolicy". 
* The metadata of the network policy contains the 'name' field. 
* The spec field of the network policy is non-empty. 
* The policyTypes field of the spec is non-empty. 
* For each egress rule in the network policy, the podSelector.matchLabels field meets the naming requirements (alphanumeric characters, hyphen, underscore, or dot). 

- `cleanup`: Cleans up resources related to the CNI provider you are using (either Calico or Cilium). You will be prompted to select which CNI provider to clean up. Example usage:

  ```
  ./netpol_migrator.sh cleanup
  ```

## License
* This tool is released under the [Apache 2.0](LICENSE).

## Security disclosures

If you think you’ve found a potential security issue, please do not post it in the Issues. Instead, please follow the
instructions [here](https://aws.amazon.com/security/vulnerability-reporting/) or [email AWS security directly](mailto:aws-security@amazon.com).

## Contributing

[See CONTRIBUTING.md](./CONTRIBUTING.md)
