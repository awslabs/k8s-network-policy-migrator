#!/bin/bash

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Check if the command line argument is provided
if [ -z "$1" ]; then
  echo "Usage: ./netpol_migrator.sh [collect|setup_environment|convert|apply|validate|rollback|cleanup]"
  exit 1
fi

case $1 in
  collect)
    echo "Collecting network policies..."
    # Execute collect.py
    python3 "${SCRIPT_DIR}/../netpolymigrator/collect.py" collect
    ;;

  setup_environment)
    echo "Setting up the environment..."
    # Deploy the Demo App & Network Policy
    python3 "${SCRIPT_DIR}/../netpolymigrator/setup_environment.py" 
    ;;

  convert)
    echo "Converting network policies..."
    # Execute convert.py
    # Make sure to provide the required --input argument, for example:
    python3 "${SCRIPT_DIR}/../netpolymigrator/convert.py" convert --input collected_network_policies
    ;;

  apply)
    # Ask the user which subfolder to use
    echo "Which subfolder do you want to use for applying the network policies?"
    echo "1. cilium_converted"
    echo "2. calico_converted"
    read -p "Enter your choice (1 or 2): " choice

    case $choice in
      1)
        echo "Applying network policies from cilium_converted..."
        # Execute apply.py with the cilium_converted subfolder
        python3 "${SCRIPT_DIR}/../netpolymigrator/apply.py" --input converted_network_policies/cilium_converted
        ;;
      2)
        echo "Applying network policies from calico_converted..."
        # Execute apply.py with the calico_converted subfolder
        python3 "${SCRIPT_DIR}/../netpolymigrator/apply.py" --input converted_network_policies/calico_converted
        ;;
      *)
        echo "Invalid choice. Please enter 1 or 2."
        exit 1
        ;;
    esac
    ;;

  rollback)
    echo "Rolling back applied network policies..."
    # Execute rollback.py
    # Make sure to provide the required --applied-network-policies-file argument, for example:
    python3 "${SCRIPT_DIR}/../netpolymigrator/rollback.py" --applied-network-policies-file applied_network_policies.yaml
    ;;

  validate)
    echo "Validating network policies..."
    # Post validation step
    python3 "${SCRIPT_DIR}/../netpolymigrator/validate.py"
    ;;

  cleanup)
    echo "Cleaning up..."
    # Prompt user to select CNI provider
    echo "Which CNI provider are you using?"
    select cni_provider in "Calico" "Cilium"; do
      case $cni_provider in
        "Calico")
          echo "Cleaning up Calico..."
          python3 "${SCRIPT_DIR}/../netpolymigrator/cleanup_calico.py"
          break
          ;;
        "Cilium")
          echo "Cleaning up Cilium..."
          python3 "${SCRIPT_DIR}/../netpolymigrator/cleanup_cilium.py"
          break
          ;;
        *)
          echo "Invalid input. Please select a number from the options."
          ;;
      esac
    done
    ;;

  *)
    echo "Invalid command. Usage: ./netpol_migrator.sh [collect|setup_environment|convert|apply|validate|rollback|cleanup]"
    exit 1
    ;;
esac
