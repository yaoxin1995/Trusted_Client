# Secure client

A kubectl-like command-line tool that allows clients to interact securely with a k8s cluster.

## Usage
```
./secure-client

Usage: secure-client <COMMAND>

Commands:
  terminal   Allocate a terminal inside a container This terminal is cross platform runable
  issue-cmd  Issue cmd to a container Example: ./secure-client issue-cmd nginx "ls -t /var"
  get        Get resource from cluster (in default namespace)
  edit       Edit a resource
  delete     Delete a resource
  watch      Watches a Kubernetes Resource for changes continuously
  apply      Apply a configuration to a resource by file name
  logs       Get logs of the first container in Pod
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```
