# cloud-cmd

cloud-cmd was forked from the wonderful [tomsteele/cloud-proxy](https://github.com/tomsteele/cloud-proxy) project. Where the goal of cloud-proxy was to provide multiple cloud instances for SOCKS proxies, cloud-cmd provides a convenient way to divide commands among multiple cloud instances.

The primary use case, at least currently, is to split an Nmap scan across multiple cloud instances. During penetration testing engagements we sometimes encounter targets that blacklist you or otherwise change their bahaviour when they detect they are being port scanned (such as show all ports as open...I'm looking at you SonicWall).

This is accomplished with a few bits of functionality, some of which the user has control over, and others which rely on hardcoded functionality. For instance, the command that gets passed to each cloud instance is configurable by the caller using Go `text/template` syntax passed to the `-cmd` flag. But one of the variables availble to the template relies on hard-coded functionality in cloud-cmd--the `-ports` flag. This flag takes a valid nmap port list (e.g. the top 5 TCP ports `21-23,80,443`) but breaks the list into equal size chunks and passes them into the command template for each cloud instance as the `{{.ports}}` variable.

There are 4 built-in variables that are passed to the command template so far: `{{.ports}}`, `{{.index}}`, `{{.ip}}`, and `{{.name}}`. Any shell command that can be successfully divided accross all cloud instances using these variables is fair game. Commands requiring additional splitting/dividing functionality (similar to the `-ports` flag and template variable) would need to have them added to cloud-cmd. As an example, if instead of dividing the ports accross the cloud instances for the same set of scan targets you wanted to scan the same ports but divide up the targets, we'd need to add a new flag and functionality for dividing something like a comma-separate list into different chunks.

# Usage

In order to deploy instances, you must provide your Digital Ocean API key either with the `-token` flag, or with the environment variable `DOTOKEN`.

In order to launch the instances and connect to them, you must provide the path to an SSH private key who's public key and signature are already configured in your Digital Ocean account. Do this using the `-key-location` flag. It is OK if the private key is encrypted, you will be prompted for the password before the tool proceeds.

Provide the number of cloud instances you want to launch with the `-count` flag.

Provide the command you want to run with the `-cmd` flag. The command uses Go `text/template` syntax and has the following variables avilable to it:

- `{{.index}}`: the number/index marking the order that instances was launched, starting at 1.
- `{{.ip}}`: The public IPv4 address of the cloud instance.
- `{{.name}}`: The name assigned to the instance by Digital Ocean, which also happens to be the configured hostname.
- `{{.ports}}`: One slice of the total list of ports that was specified with the `-ports` flag.


If successfull completion of the command requires some packages be installed first, pass a comma-separated list of packages to the `-pkg` flag.

While the command is running on the cloud instances, stderr for the SSH session will be printed as log lines in the output from cloud-cmd. Stdout for the SSH session will be redirected into files output into the current directory, one for each instance, called `out-{{.index}}.xml`. Note that the file extension can be changed with the `-ext` flag.

# Example

[![asciicast](https://asciinema.org/a/RYLcBjGhfHg4ffrKiCck2e3ZK.svg)](https://asciinema.org/a/RYLcBjGhfHg4ffrKiCck2e3ZK)

```shell
./cloud-cmd -key-location ~/.ssh/keys.d/id_rsa.admin -name clientName -count 50 -cmd "nmap -v4 -oX - -Pn -n --max-rate 10 -p {{.ports}} -sS aerissecure.com" -ports 1-65535 -force
```

In the example above we have the solution to the problem that motivated the creation of cloud-cmd. We are limiting the rate of our nmap scan using `--max-rate 10` which is incredibly slow. It would take around 3 hours to complete a scan of all ports on a single host with a rate that low if we were scanning from a single system. We've specified a port list with `-ports` that will split those ports accross each cloud instance. Note that the actual command to be run will be printed to the shell before running on each cloud instance.

Also note that we are using `-oX -` in the command to output the scan results in xml format to stdout where they will be captured by cloud-cmd and redirected to the output file for that cloud instance.

Note that since XML output is hierarchical, Nmap cannot output any port scan results until all ports for a host are done scanning. You will only see progress updates like the following until at least one host is complete:

```xml
<taskprogress task="SYN Stealth Scan" time="1565727654" percent="1.15" remaining="10402" etc="1565738055"/>
```

With a sufficiently large `--min-hostgroup`, all hosts should scan concurrently, which means you won't have any results until the scan is 100% complete. You could consider adding an additional output `-oN filename` if you want to peek in on progress by SSHing to one of the instances.


### Install

Install using `go get`:

```shell
go install github.com/aerissecure/cloud-cmd
```
