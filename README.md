# Fork

Forked from `tomsteele/cloud-proxy` and repurposed to support scanning only, and maybe eventuall additional commands.

./cloud-cmd -p 1,2,3,4-200,500 -nmap

```shell
nmap -oX ex.tcp.1.datascan-01 nmap -v4 -Pn -n -sS --max-rtt-timeout 120ms --min-rtt-timeout 50ms --initial-rtt-timeout 120ms --max-retries 1 --max-rate 10 --min-hostgroup 4096

m := map[string]interface{}{"name": "John", "age": 47}
t := template.Must(template.New("").Parse("Hi {{.name}}. Your age is {{.age}}\n"))
t.Execute(os.Stdout, m)
```

the basic idea is that for nmap, you pass in a port list. the list will be devided up into a number of equal chuncks that matches the number of launched droplets. You also pass in a templated nmap command. The templated nmap command as one variable for the split ports `{{.ports}}`, one variable for the instance index `{{.index}}` (which will be a zero padded number with the padding matching the number of launched hosts (0 for 1-9, 1 for 10-99, 2 for 100-999, etc.)). We should probably also make available `{{.ip}}` for the public ip address of the droplet and `{{.hostname}}` (or dropletname) for the name of the droplet

The nmap command will run and stdout will be streamed into output files matching the index. This would mean  you're meant to run nmap with `-oX -`. Though we could create an output file and download that at the end, or stream that file back as its written. I think we start with -oX first.

We should support some watch command, but for now it may be easiest to just print out the makings of a watch command to be filled in by the caller.

Just need to figure out what I want to actuall print to the screen now.

# cloud-proxy
cloud-proxy creates multiple DO droplets and then starts local socks proxies using SSH. After exiting, the droplets are deleted.

### Warning
This tool will deploy as many droplets as you desire, and will make a best effort to delete them after use. However, you are ultimately going to pay the bill for these droplets, and it is up to you, and you alone to ensure they actually get deleted.

### Install
Download a compiled release [here](https://github.com/tomsteele/cloud-proxy/releases/latest). You can now execute without any dependencies. Currently the only supported and tested OS is Linux:
```
$ ./cloud-proxy
```
### Usage
```
Usage of ./cloud-proxy:
  -count int
        Amount of droplets to deploy (default 5)
  -force
        Bypass built-in protections that prevent you from deploying more than 50 droplets
  -key string
        SSH key fingerprint
  -key-location string
        SSH key location (default "~/.ssh/id_rsa")
  -name string
        Droplet name prefix (default "cloud-proxy")
  -regions string
        Comma separated list of regions to deploy droplets to, defaults to all. (default "*")
  -start-tcp int
        TCP port to start first proxy on and increment from (default 55555)
  -token string
        DO API key
  -v    Print version and exit
```

### Getting Started
To use cloud-proxy you will need to have a DO API token, you can get one [here](https://cloud.digitalocean.com/settings/api/tokens). Next, ensure you have an SSH key saved on DO. This is the key that SSH will authentication with. The DO API and cloud-proxy require you to provide the fingerprint of the key you would like to use. You can obtain the fingerprint using `ssh-keygen`:
```
$ ssh-keygen -lf ~/.ssh/id_rsa.pub
```

If your key requires a passphrase, you will need to use ssh-agent:
```
$ eval `ssh-agent -s`
$ ssh-add ~/.ssh/id_rsa
```

Now you may create some proxies:
```
$ cloud-proxy -count 2 -token <api-token> -key <fingerprint>
```

When you are finished using your proxies, use CTRL-C to interrupt the program, cloud-proxy will catch the interrupt and delete the droplets.

cloud-proxy will output a proxy list for proxychains and [socksd](https://github.com/eahydra/socks/tree/master/cmd/socksd). proxychains can be configured to iterate over a random proxy for each connection by uncommenting `random_chain`, you should also comment out `string-chain`, which is the default. You will also need to uncomment `chain_len` and set it to `1`.

socksd can be helpful for programs that can accept a socks proxy, but may not work nicely with proxychains. socksd will listen as a socks proxy, and can be configured to use a set of upstream proxies, which it will iterate through in a round-robin manner. Follow the instructions in the README linked above, as it is self explanitory.

### Example Output
```
$ ./cloud-proxy -token <my_token> -key <my_fingerprint>
==> Info: Droplets deployed. Waiting 100 seconds...
==> Info: SSH proxy started on port 55555 on droplet name: cloud-proxy-1 IP: <IP>
==> Info: SSH proxy started on port 55556 on droplet name: cloud-proxy-2 IP: <IP>
==> Info: SSH proxy started on port 55557 on droplet name: cloud-proxy-3 IP: <IP>
==> Info: SSH proxy started on port 55558 on droplet name: cloud-proxy-4 IP: <IP>
==> Info: SSH proxy started on port 55559 on droplet name: cloud-proxy-5 IP: <IP>
==> Info: proxychains config
socks5 127.0.0.1 55555
socks5 127.0.0.1 55556
socks5 127.0.0.1 55557
socks5 127.0.0.1 55558
socks5 127.0.0.1 55559
==> Info: socksd config
"upstreams": [
{"type": "socks5", "address": "127.0.0.1:55555"},
{"type": "socks5", "address": "127.0.0.1:55556"},
{"type": "socks5", "address": "127.0.0.1:55557"},
{"type": "socks5", "address": "127.0.0.1:55558"},
{"type": "socks5", "address": "127.0.0.1:55559"}
]
==> Info: Please CTRL-C to destroy droplets
^C==> Info: Deleted droplet name: cloud-proxy-1
==> Info: Deleted droplet name: cloud-proxy-2
==> Info: Deleted droplet name: cloud-proxy-3
==> Info: Deleted droplet name: cloud-proxy-4
==> Info: Deleted droplet name: cloud-proxy-5
```

