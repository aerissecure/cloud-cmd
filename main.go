/*cloud-proxy is a utility for creating multiple DO droplets
and starting socks proxies via SSH after creation.*/
package main

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	// "strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aerissecure/csrange"
	"github.com/digitalocean/godo"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// TODO: there is a 10 host limit for a single droplet creation call. for larger, split into multiple calls.

var (
	ports       = flag.String("ports", "", "nmap compliant port list. It's devided into buckets, one for each droplet and made available in the cmd template as {{.ports}}")
	cmd         = flag.String("cmd", "", "templated command to run on droplets")
	pkg         = flag.String("pkg", "nmap", "packages to install, separated by comma")
	token       = flag.String("token", "", "DO API key; Or use DOTOKEN env var")
	sshLocation = flag.String("key-location", "~/.ssh/id_rsa", "SSH key location")
	count       = flag.Int("count", 5, "Amount of droplets to deploy")
	name        = flag.String("name", "cloud-proxy", "Droplet name prefix")
	ext         = flag.String("ext", ".xml", "file extension for command output files")
	regions     = flag.String("regions", "*", "Comma separated list of regions to deploy droplets to, defaults to all.")
	force       = flag.Bool("force", false, "Bypass built-in protections that prevent you from deploying more than 50 droplets")
	// TODO: REMOVE: proxy specific
	startPort   = flag.Int("start-tcp", 55555, "TCP port to start first proxy on and increment from")
	showversion = flag.Bool("v", false, "Print version and exit")
	version     = "1.0.0"
)

func main() {
	flag.Parse()
	if *showversion {
		fmt.Println(version)
		os.Exit(0)
	}
	if *token == "" {
		envToken := os.Getenv("DOTOKEN")
		if envToken != "" {
			*token = envToken
		} else {
			log.Fatalln("-token required")
		}
	}

	sshSigner, err := openSSHKey(*sshLocation)
	if err != nil {
		log.Fatalln(err)
	}
	keyID := ssh.FingerprintLegacyMD5(sshSigner.PublicKey())

	if *count > 50 && !*force {
		log.Fatalln("-count greater than 50")
	}

	client := newDOClient(*token)

	availableRegions, err := doRegions(client)
	if err != nil {
		log.Fatalf("There was an error getting a list of regions:\nError: %v\n", err)
	}

	regionCountMap, err := regionMap(availableRegions, *regions, *count)
	if err != nil {
		log.Fatalf("%v\n", err)
	}
	droplets := []godo.Droplet{}

	for region, c := range regionCountMap {
		log.Printf("Creating %d droplets in region %s", c, region)
		drops, _, err := client.Droplets.CreateMultiple(context.Background(), newDropLetMultiCreateRequest(*name, region, keyID, c))
		droplets = append(droplets, drops...)
		if err != nil {
			log.Printf("There was an error creating the droplets: %v\n", err)
			log.Println("Attempting cleanup...")
			machines := dropletsToMachines(droplets)
			cleanup(machines, client)
			log.Fatalln("You may need to do some manual clean up!")
		}
	}

	machines := dropletsToMachines(droplets)

	log.Println("Droplets deployed.")

	sig := make(chan os.Signal)
	done := make(chan bool)
	signal.Notify(sig, os.Interrupt)

	go func(sig chan os.Signal, done chan bool, machines []Machine, client *godo.Client) {
		<-sig
		fmt.Println()
		cleanup(machines, client)
		log.Println("Exiting...")
		os.Exit(0)
	}(sig, done, machines, client)

	log.Println("Please CTRL-C to destroy droplets")

	log.Println("Waiting for droplets to finish provisioning")
	continueTime := time.Now().Add(time.Second * 100).Round(time.Second)
	for time.Now().Before(continueTime.Add(time.Second * -1)) {
		log.Printf("Waiting %v seconds...\n", continueTime.Sub(time.Now().Round(time.Second)).Seconds())
		time.Sleep(time.Second * 10)
	}

	var readyMachines []*Machine
	for i := range machines {
		m := &machines[i]

		m.Index = i + 1
		m.Template = *cmd

		sshConfig := &ssh.ClientConfig{
			User: "root",
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(sshSigner),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		m.SSHConfig = sshConfig

		if err := m.GetIPs(client); err != nil {
			m.Printf("Error getting the IPv4 address of droplet: %v", err)
		}

		m.Printf("IPv4 Address: %s", m.IPv4)

		if !m.IsReady() {
			m.Println("Droplet not ready yet. Skipping...")
		}

		readyMachines = append(readyMachines, m)
		m.Println("Droplet ready")
	}

	var portBuckets []string
	if *ports != "" {
		// portBuckets, err = csrange.SplitString(len(readyMachines), *ports) // use non-contiguous csr's
		portBuckets, err = csrange.SplitStringContig(len(readyMachines), *ports)
		if err != nil {
			log.Fatalf("Error parsing -ports: %v\n", err)
		}
	}

	var wg sync.WaitGroup

	for i, m := range readyMachines {
		wg.Add(1)
		go func(idx int, m *Machine) {
			m.Println("Establishing SSH connection...")
			client, err := ssh.Dial("tcp", m.IPv4+":22", m.SSHConfig)
			if err != nil {
				m.Println("Error establishing SSH connection. Results may be incomplete. Please exit and try again")
				wg.Done()
				return
			}

			m.Println("SSH connection established.")

			m.SSHClient = client

			if *pkg != "" {
				m.Println("Installing packages")
				m.InstallPackages(strings.Split(*pkg, ","))
			}

			if *ports != "" {
				m.Ports = portBuckets[idx]
			}

			command, err := m.Command()
			if err != nil {
				m.Printf("Error preparing command template: %v\n", err)
			}

			m.Printf("Running command: %v\n", command)

			fnameFmt := "out-%0" + fmt.Sprintf("%d", len(fmt.Sprintf("%d", *count))) + "d.xml"
			fname := fmt.Sprintf(fnameFmt, m.Index)
			err = m.RunCommand(fname)
			if err != nil {
				m.Printf("Error running command: %v", err)
			}

			m.Printf("Results: %s\n", fname)
			m.Println("Done. Exiting...")

			wg.Done()
		}(i, m)
	}

	wg.Wait()
	log.Println("Done. All commands have been run.")
	log.Println("Please CTRL-C to destroy droplets")
	<-done
}

func regionMap(slugs []string, regions string, count int) (map[string]int, error) {
	allowedSlugs := strings.Split(regions, ",")
	regionCountMap := make(map[string]int)

	if regions != "*" {
		for _, s := range slugs {
			for _, a := range allowedSlugs {
				if s == a {
					if len(regionCountMap) == count {
						break
					}
					regionCountMap[s] = 0
				}
			}
		}
	} else {
		for _, s := range slugs {
			if len(regionCountMap) == count {
				break
			}
			regionCountMap[s] = 0
		}
	}

	if len(regionCountMap) == 0 {
		return regionCountMap, errors.New("There are no regions to use")
	}

	perRegionCount := count / len(regionCountMap)
	perRegionCountRemainder := count % len(regionCountMap)

	for k := range regionCountMap {
		regionCountMap[k] = perRegionCount
	}

	if perRegionCountRemainder != 0 {
		c := 0
		for k, v := range regionCountMap {
			if c >= perRegionCountRemainder {
				break
			}
			regionCountMap[k] = v + 1
			c++
		}
	}
	return regionCountMap, nil
}

func openSSHKey(privKeyPath string) (ssh.Signer, error) {
	pemBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read ssh key file: %v", err)
	}

	// Check if encrypted
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("PEM formatted block not found")
	}
	encrypted := strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")

	var signer ssh.Signer

	if encrypted {
		fmt.Printf("Enter Password (%v): ", privKeyPath)
		pw, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return nil, fmt.Errorf("error capturing password: %v\n", err)
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, pw)
		if err != nil {
			return nil, fmt.Errorf("error parsing encrypted private key: %v\n", err)
		}
	} else {
		signer, err = ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing private key: %v\n", err)
		}
	}

	return signer, nil
}

func cleanup(machines []Machine, client *godo.Client) {
	for _, m := range machines {
		if err := m.Destroy(client); err != nil {
			log.Printf("Could not delete droplet name: %s\n", m.Name)
		} else {
			log.Printf("Deleted droplet name: %s", m.Name)
		}
	}
}
