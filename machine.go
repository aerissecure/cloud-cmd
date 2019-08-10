package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"golang.org/x/crypto/ssh"

	"github.com/digitalocean/godo"
)

// Machine is just a wrapper around a created droplet.
type Machine struct {
	ID        int
	Index     int // Index (starting with 1) for the order droplet was created
	Name      string
	IPv4      string
	SSHActive bool
	Stderr    *bufio.Reader
	Listener  string
	CMD       *exec.Cmd

	SSHConfig *ssh.ClientConfig
	SSHClient *ssh.Client
	Template  string
	Ports     string
}

// Println uses fmt.Println to log to the console, formatted for this machine.
func (m *Machine) Println(a ...interface{}) {
	a = append([]interface{}{fmt.Sprintf("%s (%d):", m.Name, m.Index)}, a...)
	log.Println(a...)
}

// Printf uses fmt.Printf to log to the console, formatted for this machine.
func (m *Machine) Printf(format string, a ...interface{}) {
	log.Printf(fmt.Sprintf("%s (%d): %s", m.Name, m.Index, format), a...)
}

// IsReady ensures that the machine has an IP address.
func (m *Machine) IsReady() bool {
	return m.IPv4 != ""
}

// GetIPs populates the IPv4 address of the machine.
func (m *Machine) GetIPs(client *godo.Client) error {
	droplet, _, err := client.Droplets.Get(context.Background(), m.ID)
	if err != nil {
		return err
	}
	m.IPv4, err = droplet.PublicIPv4()
	if err != nil {
		return err
	}
	return nil
}

func (m *Machine) InstallPackages(packages []string) error {
	session, err := m.SSHClient.NewSession()
	if err != nil {
		return fmt.Errorf("error creating ssh session: %v", err)
	}
	out, err := session.CombinedOutput("apt-get update")
	if err != nil {
		return fmt.Errorf("error running apt-get update command: %v", err)
	}
	_ = out
	// if session.CombinedOutput err == nil, command returned with zero exit status
	// we only really need out in verbose mode or on error
	// m.Println(string(out))
	session.Close()

	session, err = m.SSHClient.NewSession()
	if err != nil {
		return fmt.Errorf("error creating ssh session: %v", err)
	}
	out, err = session.CombinedOutput("apt-get install -y " + strings.Join(packages, " "))
	if err != nil {
		return fmt.Errorf("error running apt-get install command: %v", err)
	}
	_ = out
	// if session.CombinedOutput err == nil, command returned with zero exit status
	// we only really need out in verbose mode or on error
	// m.Println(string(out))
	session.Close()

	return nil
}

// RunCommand runs the templated command on the remote host. This should
// be launched in a go routine using a waitgroup.
func (m *Machine) RunCommand(filename string) error {
	output, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file for stdout: %v", err)
	}
	session, err := m.SSHClient.NewSession()
	if err != nil {
		return fmt.Errorf("error creating ssh session: %v", err)
	}
	session.Stdout = output
	// hook up a stderr pipe to use the machine's println to record the status. i think launching this
	// in a goroutine and then terminating the goroutine on eof would be good enough.

	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}
	m.Stderr = bufio.NewReader(stderr)
	go m.PrintStdError()

	cmd, err := m.Command()
	if err != nil {
		return fmt.Errorf("error creating templated command: %v", err)
	}

	if err = session.Start(cmd); err != nil {
		return fmt.Errorf("error running command: %v", err)
	}

	return session.Wait()
}

// Command generates the command to be run on the remote hosting using the defined Template.
func (m *Machine) Command() (string, error) {
	vars := map[string]interface{}{
		"ports": m.Ports,
		"index": m.Index,
		"ip":    m.IPv4,
		"name":  m.Name,
	}
	var cmd bytes.Buffer
	t, err := template.New("").Parse(m.Template)
	if err != nil {
		return "", fmt.Errorf("error parsing template: %v", err)
	}
	err = t.Execute(&cmd, vars)
	if err != nil {
		return "", fmt.Errorf("error executing template: %v", err)
	}
	return cmd.String(), nil
}

// StartSSHProxy starts a socks proxy on 127.0.0.1 or the desired port.
func (m *Machine) StartSSHProxy(port, sshKeyLocation string) error {
	m.Listener = port
	m.CMD = exec.Command("ssh", "-N", "-D", port, "-o", "StrictHostKeyChecking=no", "-i", sshKeyLocation, fmt.Sprintf("root@%s", m.GetIP()))
	stderr, err := m.CMD.StderrPipe()
	if err != nil {
		return err
	}
	m.Stderr = bufio.NewReader(stderr)
	if err := m.CMD.Start(); err != nil {
		return err
	}
	m.SSHActive = true
	return nil
}

// Destroy deletes the droplet.
func (m *Machine) Destroy(client *godo.Client) error {
	_, err := client.Droplets.Delete(context.Background(), m.ID)
	return err
}

// GetIP returns the IPv4 address.
func (m *Machine) GetIP() string {
	return m.IPv4
}

func dropletsToMachines(droplets []godo.Droplet) []Machine {
	m := []Machine{}
	for _, d := range droplets {
		m = append(m, Machine{
			ID:   d.ID,
			Name: d.Name,
		})
	}
	return m
}

// PrintStdError reads from stderr from ssh and prints it to stdout.
func (m *Machine) PrintStdError() {
	// str, err := m.Stderr.ReadString('\n')
	// fmt.Printf("READ STRING: %q, err: %v\n", str, err)
	for {
		str, err := m.Stderr.ReadString('\n')
		if str != "" {
			m.Printf("2>: %s", str)
		}
		if err == io.EOF {
			return
		}
	}
}

func printProxyChains(machines []Machine) {
	for _, m := range machines {
		fmt.Printf("socks5 127.0.0.1 %s\n", m.Listener)
	}
}

func printSocksd(machines []Machine) {
	fmt.Printf("\"upstreams\": [\n")
	for i, m := range machines {
		fmt.Printf("{\"type\": \"socks5\", \"address\": \"127.0.0.1:%s\"}", m.Listener)
		if i < len(machines)-1 {
			fmt.Printf(",\n")
		}
	}
	fmt.Printf("\n]\n")
}
