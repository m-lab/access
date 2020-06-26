package address

import (
	"bytes"
	"flag"
	"fmt"
	"net"

	"github.com/m-lab/go/rtx"
	"gopkg.in/m-lab/pipe.v3"
)

var (
	iptables        string
	iptablesSave    string
	iptablesRestore string
)

func init() {
	// NOTE: because ip6tables is flag-compatible with iptables, these flags
	// support either ipv4 or ipv6 exclusively.
	// TODO: support both ipv4 and ip6tables.
	flag.StringVar(&iptables, "address.iptables", "/sbin/iptables",
		"The absolute path to the iptables command")
	flag.StringVar(&iptablesSave, "address.iptables-save", "/sbin/iptables-save",
		"The absolute path to the iptables-save command")
	flag.StringVar(&iptablesRestore, "address.iptables-restore", "/sbin/iptables-restore",
		"The absolute path to the iptables-restore command")
}

// Start initializes iptables with rules for managing device, while the envelope
// service runs on port.
//
// Current iptables rules are saved, removed, and replaced by rules fully
// managed by the IPManager. To restore the original iptables rules, call Stop()
// during shutdown.
func (r *IPManager) Start(port, device string) error {
	// Save original rules.
	origRules, err := pipe.Output(pipe.Exec(iptablesSave))
	if err != nil {
		return err
	}
	r.origRules = origRules

	// Collect commands to allow traffic from allowed (i.e. unmanaged) interfaces.
	//
	// NOTE: this finds and allows connections to all unmanaged devices. This
	// allows traffic to private and local networks. This is necessary for
	// intra-container communications on loopback and for monitoring traffic
	// over the private network.
	allowed := allowedInterfaces(device)

	startCommands := []pipe.Pipe{
		// Flushing existing rules does not change default policy.
		pipe.Exec(iptables, "--flush"),
		// Set default policy for INPUT chain to DROP packets. Dropping packets
		// guarantees that nothing gets in that should not. The following rules
		// selectively open access where necessary.
		pipe.Exec(iptables, "--policy", "INPUT", "DROP"),
	}

	startCommands = append(startCommands, allowed...)

	afterCommands := []pipe.Pipe{
		// Accept incoming connections to the envelope service HTTP(S) server.
		pipe.Exec(iptables,
			// Envelop service itself.
			"--append=INPUT", "--protocol=tcp", "--dport="+port, "--jump=ACCEPT"),
		pipe.Exec(iptables,
			// DNS
			"--append=INPUT", "--protocol=udp", "--dport=53", "--jump=ACCEPT"),
		pipe.Exec(iptables,
			// Established connections.
			"--append=INPUT", "--match=conntrack", "--ctstate=ESTABLISHED,RELATED", "--jump=ACCEPT"),

		// The last rule "rejects" packets, to send clients a signal that their
		// connection was refused rather than silently dropped.
		pipe.Exec(iptables, "--append=INPUT", "--jump=REJECT"),
	}

	commands := append(startCommands, afterCommands...)
	err = pipe.Run(
		pipe.Script("Setup iptables for managing access: "+device, commands...),
	)
	return err
}

// Stop restores the iptables rules originally found before running Start().
func (r *IPManager) Stop() ([]byte, error) {
	if r.origRules == nil {
		return nil, fmt.Errorf("cannot restore uninitialized rules")
	}
	b := bytes.NewBuffer(r.origRules)
	restore := pipe.Script("Restoring original iptables rules",
		pipe.Read(b),
		pipe.Exec(iptablesRestore),
	)
	return pipe.Output(restore)
}

func allowedInterfaces(name string) []pipe.Pipe {
	ifaces, err := net.Interfaces()
	rtx.Must(err, "failed to list interfaces")
	pipes := []pipe.Pipe{}
	for _, iface := range ifaces {
		if iface.Name != name {
			// NOTE: On M-Lab k8s deployments, `net1` is typically the public facing device.
			p := pipe.Exec(iptables, "--append=INPUT", "--in-interface="+iface.Name,
				"--protocol=all", "--jump=ACCEPT")
			pipes = append(pipes, p)
		}
	}
	return pipes
}
