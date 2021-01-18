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
	ip4tables        string
	ip4tablesSave    string
	ip4tablesRestore string

	ip6tables        string
	ip6tablesSave    string
	ip6tablesRestore string

	icmpv4 = "icmp"
	icmpv6 = "icmpv6"
)

func init() {
	// NOTE: because ip6tables is flag-compatible with iptables.
	flag.StringVar(&ip4tables, "address.iptables", "/sbin/iptables",
		"The absolute path to the iptables command")
	flag.StringVar(&ip4tablesSave, "address.iptables-save", "/sbin/iptables-save",
		"The absolute path to the iptables-save command")
	flag.StringVar(&ip4tablesRestore, "address.iptables-restore", "/sbin/iptables-restore",
		"The absolute path to the iptables-restore command")

	flag.StringVar(&ip6tables, "address.ip6tables", "/sbin/ip6tables",
		"The absolute path to the iptables command")
	flag.StringVar(&ip6tablesSave, "address.ip6tables-save", "/sbin/ip6tables-save",
		"The absolute path to the iptables-save command")
	flag.StringVar(&ip6tablesRestore, "address.ip6tables-restore", "/sbin/ip6tables-restore",
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
	var err error
	r.origRules4, err = start(ip4tablesSave, ip4tables, port, device, icmpv4)
	if err != nil {
		return err
	}
	r.origRules6, err = start(ip6tablesSave, ip6tables, port, device, icmpv6)
	if err != nil {
		return err
	}
	return nil
}

func start(iptablesSave, iptables, port, device, protocol string) ([]byte, error) {
	origRules, err := pipe.Output(pipe.Exec(iptablesSave))
	if err != nil {
		return nil, err
	}

	// Collect commands to allow traffic from allowed (i.e. unmanaged) interfaces.
	//
	// NOTE: this finds and allows connections to all unmanaged devices. This
	// allows traffic to private and local networks. This is necessary for
	// intra-container communications on loopback and for monitoring traffic
	// over the private network.
	allowed := allowedInterfaces(iptables, device)

	startCommands := []pipe.Pipe{
		// Flushing existing rules does not change default policy.
		pipe.Exec(iptables, "--flush"),
		// Set default policy for INPUT chain to DROP packets. Dropping packets
		// guarantees that nothing gets in that should not. The following rules
		// selectively open access where necessary.
		pipe.Exec(iptables, "--policy", "INPUT", "DROP"),
	}

	startCommands = append(startCommands, allowed...)

	// Accept incoming connections to the envelope service HTTP(S) server.
	afterCommands := []pipe.Pipe{
		pipe.Exec(iptables,
			// Allow protocol specific ICMP traffic.
			"--append=INPUT", "--protocol="+protocol, "--jump=ACCEPT", "--wait"),
		pipe.Exec(iptables,
			// Envelope service itself.
			"--append=INPUT", "--protocol=tcp", "--dport="+port, "--jump=ACCEPT", "--wait"),
		pipe.Exec(iptables,
			// DNS
			"--append=INPUT", "--protocol=udp", "--dport=53", "--jump=ACCEPT", "--wait"),
		pipe.Exec(iptables,
			// Established connections.
			"--append=INPUT", "--match=conntrack", "--ctstate=ESTABLISHED,RELATED", "--jump=ACCEPT", "--wait"),

		// The last rule "rejects" packets, to send clients a signal that their
		// connection was refused rather than silently dropped.
		pipe.Exec(iptables, "--append=INPUT", "--jump=REJECT", "--wait"),
	}

	commands := append(startCommands, afterCommands...)
	err = pipe.Run(
		pipe.Script("Setup iptables for managing access: "+device, commands...),
	)
	return origRules, err
}

// Stop restores the iptables rules originally found before running Start().
func (r *IPManager) Stop() ([]byte, error) {
	b4, err := stop(ip4tablesRestore, r.origRules4)
	if err != nil {
		return b4, err
	}
	b6, err := stop(ip6tablesRestore, r.origRules6)
	return append(b4, b6...), err
}

func stop(iptablesRestore string, rules []byte) ([]byte, error) {
	if rules == nil {
		return nil, fmt.Errorf("cannot restore uninitialized rules")
	}
	b := bytes.NewBuffer(rules)
	restore := pipe.Script("Restoring original iptables rules",
		pipe.Read(b),
		pipe.Exec(iptablesRestore),
	)
	return pipe.Output(restore)
}

func allowedInterfaces(iptables, name string) []pipe.Pipe {
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
