package address

import (
	"bytes"
	"net"

	"github.com/m-lab/go/rtx"
	"gopkg.in/m-lab/pipe.v3"
)

// Start initializes iptables rules for managing device, while the envelope
// service runs on the given port.
//
// Current iptables rules are saved, removed and replaced by rules fully managed
// by the IPManager. To restore the original iptables rules, call Stop() during
// shutdown.
func (r *IPManager) Start(port, device string) error {
	// TODO: support ip6tables also.

	// Save original rules.
	origRules, err := pipe.Output(pipe.Exec("iptables-save"))
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
		pipe.Exec("iptables", "--flush"),
		// Set default policy for INPUT chain to DROP packets. Dropping packets
		// guarantees that nothing gets in that should not. The following rules
		// selectively open access where necessary.
		pipe.Exec("iptables", "--policy", "INPUT", "DROP"),
	}

	startCommands = append(startCommands, allowed...)

	afterCommands := []pipe.Pipe{
		// Accept incoming connections to the envelope service HTTP(S) server.
		pipe.Exec("iptables", "--append=INPUT", "--protocol=tcp", "--dport="+port, "--jump=ACCEPT"),                    // Envelope service.
		pipe.Exec("iptables", "--append=INPUT", "--protocol=udp", "--dport=53", "--jump=ACCEPT"),                       // DNS
		pipe.Exec("iptables", "--append=INPUT", "--match=conntrack", "--ctstate=ESTABLISHED,RELATED", "--jump=ACCEPT"), // Established connections.

		// The last rule "rejects" packets, to send clients a signal that their
		// connection was refused rather than silently dropped.
		pipe.Exec("iptables", "--append=INPUT", "--jump=REJECT"),
	}

	commands := append(startCommands, afterCommands...)
	err = pipe.Run(
		//out, errs, err := pipe.DividedOutput(
		pipe.Script("Setup iptables for managing access: "+device, commands...),
	)
	// fmt.Println(string(out), string(errs))
	return err
	// return pipe.Run(
}

// Stop restores the iptables rules originally found before running Start().
func (r *IPManager) Stop() error {
	if r.origRules == nil {
		return nil
	}
	b := bytes.NewBuffer(r.origRules)
	restore := pipe.Script("Restorin original iptables rules",
		pipe.Read(b),
		pipe.Exec("iptables-restore"),
	)
	return pipe.Run(restore)
}

func allowedInterfaces(name string) []pipe.Pipe {
	ifaces, err := net.Interfaces()
	rtx.Must(err, "failed to list interfaces")
	pipes := []pipe.Pipe{}
	for _, iface := range ifaces {
		if iface.Name != name {
			// NOTE: On M-Lab k8s deployments, `net1` is typically the public facing device.
			p := pipe.Exec("iptables", "--append=INPUT", "--in-interface="+iface.Name,
				"--protocol=all", "--jump=ACCEPT")
			pipes = append(pipes, p)
		}
	}
	return pipes
}
