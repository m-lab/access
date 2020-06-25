// Package address supports managing access for a small pool of IP subnets
// using iptables.
package address

import (
	"errors"
	"net"
	"time"

	"golang.org/x/sync/semaphore"

	"gopkg.in/m-lab/pipe.v3"
)

// IPManager supports granting IP subnet access using iptables or ip6tables.
type IPManager struct {
	*semaphore.Weighted
	origRules []byte
}

// ErrMaxConcurrent is returned when the max concurrent grants has already been reached.
var ErrMaxConcurrent = errors.New("max concurrent reached")

// NewIPManager creates a new instance that will allow granting up to max IP subnets
// concurrently. Due to overhead in iptable processing and the impact that could
// have on measurements, max should be small.
func NewIPManager(max int64) *IPManager {
	return &IPManager{
		Weighted: semaphore.NewWeighted(max),
	}
}

// Grant adds an iptables/ip6tables rule to allow packets from a subnet
// containing the given IP on the INPUT chain. On success, the caller must call
// Revoke to allow a new Grants in the future.
func (r *IPManager) Grant(ip net.IP) error {
	if !r.TryAcquire(1) {
		return ErrMaxConcurrent
	}

	// Note: use 'insert' (rather than 'append') to place the new rule first, to
	// a) cooperate with the rules in the environment, b) minimize the time a packet
	// stays in the chain handling logic.
	addRule := pipe.Script("Add rules to allow "+ip.String(), ipTable("insert", ip))
	err := pipe.RunTimeout(addRule, 10*time.Second)
	if err != nil {
		// Release semaphore before returning. Note: this assumes that iptables
		// cannot add a rule AND return an error.
		r.Release(1)
	}
	return err
}

// Revoke removes the iptables/ip6tables rule previously granted for the same IP.
func (r *IPManager) Revoke(ip net.IP) error {
	delRule := pipe.Script("Remove rule to allow "+ip.String(), ipTable("delete", ip))
	err := pipe.RunTimeout(delRule, 10*time.Second)
	if err == nil {
		// Only release semaphore if removing rule succeeds.
		// NOTE: if the rule is not removed, then an error represents a leak.
		r.Release(1)
	}
	return err
}

func ipTable(command string, ip net.IP) pipe.Pipe {
	// Parameters are the same for IPv4 and IPv6 addresses, but the command is not.
	cmd, subnet := cmdForIP(ip)
	return pipe.Exec(cmd, "--"+command+"=INPUT", "--source="+ip.String()+subnet, "--jump=ACCEPT")
}

func cmdForIP(ip net.IP) (string, string) {
	if ip.To4() != nil {
		return iptables, "/24"
	}
	return iptables, "/64"
}
