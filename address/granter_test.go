package address

import (
	"net"
	"os"
	"sync"
	"testing"

	"github.com/m-lab/go/osx"
	"github.com/m-lab/go/rtx"
)

func TestIPManager_Grant(t *testing.T) {
	cwd, err := os.Getwd()
	rtx.Must(err, "Failed to get cwd")
	// Update PATH to prefer fake versions of iptables and ip6tables commands.
	resetPath := osx.MustSetenv("PATH", cwd+"/testdata:"+os.Getenv("PATH"))
	defer resetPath()

	tests := []struct {
		name          string
		max           int64
		ip            net.IP
		grantExit     string
		revokeExit    string
		wantGrantErr  bool
		wantRevokeErr bool
	}{
		{
			name: "success-ipv4",
			max:  1,
			ip:   net.ParseIP("127.0.0.1"),
		},
		{
			name: "success-ipv6",
			max:  1,
			ip:   net.ParseIP("2002::1"),
		},
		{
			name:         "error-max-concurent",
			max:          0, // Make first Grant fail.
			ip:           net.ParseIP("127.0.0.1"),
			wantGrantErr: true,
		},
		{
			name:         "error-grant-iptables",
			max:          1,
			ip:           net.ParseIP("127.0.0.1"),
			grantExit:    "1", // Make iptables exit with error during grant.
			wantGrantErr: true,
		},
		{
			name:          "error-revoke",
			max:           1,
			ip:            net.ParseIP("127.0.0.1"),
			revokeExit:    "1", // Make iptables exit with error during revoke.
			wantRevokeErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// NOTE: the fake iptables commands read and exit using the EXIT environment.
			resetExit := osx.MustSetenv("EXIT", tt.grantExit)
			defer resetExit()

			r := NewIPManager(tt.max)
			if err := r.Grant(tt.ip); (err != nil) != tt.wantGrantErr {
				t.Errorf("IPGranter.Grant() error = %v, wantErr %v", err, tt.wantGrantErr)
				return
			}
			if tt.wantGrantErr {
				return
			}

			resetExit = osx.MustSetenv("EXIT", tt.revokeExit)
			defer resetExit()
			if err := r.Revoke(tt.ip); (err != nil) != tt.wantRevokeErr {
				t.Errorf("IPGranter.Revoke() error = %v, wantErr %v", err, tt.wantRevokeErr)
			}
		})
	}
}

func TestIPManager(t *testing.T) {
	cwd, err := os.Getwd()
	rtx.Must(err, "Failed to get cwd")
	// Update PATH to prefer fake versions of iptables and ip6tables commands.
	resetPath := osx.MustSetenv("PATH", cwd+"/testdata:"+os.Getenv("PATH"))
	defer resetPath()

	wg := sync.WaitGroup{}
	mgr := NewIPManager(10)
	ip := net.ParseIP("127.0.0.2")
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			err := mgr.Grant(ip)
			if err == nil {
				// Only try to revoke when the grant was successful.
				rtx.Must(mgr.Revoke(ip), "Failed to revoke ip")
			}
			wg.Done()
		}()
	}
	wg.Wait()
}