package address

import (
	"net"
	"sync"
	"testing"

	"github.com/m-lab/go/osx"
	"github.com/m-lab/go/rtx"
)

func TestIPManager_Grant(t *testing.T) {
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
			name:       "success-ipv4",
			max:        1,
			ip:         net.ParseIP("127.0.0.1"),
			grantExit:  "0",
			revokeExit: "0",
		},
		{
			name:       "success-ipv6",
			max:        1,
			ip:         net.ParseIP("2002::1"),
			grantExit:  "0",
			revokeExit: "0",
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
			grantExit:     "0",
			revokeExit:    "1", // Make iptables exit with error during revoke.
			wantRevokeErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// NOTE: the fake iptables commands read and exit using the EXIT environment.
			defer osx.MustSetenv("IPTABLES_EXIT", tt.grantExit)()
			defer osx.MustSetenv("IP6TABLES_EXIT", tt.grantExit)()

			if tt.ip.To4() != nil {
				ip4tables = "./testdata/iptables"
			} else {
				ip6tables = "./testdata/ip6tables"
			}

			r := NewIPManager(tt.max)
			if err := r.Grant(tt.ip); (err != nil) != tt.wantGrantErr {
				t.Errorf("IPGranter.Grant() error = %v, wantErr %v", err, tt.wantGrantErr)
				return
			}
			if tt.wantGrantErr {
				return
			}

			defer osx.MustSetenv("IPTABLES_EXIT", tt.revokeExit)()
			if err := r.Revoke(tt.ip); (err != nil) != tt.wantRevokeErr {
				t.Errorf("IPGranter.Revoke() error = %v, wantErr %v", err, tt.wantRevokeErr)
			}
		})
	}
}

func TestIPManager(t *testing.T) {
	ip4tables = "./testdata/iptables"
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

// TestNullManager verifies that the NullManager does nothing.
func TestNullManager(t *testing.T) {
	t.Run("null-manager", func(t *testing.T) {
		r := &NullManager{}
		if err := r.Grant(net.ParseIP("127.0.0.1")); err != nil {
			t.Errorf("NullManager.Grant() error = %v, want nil", err)
		}
		if err := r.Revoke(net.ParseIP("127.0.0.1")); err != nil {
			t.Errorf("NullManager.Revoke() error = %v, want nil", err)
		}
		if err := r.Start("1234", "eth0"); err != nil {
			t.Errorf("NullManager.Start() error = %v, want nil", err)
		}
		if _, err := r.Stop(); err != nil {
			t.Errorf("NullManager.Stop() error = %v, want nil", err)
		}
	})
}
