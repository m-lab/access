package address

import (
	"testing"

	"github.com/m-lab/go/osx"
)

func TestIPManager_Start(t *testing.T) {
	ip4tables = "./testdata/iptables"
	ip4tablesSave = "./testdata/iptables-save"
	ip6tables = "./testdata/ip6tables"
	ip6tablesSave = "./testdata/ip6tables-save"

	tests := []struct {
		name              string
		iptablesSaveCode  string
		iptablesCode      string
		iptablesSaveCode6 string
		iptablesCode6     string
		wantErr           bool
	}{
		{
			name:              "success",
			iptablesSaveCode:  "0",
			iptablesCode:      "0",
			iptablesSaveCode6: "0",
			iptablesCode6:     "0",
		},
		{
			name:              "error-save-ipv4-failure",
			iptablesSaveCode:  "1",
			iptablesCode:      "0",
			iptablesSaveCode6: "0",
			iptablesCode6:     "0",
			wantErr:           true,
		},
		{
			name:              "error-save-ipv6-failure",
			iptablesSaveCode:  "0",
			iptablesCode:      "0",
			iptablesSaveCode6: "1",
			iptablesCode6:     "0",
			wantErr:           true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &IPManager{}
			defer osx.MustSetenv("IPTABLES_SAVE_EXIT", tt.iptablesSaveCode)()
			defer osx.MustSetenv("IPTABLES_EXIT", tt.iptablesCode)()

			defer osx.MustSetenv("IP6TABLES_SAVE_EXIT", tt.iptablesSaveCode6)()
			defer osx.MustSetenv("IP6TABLES_EXIT", tt.iptablesCode6)()

			if err := r.Start("1234", "eth0"); (err != nil) != tt.wantErr {
				t.Errorf("IPManager.Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIPManager_Stop(t *testing.T) {
	ip4tablesRestore = "./testdata/iptables-restore"
	ip6tablesRestore = "./testdata/iptables-restore"

	tests := []struct {
		name        string
		origRules4  []byte
		origRules6  []byte
		restoreExit string
		wantErr     bool
	}{
		{
			name:        "success",
			restoreExit: "0",
			origRules4:  []byte("sample-input-message"),
			origRules6:  []byte(""),
		},
		{
			name:    "failure-to-restore-empty-rules",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &IPManager{origRules4: tt.origRules4, origRules6: tt.origRules6}
			defer osx.MustSetenv("IPTABLES_RESTORE_EXIT", tt.restoreExit)()

			b, err := r.Stop()
			if (err != nil) != tt.wantErr {
				t.Errorf("IPManager.Stop() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if string(b) != "sample-input-message" {
				t.Errorf("IPManager.Stop() wrong message = %q, want %q", string(b), "sample-input-message")
			}
		})
	}
}
