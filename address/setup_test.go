package address

import (
	"testing"

	"github.com/m-lab/go/osx"
)

func TestIPManager_Start(t *testing.T) {
	iptables = "./testdata/iptables"
	iptablesSave = "./testdata/iptables-save"

	tests := []struct {
		name             string
		iptablesSaveCode string
		iptablesCode     string
		wantErr          bool
	}{
		{
			name:             "success",
			iptablesSaveCode: "0",
			iptablesCode:     "0",
		},
		{
			name:             "success",
			iptablesSaveCode: "1",
			iptablesCode:     "0",
			wantErr:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &IPManager{}
			defer osx.MustSetenv("IPTABLES_SAVE_EXIT", tt.iptablesSaveCode)()
			defer osx.MustSetenv("IPTABLES_EXIT", tt.iptablesCode)()

			if err := r.Start("1234", "eth0"); (err != nil) != tt.wantErr {
				t.Errorf("IPManager.Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIPManager_Stop(t *testing.T) {
	iptablesRestore = "./testdata/iptables-restore"

	tests := []struct {
		name        string
		origRules   []byte
		restoreExit string
		wantErr     bool
	}{
		{
			name:        "success",
			restoreExit: "0",
			origRules:   []byte("sample-input-message"),
		},
		{
			name:      "failure-to-restore-empty-rules",
			origRules: nil,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &IPManager{origRules: tt.origRules}
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
