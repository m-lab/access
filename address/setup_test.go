package address

import (
	"os"
	"testing"
)

func TestIPManager_Start(t *testing.T) {
	os.Setenv("PATH", "../cmd/envelope/testdata/:"+os.Getenv("PATH"))
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
			os.Setenv("IPTABLES_SAVE_EXIT", tt.iptablesSaveCode)
			os.Setenv("IPTABLES_EXIT", tt.iptablesCode)
			if err := r.Start("1234", "eth0"); (err != nil) != tt.wantErr {
				t.Errorf("IPManager.Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
