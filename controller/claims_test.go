package controller

import (
	"context"
	"testing"

	"github.com/go-test/deep"
)

func TestGetIntegrationClaims(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want *IntegrationClaims
	}{
		{
			name: "nil-context",
			ctx:  nil,
			want: nil,
		},
		{
			name: "no-claims-in-context",
			ctx:  context.Background(),
			want: nil,
		},
		{
			name: "with-integration-claims",
			ctx: SetIntegrationClaims(context.Background(), &IntegrationClaims{
				IntegrationID: "test-int",
				KeyID:         "ki_test",
			}),
			want: &IntegrationClaims{
				IntegrationID: "test-int",
				KeyID:         "ki_test",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetIntegrationClaims(tt.ctx)
			if diff := deep.Equal(got, tt.want); diff != nil {
				t.Errorf("GetIntegrationClaims() mismatch: %v", diff)
			}
		})
	}
}
