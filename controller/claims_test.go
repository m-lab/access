package controller

import (
	"context"
	"testing"

	"github.com/go-test/deep"
)

func TestGetCustomClaim(t *testing.T) {
	type custom struct {
		Foo string
	}
	val := &custom{Foo: "bar"}
	tests := []struct {
		name string
		ctx  context.Context
		want any
	}{
		{
			name: "no-claim-in-context",
			ctx:  context.Background(),
			want: nil,
		},
		{
			name: "with-custom-claim",
			ctx:  SetCustomClaim(context.Background(), val),
			want: val,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetCustomClaim(tt.ctx)
			if diff := deep.Equal(got, tt.want); diff != nil {
				t.Errorf("GetCustomClaim() mismatch: %v", diff)
			}
		})
	}
}
