package controller

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/m-lab/go/rtx"

	"github.com/prometheus/procfs"
)

func TestTxController_Limit(t *testing.T) {
	tests := []struct {
		name     string
		limit    uint64
		current  uint64
		procPath string
		visited  bool
		wantErr  bool
	}{
		{
			name:     "success",
			procPath: "testdata/proc-success",
			visited:  true,
		},
		{
			name:     "reject",
			limit:    1,
			current:  2,
			procPath: "testdata/proc-success",
			visited:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			procPath = tt.procPath
			device = "eth0"
			maxRate = tt.limit

			pfs, err := procfs.NewFS(procPath)
			rtx.Must(err, "Failed to allocate procfs")

			tx := &TxController{
				device:   device,
				limit:    tt.limit,
				pfs:      pfs,
				period:   time.Millisecond,
				current:  tt.current,
				Enforced: Paths{"/": true},
			}

			visited := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				visited = true
			})
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rw := httptest.NewRecorder()

			tx.Limit(next).ServeHTTP(rw, req)

			if visited != tt.visited {
				t.Errorf("TxController.Limit() got %t, want %t", visited, tt.visited)
			}
		})
	}
}

func TestNewTxController(t *testing.T) {
	tests := []struct {
		name     string
		limit    uint64
		want     *TxController
		procPath string
		device   string
		enforced Paths
		wantErr  bool
	}{
		{
			name:     "failure",
			procPath: "testdata/proc-failure",
			device:   "eth0",
			enforced: Paths{},
			wantErr:  true,
		},
		{
			name:     "failure-nodevfile",
			procPath: "testdata/proc-nodevfile",
			device:   "eth0",
			enforced: Paths{},
			wantErr:  true,
		},
		{
			name:     "failure-nodevice",
			procPath: "testdata/proc-nodevice",
			device:   "eth0",
			enforced: Paths{},
			wantErr:  true,
		},
		{
			name:     "failure-nilpaths",
			procPath: "testdata/proc-success",
			device:   "eth0",
			enforced: nil,
			wantErr:  true,
		},
		{
			name:     "failure-nodevice",
			device:   "",
			enforced: Paths{},
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device = tt.device
			procPath = tt.procPath
			maxRate = tt.limit
			ctx := context.Background()
			got, err := NewTxController(ctx, tt.enforced)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTxController() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTxController() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTxController_Watch(t *testing.T) {
	tests := []struct {
		name         string
		limit        uint64
		want         *TxController
		procPath     string
		badProc      string
		wantWatchErr bool
	}{
		{
			name:     "success-zero-rate",
			procPath: "testdata/proc-success",
			limit:    0,
		},
		{
			name:         "success-rate",
			procPath:     "testdata/proc-success",
			limit:        1,
			wantWatchErr: true,
		},
		{
			name:         "success-error-reading-proc",
			procPath:     "testdata/proc-success",
			limit:        1,
			badProc:      "testdata/proc-nodevfile",
			wantWatchErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device = "eth0"
			procPath = tt.procPath
			maxRate = tt.limit

			pfs, err := procfs.NewFS(procPath)
			rtx.Must(err, "Failed to allocate procfs")

			// NewTxController starts Watch in a goroutine. But, we want to call
			// tx.Watch explicitly below, so create a literal tx controller.
			tx := &TxController{
				device: device,
				limit:  maxRate,
				pfs:    pfs,
				period: time.Millisecond,
			}

			if tt.badProc != "" {
				pfs, err := procfs.NewFS(tt.badProc)
				rtx.Must(err, "Failed to allocate procfs for %q", tt.badProc)
				// New used a good path, but we replace the pfs with a bad proc record.
				tx.pfs = pfs
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			err = tx.Watch(ctx)
			if (err != nil) != tt.wantWatchErr {
				t.Errorf("Watch() error = %v, wantErr %v", err, tt.wantWatchErr)
				return
			}
		})
	}
}

type fakeListener struct {
	conn   fakeConn
	err    error
	closed int
}

type fakeConn struct {
	net.TCPConn
	closed int
}

func (c *fakeConn) Close() error {
	c.closed++
	return nil
}

func (f *fakeListener) Accept() (net.Conn, error) {
	return &f.conn, f.err
}
func (f *fakeListener) Close() error {
	f.closed++
	return nil
}
func (f *fakeListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

func TestTxController_Accept(t *testing.T) {
	tests := []struct {
		name       string
		l          *fakeListener
		tx         *TxController
		wantClosed int
		wantErr    bool
	}{
		{
			name: "success-accepted",
			l:    &fakeListener{},
			tx: &TxController{
				current: 0,
				limit:   1,
			},
			wantClosed: 0,
		},
		{
			name: "success-rejected",
			l:    &fakeListener{conn: fakeConn{}},
			tx: &TxController{
				current: 2,
				limit:   1,
			},
			wantClosed: 1,
			wantErr:    true,
		},
		{
			name: "success-accept-with-nil-tx",
			l:    &fakeListener{conn: fakeConn{}},
			tx:   nil, // Accept should work even with a nil tx.
		},
		{
			name:    "error-accept-returns-error",
			l:       &fakeListener{err: errors.New("this is a fake accept error")},
			tx:      &TxController{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := tt.tx.Accept(tt.l)
			if (err != nil) != tt.wantErr {
				t.Errorf("TxController.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fc, ok := conn.(*fakeConn)
			if conn != nil && ok && fc.closed != tt.wantClosed {
				t.Errorf("TxController.Accept() failed to close conn; got %d, want %d", fc.closed, tt.wantClosed)
			}
		})
	}
}
