package chanio

import "io"

// ReadOnce reads from the given reader once and closes the returned channel. All data is discarded.
func ReadOnce(r io.Reader) <-chan struct{} {
	c := make(chan struct{})
	go func() {
		b := make([]byte, 1)
		// Block on read. Will return on EOF or when client sends data (which is discarded).
		r.Read(b)
		// Close channel to send reader a signal.
		close(c)
	}()
	return c
}
