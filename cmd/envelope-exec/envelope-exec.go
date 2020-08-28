package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"time"

	"github.com/gorilla/websocket"
	"github.com/m-lab/access/chanio"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/logx"
	"github.com/m-lab/go/rtx"
	v2 "github.com/m-lab/locate/api/v2"
)

var (
	locate      = flagx.MustNewURL("https://locate-dot-mlab-sandbox.appspot.com/v2/nearest/")
	privKey     flagx.FileBytes
	machine     string
	service     string
	timeout     time.Duration
	envelopeKey string
	logFatalf   = log.Fatalf
)

func init() {
	setupFlags()
}

func setupFlags() {
	flag.Var(&locate, "locate-url", "URL Prefix for locate service")
	flag.StringVar(&service, "service", "wehe/replay", "<name>/<datatype> to request")
	flag.DurationVar(&timeout, "timeout", 60*time.Second, "Complete request and command execution within timeout")
	flag.StringVar(&envelopeKey, "envelope-key", "wss://:4443/v0/envelope/access", "The key name to extract from the result URLs")
}

func mustRunCommandAsync(ctx context.Context, args []string, extraEnv []string) context.Context {
	ctx2, cancel2 := context.WithCancel(ctx)

	go func() {
		// Run command in background, and cancel context upon completion.
		defer cancel2()
		// Place the URL into the named environment variable for access by the command.
		logx.Debug.Println("Exec:", args)
		cmd := exec.CommandContext(ctx2, args[0], args[1:]...)
		cmd.Env = append(os.Environ(), extraEnv...)
		if logx.LogxDebug.Get() {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
		rtx.Must(cmd.Run(), "Failed to run %#v", args)
	}()

	return ctx2
}

func main() {
	flag.Parse()
	rtx.Must(flagx.ArgsFromEnvWithLog(flag.CommandLine, false), "Failed to read args from env")
	if len(flag.Args()) == 0 {
		logFatalf("ERROR: no command given to execute")
		return
	}

	// Prepare a context with absolute timeout for getting token and running command.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Construct locate URL and request.
	locate.Path = path.Join(locate.Path, service)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, locate.String(), nil)
	rtx.Must(err, "Failed to create request")

	// Issue Locate API request.
	resp, err := http.DefaultClient.Do(req)
	rtx.Must(err, "Failed to contact locate service")
	defer resp.Body.Close()

	// Read response body into v2.NearestResult.
	body, err := ioutil.ReadAll(resp.Body)
	rtx.Must(err, "Failed to read response")
	result := v2.NearestResult{}
	err = json.Unmarshal(body, &result)
	rtx.Must(err, "Failed to parse locate result")

	// Check for an application level error from the Locate API.
	if result.Error != nil {
		log.Fatalf("Request failed: %#v", result.Error)
	}

	// Attempt to open a connection to one of the envelope result URLs.
	conn, access, err := openWebsocket(ctx, &result)
	rtx.Must(err, "Failed to open websocket connection to results: %#v", result)
	defer conn.Close()

	// Prepare variables to inject into the command's environment.
	env := []string{
		"SERVICE_HOSTNAME=" + access.Hostname(),
		"SERVICE_URL=" + access.String(),
	}

	// The connection to the envelope is open. Commands are run
	// asynchronously. Commands get one chance to complete successfully.
	// Commands that exit with an error cause this process to exit early.
	ctx2 := mustRunCommandAsync(ctx, flag.Args(), env)

	// Wait for either the command context to expire (after command exits,
	// or runtime timeout expires), or the envelope connection to close
	// (envelope timeout).
	select {
	case <-ctx2.Done():
		return
	case <-chanio.ReadOnce(conn.UnderlyingConn()):
		return
	}
}

func openWebsocket(ctx context.Context, result *v2.NearestResult) (*websocket.Conn, *url.URL, error) {
	// Try each result until a connection to the envelope service succeeds.
	// Then, run the user-provided command once.
	for _, target := range result.Results {
		rawurl := target.URLs[envelopeKey]
		access, err := url.Parse(rawurl)
		if err != nil {
			return nil, nil, err
		}
		// Open websocket.
		logx.Debug.Println("Issue request to:", access.Hostname())
		headers := http.Header{}
		headers.Add("Sec-WebSocket-Protocol", "net.measurementlab.envelope")
		// TODO: permit appending additional parameters to envelope URL.
		conn, _, err := websocket.DefaultDialer.DialContext(ctx, access.String(), headers)
		if err != nil {
			// It's okay for one machine to reject the connection.
			// The for loop keeps trying the available results until one succeeds.
			continue
		}
		return conn, access, nil
	}
	return nil, nil, errors.New("Failed to open websocket conn from all results")
}
