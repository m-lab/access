package main

import (
	"context"
	"encoding/json"
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
	locate    = flagx.MustNewURL("https://locate-dot-mlab-sandbox.appspot.com/v2/nearest/")
	privKey   flagx.FileBytes
	machine   string
	service   string
	timeout   time.Duration
	envKey    string
	logFatalf = log.Fatalf
)

func init() {
	setupFlags()
}

func setupFlags() {
	flag.Var(&locate, "locate-url", "URL Prefix for locate service")
	flag.StringVar(&service, "service", "wehe/replay", "<name>/<datatype> to request")
	flag.DurationVar(&timeout, "timeout", 60*time.Second, "Complete request and command execution within timeout")
	flag.StringVar(&envKey, "env-key", "wss:///v0/envelope/access", "The key name to extract from the result URLs")
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

	// Read response body into v2.QueryResult.
	body, err := ioutil.ReadAll(resp.Body)
	rtx.Must(err, "Failed to read response")
	result := v2.QueryResult{}
	err = json.Unmarshal(body, &result)
	rtx.Must(err, "Failed to parse locate result")

	// Check for an application level error from the Locate API.
	if result.Error != nil {
		log.Fatalf("Request failed: %#v", result.Error)
	}

	// For each result returned
	for _, target := range result.Results {
		rawurl := target.URLs[envKey]
		access, err := url.Parse(rawurl)
		rtx.Must(err, "Failed to parse URL using key %s: %#v", envKey, target.URLs)

		// Open websocket.
		logx.Debug.Println("Issue request to:", access.Hostname())
		headers := http.Header{}
		headers.Add("Sec-WebSocket-Protocol", "net.measurementlab.envelope")
		// TODO: permit appending additional parameters to envelope URL.
		conn, _, err := websocket.DefaultDialer.DialContext(ctx, access.String(), headers)
		if err != nil {
			// It's okay for one machine to reject the connection.
			continue
		}
		rc := conn.UnderlyingConn()
		defer rc.Close()

		// Prepare variables to inject into the command's environment.
		env := []string{
			"SERVICE_HOSTNAME=" + access.Hostname(),
			"SERVICE_URL=" + access.String(),
		}

		// The connection to the envelope is open; Commands only get one chance
		// to complete successfully. commands that exit with an error cause this
		// process to exit early.
		ctx2 := mustRunCommandAsync(ctx, flag.Args(), env)

		select {
		case <-ctx2.Done():
			return
		case <-chanio.ReadOnce(rc):
			return
		}
	}
}
