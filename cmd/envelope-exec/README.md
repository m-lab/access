# envelope-exec Command Line Utility

The envelope-exec command executes a user-provided command that will connect
to a service running the M-Lab platform, behind the [access envelope][envelope].

Simply, envelope-exec contacts the [Locate API][locate-v2], to find a list of
nearby healthy service names, opens a websocket connection to one of the
access envelope URLs returned, and then executes a user-provided command.

The following describes the conventions the user-provided command should
support.

[locate-v2]: https://github.com/m-lab/locate/blob/master/USAGE.md
[envelope]: https://github.com/m-lab/access/blob/master/cmd/envelope/README.md

## Services Using the Access Envelope

Not all services on M-Lab use the access envelope. It is the users
responsibility to determine if this is the case before using envelope-exec.

The envelope-exec command will provide the target service URL and service
name in environment variables so that the user-provided command can target a
specific service and machine. It is up to the user-provided command to
include service-specific ports where required.

The envelope-exec command creates two environment variables:

* `SERVICE_URL` - the original websocket url to the access envelope.
* `SERVICE_HOSTNAME` - the target service hostname.

A service that uses the access envelope is `wehe/replay`.

```sh
go get github.com/m-lab/access/cmd/envelope-exec
# Show the variables available to user-provided commands.
envelope-exec bash -c "env"
# Run a replay using the $SERVICE_HOSTNAME provided the variables available to
# user-provided commands.
envelope-exec bash -c "python src/replay_client.py
  --pcap_folder=./replayTraces/Vimeo_12122018/
  --serverInstance=$SERVICE_HOSTNAME"
```
