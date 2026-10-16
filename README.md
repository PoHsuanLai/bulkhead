# bulkhead

Run a command, or a long-running agent process, confined by
[bubblewrap](https://github.com/containers/bubblewrap). Killing a job kills the whole sandbox,
not just the first process in it.

Linux only. It needs the `bwrap` program installed and a kernel that allows unprivileged user
namespaces. bubblewrap runs as a separate process and is never linked.

## What a confined command gets

- an allow-list root, read-only: `/usr`, `/etc` (minus password hashes, sudoers, host keys and
  saved network credentials), the `/bin` and `/lib*` links, and `/opt` or other paths only when
  you name them (`Hardening::opt`, `Hardening::extra_ro`); fresh in-memory `/tmp`, `/var/tmp`
  and `/run`; no `/home`, `/var`, `/mnt`, `/media`, `/sys`
- one writable place: the working directory you give it (never `/`)
- no network, unless you ask for the host's (or, for an agent, one forwarded endpoint, or a
  list of named hosts through a filtering proxy)
- a cleared environment rebuilt from an allowlist, with a fixed `PATH` and `HOME`
- its own session, no capabilities, and death with its parent
- resource limits (`Hardening::limits`): by default memory, process count and CPU seconds in a
  transient systemd user scope, and a size cap on every scratch directory. If the limits cannot
  be applied the sandbox is not created (`CannotSandbox::LimitsUnavailable`); running without
  them needs an explicit `LimitPolicy::Unlimited(AcceptNoLimits)`. `LimitPolicy::Rlimit` is the
  weaker choice for hosts with no user manager: CPU seconds and address space per process, and
  no cap on the number of processes

Requirement for callers: every file descriptor above 2 must be close-on-exec when a sandbox
starts (Rust's std, tokio and zbus already do this). Without `unsafe` the child cannot close
leftovers, so `start` and `agent_command` check `/proc/self/fd` and refuse with
`StartFault::InheritedFds` (`Hardening::fds` can allow it). The host network mode shares the host's
loopback services and abstract unix sockets and is unfiltered. The filtered modes are the forwarded
endpoint and the host allow-list (`NetworkMode::Allowlist`): an agent that needs the web gets named
hosts, not all or nothing.

A command never runs unsandboxed: when the sandbox cannot confine one (no `bwrap`, namespaces
refused, a bad working directory), `Shell` refuses and says why.

## Pieces

- `Sandbox` and `Job`: the seam. `BwrapSandbox` is the real one, `FakeSandbox` (in `fake`)
  records what it was asked and answers from a script, for tests.
- `Detected`: the startup probe, bubblewrap or the reason there is none.
- `Shell`: a table of running terminals over any sandbox: create, output, wait, kill, release.
- `redact`, `Tail`, `shown`: output is bounded, valid UTF-8, and secret-looking values are masked.
- `AgentRun`, `agent_bwrap_args`, `NetworkMode`, `forward`: confining a long-running agent
  process, including an endpoint-only network mode served by a small forwarder
  (`bulkhead-forward`, or your own binary calling `cli::forward_main`).
- `egress`: the allow-list mode. The agent's namespace has only a loopback; the same forwarder
  hands each connection to a unix socket, and `egress::Proxy` on the other end speaks HTTP proxy
  (`CONNECT host:port` and `http://` requests, nothing else). An `EgressPolicy` lists allowed and
  denied hosts (exact, or `*.domain` for subdomains; deny wins; ports 443 and 80 unless listed;
  an empty allow list is refused). The proxy resolves a name once, refuses any name with an
  address that is loopback, private, link-local, shared (100.64.0.0/10), multicast or
  unspecified unless that exact address is listed, and connects to the address it checked.
  `AgentRun::new` sets `HTTPS_PROXY`, `HTTP_PROXY` (both cases) and an empty `NO_PROXY`. It
  filters by name, not content: an allowed host still receives whatever the agent sends it.
- `enter` and `bulkhead-enter`: an optional exec stage (`AgentRun::with_landlock`) that bubblewrap
  runs first. It applies a Landlock ruleset to itself (read and execute where the root is read-only,
  write only in the workspace and the private scratch places, TCP connect only to the forwarder's
  port or nowhere), prints `bulkhead-enter: landlock=full|files-only|none` on standard error
  (`LandlockLevel::from_report_line` reads it), and execs the agent. On a kernel without Landlock
  or without its network rules it still runs the agent, and says so in that line.
  The Landlock calls (`enter::apply`, `enter::enter_main`, the binary) are behind the `landlock`
  feature, off by default: a crate that only builds the command line links no sandbox library.

## Ubuntu 24.04 and later: AppArmor

Ubuntu sets `kernel.apparmor_restrict_unprivileged_userns=1`, so an unprivileged `bwrap` cannot
make a user namespace and no sandbox is created. bulkhead reads that setting and reports
`CannotSandbox::RestrictedByAppArmor` instead of the general "kernel refuses" reason. It still
fails closed. Two ways out; pick one.

Allow it for bubblewrap only. Save this as `/etc/apparmor.d/bwrap` and run
`sudo apparmor_parser -r /etc/apparmor.d/bwrap`:

```
abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,

  include if exists <local/bwrap>
}
```

Or switch the restriction off for the whole machine:

```
echo 'kernel.apparmor_restrict_unprivileged_userns = 0' | sudo tee /etc/sysctl.d/60-userns.conf
sudo sysctl --system
```

## Tests

`cargo test` runs everything that needs no privileges. The tests that use a real `bwrap` skip,
with a printed reason, where it is missing or the kernel refuses user namespaces.

## License

MIT OR Apache-2.0.
