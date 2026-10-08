# bulkhead

Run a command, or a long-running agent process, confined by
[bubblewrap](https://github.com/containers/bubblewrap). Killing a job kills the whole sandbox,
not just the first process in it.

Linux only. It needs the `bwrap` program installed and a kernel that allows unprivileged user
namespaces. bubblewrap runs as a separate process and is never linked.

## What a confined command gets

- the host filesystem read-only, with `/home`, `/root`, `/run`, `/tmp` and the like emptied
- one writable place: the working directory you give it (never `/`)
- no network, unless you ask for the host's (or, for an agent, one forwarded endpoint)
- a cleared environment rebuilt from an allowlist, with a fixed `PATH` and `HOME`
- its own session, no capabilities, and death with its parent

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

## Tests

`cargo test` runs everything that needs no privileges. The tests that use a real `bwrap` skip,
with a printed reason, where it is missing or the kernel refuses user namespaces.

## License

MIT OR Apache-2.0.
