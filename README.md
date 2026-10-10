# Guardian agent-windows

Windows Guardian agent (service, user agent, MSI).

Depends on sibling checkout of `agent-common` at `../agent-common`.

## Releases

Pushing a `vX.Y.Z` tag (or running the **Release** workflow) builds and attaches:

- `guardian-agent-x86_64-pc-windows-msvc.msi` + `.sha256`

Successful tag builds also dispatch the artifact URLs to the versions feed.
