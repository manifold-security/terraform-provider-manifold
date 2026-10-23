# Security policy

The provider holds an OIDC client secret and the access tokens it gets with it. If it can be made to leak them, send them somewhere other than your Manifold instance, or apply changes nobody planned, report it privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: the **Report a vulnerability** button on this repository's **Security** tab.

Do not open a public issue or pull request for a vulnerability.

Include the provider version (`terraform version` or `tofu version` lists it), the CLI and version you ran it with, and the smallest configuration that reproduces the problem. Leave real credentials and endpoints out.

## What happens next

We acknowledge a report within two weeks. Disclosure is coordinated with you: the details stay private until a fixed release is out, and the advisory credits you unless you ask us not to.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope:

- the client secret or an access token reaching any host other than the configured `endpoint` and `auth_domain`, or showing up in plan output, state or logs;
- a request going out over plain http to anything other than loopback, or following a redirect;
- an apply that changes or deletes a policy the plan didn't show, or overwrites a dashboard edit despite the `If-Match` check.

Out of scope: vulnerabilities in the Manifold platform or its management API. Report those to Manifold directly rather than here.
