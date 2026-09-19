# Project History

TAR Vault Sync began with a familiar problem: a development machine is more
than a source-code checkout.

I work on many projects and tasks on the same computer. Each one gradually
collects the things that make it usable: editor settings, local tooling,
Docker configuration, project files, scripts, credentials, environment
variables, and the small pieces of context that turn an empty folder into a
working environment. Rebuilding that environment from scratch is possible,
but it is rarely quick. It is also the kind of repeated work that is easy to
postpone.

My development environment is deliberately lightweight, portable, and simple.
I described that approach in [My Development Environment: A Lightweight,
Portable, and Simple Approach](https://fmarslan.com/en/2025/12/01/my-development-environment-a-lightweight-portable-and-simple-approach.html).
Even with that foundation, restoring several independent workspaces still
requires time and attention. Every project can have different tools,
containers, local files, conventions, and configuration. The more workspaces
there are, the more expensive it becomes to prepare a new machine or recover
quickly after a problem.

The natural answer is backup. A project workspace should be easy to recover
online so that a developer can restore it, prepare the necessary environment,
and continue working. But a real workspace also contains secrets, and that is
where a normal backup strategy stops being enough.

Secrets appear in many forms. They may be Docker environment variables,
application settings, passwords, API keys, certificate files, private keys,
or Git credentials. They may live in files that are useful to restore but are
not safe to upload as ordinary backup data. Simply copying every file to the
cloud would be convenient, but convenience cannot be allowed to turn private
material into an exposed archive.

There are many secret-management tools, and each solves an important part of
this problem. However, I could not find one that fit the complete practical
need: working across different development environments while handling the
different forms secrets take in day-to-day work. I wanted a tool that could
support configuration for Docker, passwords, files, and Git credentials,
without treating them all as the same kind of value or requiring secrets to be
stored alongside a normal workspace backup.

That gap is why TAR Vault Sync exists.

The project is built around a local-first idea. Project setup and
secret-free configuration can travel with a workspace, while secret values
remain in approved secret providers or encrypted vault payloads. A machine
should be able to recover its environment without turning backups, logs, or
local state into another place where secrets can leak. The goal is not only to
move values from one place to another; it is to make restoring a working
development environment practical while preserving clear security boundaries.

TAR Vault Sync is also an experiment in how software can be developed in the
age of AI agents. The project is being developed with AI to serve a real
personal need, and AI agents are intended to be contributors as well. This is
not an attempt to avoid the future of software development. It is an attempt
to learn how to work responsibly with it: to give agents clear constraints,
to keep security decisions explicit, and to use them to improve a useful tool
without losing ownership of the problem it solves.

If TAR Vault Sync is useful for your own work, you are welcome to adapt it and
contribute with your own AI agents. Different developers will have different
workspaces, providers, tools, and security requirements. The shared purpose is
simple: make it easier to restore the environments we depend on, while keeping
the secrets inside them protected.
