# CLAUDE.md — robotico-ci-public

The public half of Robotico's CI: building blocks that every repository of the organisation, public ones included,
may run. Today that is the secret scan (gitleaks). Everything that needs internal names, tokens or reports stays in the
private `robotico-ci`.

## Data classes and trust levels

Level: public (set by Lukas on 2026-11-08, repository created as robotico-ci-public). Extensions: none.
Before every commit, read robotico-core:data-classes: what may be committed here and, above all, what may not.
Nothing internal goes here: no hostnames, internal URLs, people, customer or business data, no ticket texts.
