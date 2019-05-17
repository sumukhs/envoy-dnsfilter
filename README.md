# Envoy Dns filter
This project implements a L4 Udp Filter based on [envoy proxy](https://github.com/envoyproxy). 
The structure of the repo is adopted from the sample ['echo2'](https://github.com/envoyproxy/envoy-filter-example) filter example.

## Building

To build the Envoy static binary:

1. `git submodule update --init`
2. `bazel build //:envoy`

## Testing

To run the dns filter tests:

`bazel test //test/...`

To run the regular Envoy tests from this project:

`bazel test @envoy//test/...`

## How it works

The [private Envoy repository](https://github.com/sumukhs/envoy) is provided as a submodule.
The [`WORKSPACE`](WORKSPACE) file maps the `@envoy` repository to this local path.

The [`BUILD`](BUILD) file introduces a new Envoy static binary target, `envoy`,
that links together the new filter and `@envoy//source/exe:envoy_main_lib`. The
`dns` filter registers itself during the static initialization phase of the
Envoy binary as a new filter.