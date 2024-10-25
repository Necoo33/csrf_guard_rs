# Changelog

## v0.4.0

Added `TokenStatus` enum.
Added `.status` field to `Csrf` struct which has the type of `TokenStatus`
`check_if_token_exist()` function replaced by `check_token_status()` function. It returns a variant of `TokenStatus`, which implements `Debug`, `Clone` and `PartialEq` derive macros.

## v0.3.0

A bug fixed on protection mechanism.
uuid version upgraded to 1.11.0 .

## v0.2.0

Added expiration mechanism, now you can set when a csrf token will be expire and give an ip to new one. This won't break any of the backward code.

## v0.1.1

Fixed some documentation typos.

## v0.1.0

[csrf_guard](https://github.com/Necoo33/csrf_guard_rs) released.
