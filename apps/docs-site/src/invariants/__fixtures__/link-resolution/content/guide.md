# Guide

## Setup

Follow these steps.

## Redirect to `/oauth/authorize`

The exact shape that exposed the `slugifyHeading` approximation's divergence
from `github-slugger`'s real behaviour (qauth-labs/qauth#351 fix round 1):
punctuation glued directly to a word, with no surrounding space, inside a
heading. `github-slugger` deletes the `/` characters with nothing in their
place, so this heading's real anchor is `redirect-to-oauthauthorize` — NOT
`redirect-to-oauth-authorize`, which is what the old hand-rolled
approximation computed.
