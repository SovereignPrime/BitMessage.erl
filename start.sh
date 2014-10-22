#!/bin/bash
PATH=.:$PATH
./rebar compile &&
erl -pa ./ebin -pa ./deps/*/ebin -sname bitmessage -mnesia dir '"./data"' \
    -eval "application:start(bitmessage)" \
    -config ./priv/bitmessage \
