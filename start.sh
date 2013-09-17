#!/bin/bash
rebar compile &&
erl -pa ./ebin -pa ./deps/*/ebin -sname bitmessage -mnesia dir '"./data"' \
    -eval "application:start(bitmessage)" \
    #-run observer 
