#!/bin/bash
rebar compile &&
erl -pa ./ebin -pa ./deps/*/ebin -sname bitmessage -mnesia dir '"./data"' -run observer -eval "application:start(bitmessage)"
