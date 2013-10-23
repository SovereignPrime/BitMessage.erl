-module(bitmessage_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    application:start(sasl),
    application:start(crypto),
    application:start(ranch),
    application:start(mnesia),
    bitmessage_sup:start_link().

stop(_State) ->
    application:stop(crypto),
    application:stop(ranch),
    application:stop(mnesia),
    application:stop(sasl),
    ok.
