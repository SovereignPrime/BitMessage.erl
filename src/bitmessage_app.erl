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
    error_logger:tty(false),
    bitmessage_sup:start_link(),
    Port = application:get_env(bitmessage, listen_port, 8444),
    {ok, _} = ranch:start_listener(bitmessage_listener, 100, ranch_tcp, [{port, Port}], bm_listener, []).

stop(_State) ->
    application:stop(crypto),
    application:stop(ranch),
    application:stop(mnesia),
    application:stop(sasl),
    ok.
