-module(bitmessage_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

-spec start(application:start_type(), term()) -> {ok, pid()} 
                                                 | {error, _} 
                                                 | {ok, pid(), _}.
start(_StartType, _StartArgs) ->
    application:start(sasl),
    application:start(crypto),
    application:start(ranch),
    application:start(mnesia),
    Port = application:get_env(bitmessage, listen_port, 8444),
    {ok, _} = ranch:start_listener(bitmessage_listener, 100, ranch_tcp, [{port, Port}], bm_reciever, []),
    bitmessage_sup:start_link().

-spec stop(term()) -> ok.
stop(_State) ->
    ok.
