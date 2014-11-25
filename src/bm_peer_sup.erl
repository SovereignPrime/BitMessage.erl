-module(bm_peer_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(CHILD(Id, Mod, Type, Args), {Id, {Mod, start_link, Args},
                                     permanent, 5000, Type, [Mod]}).

%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%%
%% @end
%%--------------------------------------------------------------------
-spec start_link() -> {ok, pid()} | ignore | {error, string()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart frequency and child
%% specifications.
%%
%% @spec init(Args) -> {ok, {SupFlags, [ChildSpec]}} |
%%                     ignore |
%%                     {error, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    {ok, ConNum} = application:get_env(bitmessage, max_number_of_outgoing_connections),
    ChildSpec = [ ?CHILD({peer, C}, bm_reciever, worker, []) || C <- lists:seq(1, ConNum)],
    %ChildSpec = [ ?CHILD({socket, 1}, bm_socket, worker, [1]),
    %              ?CHILD({protocol, 1}, bm_protocol, worker, [1]) ],
    {ok, {{one_for_all, 15, 100}, 
          [
           ?CHILD(connection_dispatcher, bm_connetion_dispatcher, worker, []) | 
           ChildSpec
          ]
}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
