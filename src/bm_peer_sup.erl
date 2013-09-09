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
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
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
    ConNum = application:get_env(bitmessage, max_number_of_outgoing_connections, 8),
    ChildSpec = [ ?CHILD({peer, C}, bm_reciever, worker, []) || C <- lists:seq(1, ConNum)],
    {ok, {{one_for_one, 5, 10}, [
                ?CHILD(connection_dispatcher, bm_connetion_dispatcher, worker, []) | 
                ChildSpec
                ]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
