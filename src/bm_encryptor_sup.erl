-module(bm_encryptor_sup).

-behaviour(supervisor).

-include("../include/bm.hrl").

%% API
-export([start_link/0]).
-export([add_encryptor/1]).

%% Supervisor callbacks
-export([init/1]).

-define(CHILD(Mod, Type, Args), {make_ref(), {Mod, start_link, Args},
                                     transient, 5000, Type, [Mod]}).

%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error} {{{1
%% @end
%%--------------------------------------------------------------------
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%%--------------------------------------------------------------------
%% @doc
%% Adds new encryptor process for message
%%
%% @end
%%--------------------------------------------------------------------
-spec add_encryptor(#message{}) -> supervisor:startchild_ret().  % {{{1
add_encryptor(DMessage) ->
    supervisor:start_child(?MODULE, [DMessage]).

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
    {ok, {{simple_one_for_one, 5, 10}, [?CHILD(bm_message_encryptor, worker, [])]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
