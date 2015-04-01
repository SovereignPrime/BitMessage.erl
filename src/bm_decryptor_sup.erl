-module(bm_decryptor_sup).

-behaviour(supervisor).
-include("../include/bm.hrl").

%% API
-export([start_link/0]).
-export([add_decryptor/1]).

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

%%--------------------------------------------------------------------
%% @doc
%% Adds decryptor process w/new keypair
%%
%% @end
%%--------------------------------------------------------------------
-spec add_decryptor(#privkey{}) -> supervisor:startchild_ret().
add_decryptor(PrivKey) ->
    %TODO
    supervisor:start_child(?MODULE, ?CHILD({cryptor, make_ref()}, 
                                           bm_message_decryptor,
                                           worker,
                                           [PrivKey])).
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
    ok = bm_db:wait_db(),
    Children = bm_db:foldr(fun(O, A) ->
                [?CHILD({cryptor, length(A) + 1}, bm_message_decryptor, worker, [O]) | A]
            end, [], privkey),
    {ok, {{one_for_one, 5, 10}, 
          [?CHILD(decoder, bm_decryptor, worker, [#privkey{}]) | Children]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
