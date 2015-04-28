-module(bm_attachment_sup).

-behaviour(supervisor).

%% API functions
-export([start_link/0]).

%% Supervisor callbacks
-export([
         init/1,
         download_attachment/2
        ]).

-define(CHILD(Mod, Type, Args), {make_ref(), {Mod, start_link, Args},
                                     transient, 5000, Type, [Mod]}).

%%%===================================================================
%%% API functions  {{{1
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->  % {{{2
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec download_attachment(Hash, Path) -> supervisor:startchild_ret() when  % {{{2
      Hash :: binary(), 
      Path :: string().
download_attachment(Hash, Path) ->
    supervisor:start_child(?MODULE, [Hash, Path]).

%%%===================================================================
%%% Supervisor callbacks  {{{1
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
init([]) ->  % {{{2
    {ok, {{simple_one_for_one, 5, 10}, [
                                        ?CHILD(bm_attachment_srv, worker, [])
                                       ]}}.

%%%===================================================================
%%% Internal functions  % {{{1
%%%===================================================================
