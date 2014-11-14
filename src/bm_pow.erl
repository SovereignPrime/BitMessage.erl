-module(bm_pow).

-behaviour(gen_server).

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-export([
    make_pow/1,
    check_pow/1,
    check_pow/3
    ]).

-record(state, {}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec start_link() -> {ok, pid()} | ignore | {error, string()}. % {{{1
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%--------------------------------------------------------------------
%% @doc
%% Starts POW counting for `Payload`
%%
%% @end
%%--------------------------------------------------------------------
-spec make_pow(binary()) -> integer().  % {{{1
make_pow(Payload) ->
    gen_server:call(?MODULE, {make, Payload}, infinity).

%%--------------------------------------------------------------------
%% @doc
%% Check POW correctness for object
%%
%% @end
%%--------------------------------------------------------------------
-spec check_pow(binary()) -> boolean().  % {{{1
check_pow(<<Nonce:64/big-integer, Payload/bytes>>) ->
    check_pow(<<Nonce:64/big-integer, Payload/bytes>>, 320, 14000).
check_pow(<<Nonce:64/big-integer, Payload/bytes>>, NTpB, ExtraBytes) ->
    Target = bm_types:pow(2 , 64) div ((size(Payload) + ExtraBytes)* NTpB),
    InitialHash = crypto:hash(sha512, Payload),
    <<ResultHash:64/big-integer, _/bytes>> = bm_auth:dual_sha(<<Nonce:64/big-integer, InitialHash/bytes>>),  
    ( ResultHash =< Target ).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->  % {{{1
    {ok, #state{}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call({make, Payload}, _From, State) ->  % {{{1
    Target = bm_types:pow(2 , 64) / ((size(Payload) + 14000 + 8)* 320),
    InitialHash = crypto:hash(sha512, Payload),
    {ok, Reply, _} = compute_pow(InitialHash, Target),
    {reply, Reply, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->  % {{{1
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->  % {{{1
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->  % {{{1
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->  % {{{1
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
-spec compute_pow(binary(), float()) -> {ok, non_neg_integer(), non_neg_integer()}.  % {{{1
compute_pow(InitialHash, Target) ->
    compute_pow(InitialHash, Target, 99999999999999999999, 0).

-spec compute_pow(binary(), Target, TrialValue, Nonce) -> {ok, Nonce, TrialValue}  when % {{{1
      Target :: float(),
      TrialValue :: non_neg_integer(),
      Nonce :: non_neg_integer().
compute_pow(InitialHash, Target, TrialValue, Nonce) when TrialValue > Target ->
    <<ResultHash:8/big-integer-unit:8, _/bytes>> = bm_auth:dual_sha(<<(Nonce + 1):64/big-integer, InitialHash/bytes>>),
    compute_pow(InitialHash, Target, ResultHash, Nonce + 1);
compute_pow(_InitialHash, _Target, TrialValue, Nonce) ->
    {ok, Nonce, TrialValue}.
    
