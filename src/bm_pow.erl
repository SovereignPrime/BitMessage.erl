-module(bm_pow).

-behaviour(gen_server).

-include("../include/bm.hrl").

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
    make_pow/3,
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
-spec make_pow(binary()) -> binary() | not_found.  % {{{1
make_pow(Payload) ->
    make_pow(Payload, ?MIN_NTPB, ?MIN_PLEB).

-spec make_pow(Payload, NTpB, PLEB) -> Payload | not_found when % {{{1
      Payload :: binary(),
      NTpB :: non_neg_integer(),
      PLEB :: non_neg_integer().
make_pow(Payload, NTpB, PLEB) ->
    Target = compute_terget(Payload, NTpB, PLEB),
    error_logger:info_msg("Computing POW target = ~p~n", [Target]),
    gen_server:call(?MODULE, {make, Payload, Target}, infinity).

%%--------------------------------------------------------------------
%% @doc
%% Check POW correctness for object
%%
%% @end
%%--------------------------------------------------------------------
-spec check_pow(binary()) -> boolean().  % {{{1
check_pow(Payload) ->
    check_pow(Payload, ?MIN_NTPB, ?MIN_PLEB).
check_pow(<<Nonce:64/big-integer, Payload/bytes>>, NTpB, ExtraBytes) ->
    Target = compute_terget(Payload, NTpB, ExtraBytes),
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
handle_call({make,  % {{{1
             <<Time:64/big-integer, _/bytes>>=Payload, Target},
            _From,
            State) ->
    if Time > bm_types:timestamp() - 300 ->
           {reply, not_found, State};
       true ->
           Cores = erlang:system_info(schedulers_online),
           <<Max64:64/integer>> = binary:copy(<<255>>, 8),
           Len = (Max64 + 1) div Cores,
           Pool = lists:seq(0, Max64, Len), 
           InitialHash = crypto:hash(sha512, Payload),
           Pid = self(),
           Pids = lists:map(
                    fun(N) ->
                            spawn(
                              fun() ->
                                      case compute_pow(InitialHash, Target, N, N + Len) of
                                          {ok, POW, _} ->
                                              Reply = <<POW:64/big-integer, Payload/bytes>>,
                                              Pid ! {ok, Reply};
                                          not_found ->
                                              Pid ! not_found
                                      end
                              end)
                    end,
                    Pool),
           R = collect_results(Cores),
           lists:foreach(fun(P) -> exit(P, kill) end, Pids),
           {reply, R, State};
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
-spec compute_pow(binary(), float(), non_neg_integer(), non_neg_integer()) -> {ok, non_neg_integer(), non_neg_integer()} | not_found.  % {{{1
compute_pow(InitialHash, Target, Nonce, Max) ->
    compute_pow(InitialHash, Target, 99999999999999999999, Nonce, Max).

-spec compute_pow(binary(), Target, TrialValue, Nonce, Max) -> {ok, Nonce, TrialValue} | not_found  when % {{{1
      Target :: float(),
      TrialValue :: non_neg_integer(),
      Max :: non_neg_integer(),
      Nonce :: non_neg_integer().
compute_pow(InitialHash, Target, TrialValue, Nonce, Max) when TrialValue > Target,
                                                         Nonce =< Max ->
    <<ResultHash:8/big-integer-unit:8, _/bytes>> = bm_auth:dual_sha(<<(Nonce + 1):64/big-integer, InitialHash/bytes>>),
    compute_pow(InitialHash, Target, ResultHash, Nonce + 1, Max);
compute_pow(_InitialHash, _Target, TrialValue, Nonce, Max) when Nonce =< Max ->
    {ok, Nonce, TrialValue};
compute_pow(_InitialHash, _Target, _TrialValue, _Nonce, _Max) ->
    not_found.
    
-spec compute_terget(Payload, NTpB, PLEB) -> integer() when  % {{{1
      Payload :: binary(),
      NTpB :: non_neg_integer(),
      PLEB :: non_neg_integer().
compute_terget(<<Time:64/big-integer, _/bytes>> = Payload, NTpB, PLEB) ->
    TTL = Time - bm_types:timestamp(),
    PayloadLength = size(Payload) + 8,
    PLPEB = PayloadLength + PLEB,
    bm_types:pow(2 , 64) div (NTpB * (PLPEB + (TTL * PLPEB) div bm_types:pow(2, 16))).

-spec collect_results(non_neg_integer()) -> binary() | not_found.  % {{{1
collect_results(N) when N > 0 ->
    receive 
        not_found ->
            collect_results(N - 1);
        {ok, Nonce} ->
            Nonce
    end;
collect_results(0) ->
    not_found.
