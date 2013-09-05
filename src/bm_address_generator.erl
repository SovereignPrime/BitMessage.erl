-module(bm_address_generator).  
-behaviour(gen_server).  
-include("../include/bm.hrl").

%% UintTest macro
-include_lib("eunit/include/eunit.hrl").

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
    generate_random_address/3
    ]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

generate_random_address(Label, Stream, EighteenthByteRipe) ->
    gen_server:cast(?MODULE, {generate, random, Label, Stream, EighteenthByteRipe}).

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
init([]) ->
    bm_db:wait_db(),
    {ok, []}.

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
handle_cast({generate, random, Label, Stream, EighteenthByteRipe}, State) ->
    bm_db:insert(privkey, [generate_keys(Label, Stream, EighteenthByteRipe)]),
    {noreply, State};
handle_cast(_Msg, State) ->
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
handle_info(_Info, State) ->
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
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
%generate_keys(DeterministicPassword, Nonce, EighteenthByteRipe) when size(DeterministicPassword) /= 0 ->
%    PotentialPrivSign = crypto:hash(sha512, <<DeterministicPassword/bytes, (bm_auth:encode_varint(Nonce))/bytes>>),
%    PotentialPrivKey = crypto:hash(sha512, <<DeterministicPassword/bytes, (bm_auth:encode_varint(Nonce + 1))/bytes>>),
%    PotentialPubKey = point_mult(PotentialPrivKey),
%    PotentialPubSign = point_mult(PotentialPrivSign),
%    Ripe = case {crypto:hash(ripemd160, crypto:hash(sha512, <<PotentialPubSign:(32 * 8)/bytes, PotentialPubKey: (32 * 8)/bytes>>)), EighteenthByteRipe}  of
%        {<<0, 0, R>>, true} ->
%            R;
%        {<<0, R>>, false} ->
%            R;
%        _ ->
%            generate_keys(DeterministicPassword, Nonce + 2, EighteenthByteRipe)
%    end,
%    bm_auth:encode_address(3, Stream, Ripe).
                          
generate_keys(Label, Stream, EighteenthByteRipe) ->
    {PotentialPubSign, PotentialPrivSign} = crypto:generate_key(ecdh, secp256k1),
    {PotentialPubKey, PotentialPrivKey} = crypto:generate_key(ecdh, secp256k1),
    case { bm_auth:generate_ripe(<<PotentialPubSign:32/bytes, PotentialPubKey:32/bytes>>), EighteenthByteRipe}  of
        {<<0, 0, Ripe/bytes>>, true} ->
            #privkey{hash=Ripe, 
                     address=bm_auth:encode_address(3, Stream, Ripe),
                     psk=PotentialPrivSign,
                     pek=PotentialPrivKey,
                     label=Label,
                     time=bm_types:timestamp()};
        {<<0, Ripe/bytes>>, false} ->
            #privkey{hash=Ripe, 
            address=bm_auth:encode_address(3, Stream, Ripe),
            psk=PotentialPrivSign,
            pek=PotentialPrivKey,
            label=Label,
            time=bm_types:timestamp()};
        _ ->
            generate_keys(Label, Stream, EighteenthByteRipe)
    end.
