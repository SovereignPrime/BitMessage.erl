-module(bm_address_generator).  
-behaviour(gen_server).  

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

-record(command, {command,
                  addressVersionNumber = 3,
                  streamNumber = 1,
                  label,
                  numberOfAddressesToMake = 1,
                  deterministicPassphrase,
                  eighteenByteRipe = true,
                  nonceTrialsPerByte = 0,
                  payloadLengthExtraBytes = 0,
                  chanAddress}).

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
%                          
%generate_keys(EighteenthByteRipe) ->
%    PotentialPrivSign = crypto:rand_bytes(32),
%    PotentialPrivKey = crypto:rand_bytes(32),
%    PotentialPubKey = point_mult(PotentialPrivKey),
%    PotentialPubSign = point_mult(PotentialPrivSign),
%    Ripe = case {crypto:hash(ripemd160, crypto:hash(sha512, <<PotentialPubSign:(32 * 8)/bytes, PotentialPubKey: (32 * 8)/bytes>>)), EighteenthByteRipe}  of
%        {<<0, 0, R>>, true} ->
%            R;
%        {<<0, R>>, false} ->
%            R;
%        _ ->
%            generate_keys(EighteenthByteRipe)
%    end,
%    bm_auth:encode_address(3, Stream, Ripe).
%    
%point_mult(Priv) ->
%    {Public, Priv} = crypto:generate_key(ecdh, secp256k1, Priv),
%    Public.
