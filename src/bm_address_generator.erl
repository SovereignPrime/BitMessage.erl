-module(bm_address_generator).  
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
    generate_random_address/4
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
start_link() ->  % {{{1
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%--------------------------------------------------------------------
%% @doc
%% Generate random bitmessage address and keypair
%%
%% @end
%%--------------------------------------------------------------------
-spec generate_random_address(Label, Stream, EighteenthByteRipe, Callback) -> ok when  % {{{1
      Label :: reference(),
      Stream :: integer(),
      EighteenthByteRipe :: boolean(),
      Callback :: module().
generate_random_address(Label,
                        Stream,
                        EighteenthByteRipe,
                        Callback) ->
    gen_server:cast(?MODULE,
                    {generate,
                     random,
                     Label,
                     Stream,
                     EighteenthByteRipe,
                     Callback}).

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
handle_call(_Request, _From, State) ->  % {{{1
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
handle_cast({generate,
             random,
             Label,
             Stream,
             EighteenthByteRipe,
             Callback},
            State) ->  % {{{1
    PK = generate_keys(Label,
                       Stream,
                       EighteenthByteRipe),
    bm_db:insert(privkey, [PK]),
    bm_decryptor_sup:add_decryptor(PK),
    error_logger:info_msg("Address ~p ready~n",[PK]),
    Callback:key_ready(PK#privkey.address),
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
                          
%%--------------------------------------------------------------------
%% @private
%% @doc
%% Generates keypair recurcively and saves result to db
%%
%% @end
%%--------------------------------------------------------------------
-spec generate_keys(Label, Stream, EighteenthByteRipe) -> #privkey{} when  % {{{1
      Label :: any(),
      Stream ::integer(),
      EighteenthByteRipe :: boolean().
generate_keys(Label, Stream, EighteenthByteRipe) ->
    {<<4, PSK/bytes>> = PotentialPubSign, PotentialPrivSign} = crypto:generate_key(ecdh, secp256k1),
    {<<4, PEK/bytes>> = PotentialPubKey, PotentialPrivKey} = crypto:generate_key(ecdh, secp256k1),
    case { bm_auth:generate_ripe(<<PotentialPubSign/bytes, PotentialPubKey/bytes>>), EighteenthByteRipe}  of
        {<<0, 0, Ripe/bytes>>, true} ->
            #privkey{hash=Ripe, 
                     address=bm_auth:encode_address(3, Stream, <<0, 0, Ripe/bytes>>),
                     psk=PotentialPrivSign,
                     pek=PotentialPrivKey,
                     public = <<PSK:64/bytes, PEK:64/bytes>>,
                     label=Label,
                     time=bm_types:timestamp()};
        {<<0, Ripe/bytes>>, false} ->
            #privkey{hash=Ripe, 
                     address=bm_auth:encode_address(3, Stream, <<0, Ripe/bytes>>),
                     psk=PotentialPrivSign,
                     pek=PotentialPrivKey,
                     public = <<PSK:64/bytes, PEK:64/bytes>>,
                     label=Label,
                     time=bm_types:timestamp()};
        _ ->
            generate_keys(Label, Stream, EighteenthByteRipe)
    end.
