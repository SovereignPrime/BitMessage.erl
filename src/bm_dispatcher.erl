-module(bm_dispatcher).

-behaviour(gen_server).

-include("../include/bm.hrl").

%% API  {{{1
-export([start_link/0]).
-export([message_arrived/3,
         broadcast_arrived/3,
         register_receiver/1,
         send_message/1,
         send_broadcast/1,
         generate_address/0,
         get_callback/0
]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).
% }}}

-record(state, {callback=bitmessage}).

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
%% Callback when new incomming message arrived
%%
%% @end
%%--------------------------------------------------------------------
-spec message_arrived(Data, Hash, Address) ->  ok when % {{{1
      Data :: binary(),
      Hash :: binary(),
      Address :: binary().
message_arrived(Data, Hash, Address) ->
    gen_server:cast(?MODULE, {arrived, msg, Hash, Address, Data}).

%%--------------------------------------------------------------------
%% @doc
%% Callback when new incomming broadcast arrived
%%
%% @end
%%--------------------------------------------------------------------
-spec broadcast_arrived(Data, Hash, Address) ->  ok when % {{{1
      Data :: binary(),
      Hash :: binary(),
      Address :: binary().
broadcast_arrived(Data, Hash, Address) ->
    gen_server:cast(?MODULE, {arrived, broadcast,Hash, Address, Data}).

%%--------------------------------------------------------------------
%% @doc
%% Send a message
%%
%% @end
%%--------------------------------------------------------------------
-spec send_message(#message{}) ->  ok. % {{{1
send_message(Message) ->
    NMessage = Message#message{hash=crypto:hash(sha512, Message#message.text),
                               folder=sent,
                               type=msg},
    mnesia:transaction(fun() ->
                               mnesia:write(message, NMessage, write)
                       end),
    gen_server:cast(?MODULE, {send, msg, NMessage}).

%%--------------------------------------------------------------------
%% @doc
%% Send a broadcast TODO
%%
%% @end
%%--------------------------------------------------------------------
-spec send_broadcast(#message{}) ->  ok. % {{{1
send_broadcast(Message) ->
    NMessage = Message#message{hash=crypto:hash(sha512, Message#message.text),
                               folder=sent,
                               type=msg},
    mnesia:transaction(fun() ->
                               mnesia:write(message, NMessage, write)
                       end),
    gen_server:cast(?MODULE, {send, broadcast, Message}).

%%--------------------------------------------------------------------
%% @doc
%% Generates new BM address
%%
%% @end
%%--------------------------------------------------------------------
-spec generate_address() ->  ok. % {{{1
generate_address() ->
    gen_server:cast(?MODULE, generate_address).

%%--------------------------------------------------------------------
%% @doc
%% Registers callback module
%%
%% @end
%%--------------------------------------------------------------------
-spec register_receiver(atom()) -> ok.  % {{{1
register_receiver(Callback) ->
    gen_server:cast(?MODULE, {register, Callback}).

%%--------------------------------------------------------------------
%% @doc
%% Get callback module
%%
%% @end
%%--------------------------------------------------------------------
-spec get_callback() -> module().  % {{{1
get_callback() ->
    gen_server:call(?MODULE, callback).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @end
%%--------------------------------------------------------------------
-spec init([]) -> {ok, #state{}}.  % {{{1
init([]) ->
    bm_db:wait_db(),
    Messages = bm_db:select(message,
                            [{#message{folder=sent,
                                       status='new',
                                       _='_'},
                              [],
                              ['$_']},
                             {#message{folder=sent,
                                       status='wait_pubkey',
                                       _='_'},
                              [],
                              ['$_']},
                             {#message{folder=sent,
                                       status='encrypt_message',
                                       _='_'},
                              [],
                              ['$_']}],
                            10000),
    lists:foreach(fun(E) ->
                          bm_encryptor_sup:add_encryptor(E, bitmessage)
                  end,
                  Messages),
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
handle_call(callback, _From, #state{callback=Callback}=State) ->  % {{{1
    {reply, Callback, State};
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
handle_cast({arrived, Type, Hash, Address,  Data},  #state{callback=Callback}=State) ->  % {{{1
    #address{version=AddrVer,
             stream=Stream, % TODO: Is this stream ok??
             ripe=RIPE}=bm_auth:decode_address(Address),
    file:write_file("./test/data/broadcast_decr.bin", Data),
    {AV, R1} = bm_types:decode_varint(Data),
    {AVer, R2} = case bm_types:decode_varint(R1) of
              {Stream, R} ->
                         {AV, R};
                     {A, R} ->
                         {Stream, RO} = bm_types:decode_varint(R),
                         {A, RO}
          end,
    <<_BField:32/big-integer, PSK:64/bytes, PEK:64/bytes, R3/bytes>> = R2,
    {NTpB,
     PLEB,
     R4} = case AddrVer of
               2 ->
                   {?MIN_NTPB, ?MIN_PLEB, R3};
               MV when MV >= 3 ->
                   {NonceTrailsPerBytes, RV} = bm_types:decode_varint(R3),
                   {ExtraBytes, RV1} = bm_types:decode_varint(RV),
                   {NonceTrailsPerBytes, ExtraBytes, RV1}
           end,
    case Type of
        msg -> 
            <<DRIPE:20/bytes, MsgEnc/big-integer, R5/bytes>> = R4,
            RecOK = 
            if DRIPE == RIPE ->
                   true;
               true ->
                   false
            end;
        broadcast ->
            <<MsgEnc/big-integer, R5/bytes>> = R4,
            RecOK = true
    end,

    {Message, R6} = bm_types:decode_varbin(R5),
    {AckData, R7} = if Type == msg ->
                           bm_types:decode_varbin(R6);
                       true -> 
                           {ok, R6}
    end,
    error_logger:info_msg("msg received  ver ~p message ~p ackdata ~p~n", ["MsgVer", Message, AckData]),
    {Sig, R8} = bm_types:decode_varbin(R7),
    SLen = size(Data) - size(R7),
    <<DataSig:SLen/bytes, _/bytes>> = Data,
    PuSK = <<4, PSK/bytes>>,
    SigOK = case crypto:verify(ecdsa, sha, DataSig, Sig, [PuSK, secp256k1]) of
                true -> true;
                false ->
                    [#inventory{payload=D}] = bm_db:lookup(inventory, Hash),
                    %file:write_file("./test/data/broadcast_encr.bin", D),
                    %file:write_file("./test/data/broadcast_decr.bin", Data),
                    <<_:64/integer,
                      TT:12/bytes,
                      V/integer,
                      Stream/integer,
                      Rest/bytes>> = D,

                    Tag = if Type == broadcast, 
                             V == 5 ->
                                 <<Ta:32/bytes, _/bytes>> = Rest,
                                 Ta;
                             true ->
                                 <<>>
                          end,
                    DS = <<TT:12/bytes,
                           V/integer,
                           Stream/integer,
                           Tag/bytes,
                           DataSig/bytes>>,
                    crypto:verify(ecdsa,
                                  sha,
                                  DS,
                                  Sig,
                                  [PuSK,
                                   secp256k1])
            end,
    error_logger:info_msg("Receiver: ~p Signature: ~p AddrVer ~p~n", [RecOK, SigOK, AddrVer]),
    if RecOK, SigOK, AddrVer > 0, AVer =< 4 ->
            {Subject, Text} = case MsgEnc of
                1 ->
                    {"", Message};
                _ ->
                    {match, [_, S,  T]} = re:run(Message, "Subject:(.+)\nBody:(.+)$", [{capture, all, binary},firstline, {newline, any}, dotall, ungreedy]),
                    {S, T}
            end,
            FRipe = bm_auth:generate_ripe(<<4, PSK/bytes, 4, PEK/bytes>>),
            From = bm_auth:encode_address(AVer, Stream, FRipe),
            PubKey = #pubkey{hash=FRipe,
                             psk=PSK,
                             pek=PEK,
                             ntpb=NTpB,
                             pleb=PLEB,
                             time=bm_types:timestamp()},
            error_logger:info_msg("~p~n", [PubKey]),
            bm_db:insert(pubkey, [PubKey]),
            MR = #message{hash=Hash, 
                          enc=MsgEnc, 
                          from=From, 
                          to=Address, 
                          subject=Subject,
                          folder=incoming,
                          time=calendar:local_time(),
                          ackdata=AckData,
                          status=unread,
                          type=Type,
                          text=Text},
            bm_db:insert(message, [MR]),
            if AckData /= ok ->
                    bm_sender:send_broadcast(bm_message_creator:create_ack(MR));
                true ->
                    ok
            end,
            Callback:received(Hash),
            {noreply, State};
        true ->
            {noreply, State}
    end;
handle_cast({send, Type, Message}, #state{callback=Callback}=State) ->  % {{{1
    error_logger:info_msg("Sending message ~p~n", [Message]),
    bm_encryptor_sup:add_encryptor(Message#message{type=Type}, Callback),
    {noreply, State};
handle_cast({register, Module}, State) ->  % {{{1
    {noreply, State#state{callback=Module}};
handle_cast(generate_address, #state{callback=Callback}=State) ->  % {{{1
    bm_address_generator:generate_random_address(make_ref(), 1, false, Callback),
    {noreply, State};
handle_cast(Msg, State) ->  % {{{1
    error_logger:warning_msg("Wrong cast ~p recved in ~p~n", [Msg, ?MODULE]),
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
