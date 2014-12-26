-module(bm_message_encryptor).

-behaviour(gen_fsm).

-include("../include/bm.hrl").
%% API
-export([start_link/2]).

%% gen_fsm callbacks
-export([init/1, % {{{1
         wait_pubkey/2,
         encrypt_message/2,
         make_inv/2,
         handle_event/3,
         handle_sync_event/4,
         handle_info/3,
         terminate/3,
         code_change/4]). %}}}
-export([pubkey/1]).

-record(state, {type, message, pek, psk, hash, callback}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(DMessage, Callback) ->  % {{{1
    io:format("~p~n", [DMessage]),
    gen_fsm:start_link(?MODULE, [DMessage, Callback], []).

%%--------------------------------------------------------------------
%% @doc
%% Informs encrypotor about receiving new PubKey
%% 
%% @end
%%--------------------------------------------------------------------
-spec pubkey(#pubkey{}) -> ok.  % {{{1
pubkey(PubKey) ->
    Pids = supervisor:which_children(bm_encryptor_sup),
    send_all(Pids, {pubkey, PubKey}).
%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm is started using gen_fsm:start/[3,4] or
%% gen_fsm:start_link/[3,4], this function is called by the new
%% process to initialize.
%%
%% @spec init(Args) -> {ok, StateName, State} |
%%                     {ok, StateName, State, Timeout} |
%%                     ignore |
%%                     {stop, StopReason}
%% @end
%%--------------------------------------------------------------------

%% Init for already packed messages  {{{1
init([
      #message{to=To,
              from=From,
              subject=Subject,
              enc=Enc,
              text=Text,
              type=Type,
              folder=sent,
              status=Status}=Message,
     Callback
     ]) when 
      Status == encrypt_message;
      Status == wait_pubkey ->
    #address{ripe=Ripe} = bm_auth:decode_address(To),
    {ok,
     wait_pubkey,
     #state{type=msg,
            message=Message,
            hash=Ripe,
            callback=Callback},
     0};

%% Init for new and resending messages  {{{1
init([
      #message{hash=Id,
              to=To,
              from=From,
              subject=Subject,
              enc=Enc,
              text=Text,
              status=Status,
              folder=sent,
              type=msg} = Message,
      Callback
     ]) when 
      Status == new;
      Status == ackwait->

    MyRipe = case bm_auth:decode_address(From) of
    #address{ripe = <<0,0,R/bytes>>} when size(R) == 18 -> 
            R;
    #address{ripe = <<0,R/bytes>>} when size(R) == 19 -> 
            R;
    #address{ripe = <<R/bytes>>} when size(R) == 20 -> 
            R
    end,
    #address{ripe=Ripe} = bm_auth:decode_address(To),
    {MyPek, MyPSK, PubKey} = case bm_db:lookup(privkey, MyRipe) of
        [#privkey{public=Pub, pek=EK, psk=SK, hash=MyRipe}] ->
            {EK, SK, Pub};
        [] ->
            error_logger:warning_msg("No addres ~n"),
            {stop, {shudown, "Not my address"}}
    end,
    
    Time = bm_types:timestamp() + 86400 * 2 + crypto:rand_uniform(-300, 300),
    A = crypto:rand_bytes(32),
    AckData = bm_message_creator:create_obj(2, 1, 1, A),
    Ack = bm_message_creator:create_message(<<"object">>,
                                            AckData),
    MSG = <<"Subject:", Subject/bytes, 10, "Body:", Text/bytes>>,
    error_logger:info_msg("MSG ~p ~n", [MSG]),
    UPayload = <<3, %Address version
                 1, %Stream number
                 1:32/big-integer, %Bitfield
                 PubKey:128/bytes,
                 (bm_types:encode_varint(?MIN_NTPB))/bytes, %NonceTrialsPerByte
                 (bm_types:encode_varint(?MIN_PLEB))/bytes, % ExtraBytes
                 Ripe/bytes,
                 Enc, % Message encoding
                 (bm_types:encode_varint(byte_size(MSG)))/bytes,
                 MSG/bytes,
                 (bm_types:encode_varint(byte_size(Ack)))/bytes,
                 Ack/bytes>>,
    SPayload = <<Time:64/big-integer,
                 ?MSG:32/big-integer,
                 1, % Stream
                 UPayload/bytes>>,
    Sig = crypto:sign(ecdsa, sha, SPayload, [MyPSK, secp256k1]),
    Payload = <<UPayload/bytes, (bm_types:encode_varint(byte_size(Sig)))/bytes, Sig/bytes>>,
    error_logger:info_msg("Message ~p ~n", [Payload]),
    <<Hash:32/bytes, _/bytes>>  = bm_auth:dual_sha(Payload),
    NMessage = Message#message{payload=Payload,
                               hash=Hash,
                               folder=sent,
                               ackdata=A,
                               status=wait_pubkey},
    io:format("Deleting: ~p~n", [Message]),
    mnesia:dirty_delete(message, Id),
    bm_db:insert(message, [NMessage]),
    {ok,
     wait_pubkey,
     #state{type=msg,
            hash=Ripe,
            message=NMessage,
            callback=Callback},
     0};

% Init for broadcasts  {{{1
init([
      #message{hash=Id,
              from=From,
              subject=Subject,
              enc=Enc,
              text=Text,
              status=new,
              folder=sent,
              type=broadcast} = Message,
      Callback
     ]) ->

    error_logger:info_msg("Encrypting broadcast: ~p~n", [Subject]),
    MyRipe = case bm_auth:decode_address(From) of
                 #address{ripe = <<0,0,R/bytes>>} when size(R) == 18 -> 
                     R;
                 #address{ripe = <<0,R/bytes>>} when size(R) == 19 -> 
                     R;
                 #address{ripe = <<R/bytes>>} when size(R) == 20 -> 
                     R
             end,
    {BroadcastEK,
     Tag,
     MyPSK,
     PubKey} = case bm_db:lookup(privkey, MyRipe) of
                   [#privkey{public=Pub,
                             psk=SK,
                             hash=MyRipe}] ->
                       {BK, T} = bm_auth:broadcast_key(From),
                       EK = bm_auth:pubkey(BK),
                       {EK, T, SK, Pub};
                   [] ->
                       error_logger:warning_msg("No addres ~n"),
                       {stop, {shudown, "Not my address"}}
               end,
    error_logger:info_msg("Encrypting broadcast w/tag: ~p~n", [Tag]),

    Time = bm_types:timestamp() + 86400 * 2 + crypto:rand_uniform(-300, 300),
    MSG = <<"Subject:", Subject/bytes, 10, "Body:", Text/bytes>>,
    error_logger:info_msg("Broadcast: ~p ~n", [MSG]),
    UPayload = <<3, %Address version
                 1, %Stream number
                 1:32/big-integer, %Bitfield
                 PubKey:128/bytes,
                 (bm_types:encode_varint(?MIN_NTPB))/bytes, %NonceTrialsPerByte
                 (bm_types:encode_varint(?MIN_PLEB))/bytes, % ExtraBytes
                 Enc, % Message encoding
                 (bm_types:encode_varint(byte_size(MSG)))/bytes, % Message size
                 MSG/bytes>>,
    SPayload = <<Time:64/big-integer,
                 ?BROADCAST:32/big-integer,
                 1, % Stream
                 UPayload/bytes>>,
    Sig = crypto:sign(ecdsa, sha, SPayload, [MyPSK, secp256k1]),
    Payload = <<UPayload/bytes, (bm_types:encode_varint(byte_size(Sig)))/bytes, Sig/bytes>>,
    error_logger:info_msg("Broadcast ~p ~n", [Payload]),
    <<Hash:32/bytes, _/bytes>>  = bm_auth:dual_sha(Payload),
    NMessage = Message#message{payload=Payload,
                               hash=Hash,
                               folder=sent,
                               ackdata=ok,
                               to=Tag,
                               status=encrypt_message},
    io:format("Deleting: ~p~n", [Message]),
    mnesia:dirty_delete(message, Id),
    bm_db:insert(message, [NMessage]),
    {ok,
     encrypt_message,
     #state{type=broadcast,
            message=NMessage,
            pek=BroadcastEK,
            callback=Callback},
     0}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% State for waiting PubKey for encryption
%% 
%% @end
%%--------------------------------------------------------------------
-spec wait_pubkey(term(), #state{}) ->  % {{{1
                  {next_state, NextStateName, NextState} |
                  {next_state, NextStateName, NextState, Timeout} |
                  {stop, Reason, NewState} when
      NextStateName :: atom(),
      NewState :: #state{},
      Timeout :: integer(),
      Reason :: term(),
      NewState :: atom().

%% Timeout check for PubKey in DB and rsend GetPubKey  % {{{2
wait_pubkey(timeout, #state{message=#message{to=To}=Message}=State) ->
    #address{ripe=Ripe} = bm_auth:decode_address(To),
    case bm_db:lookup(pubkey, Ripe) of
        [#pubkey{pek=PEK,
                 psk=PSK,
                 hash=Ripe}] ->
                    NMessage = Message#message{status=encrypt_message,
                                               folder=sent},
                    bm_db:insert(message, [NMessage]),
            {next_state,
             encrypt_message,
             State#state{type=msg,
                         message=NMessage,
                         pek=PEK,
                         psk=PSK},
             0};
        [] ->
            error_logger:info_msg("No pubkey Sending msg: ~p~n", [Ripe]),
            bm_sender:send_broadcast(
              bm_message_creator:create_getpubkey(
                bm_auth:decode_address(To))),
            NMessage = Message#message{status=wait_pubkey,
                                       folder=sent},
            bm_db:insert(message, [NMessage]),
            Timeout = application:get_env(bitmessage, max_time_to_wait_pubkey, 12 * 3600 * 1000),
            {next_state, wait_pubkey, State#state{type=msg, message=NMessage}, Timeout}
    end;

%% Receive PubKey and check compability  % {{{2
wait_pubkey({pubkey,
             #pubkey{pek=PEK,
                     psk=PSK,
                     hash=Ripe}},
            #state{hash=Ripe,
                   message=Message}=State) ->
            NMessage = Message#message{status=encrypt_message},
            bm_db:insert(message, [NMessage]),
    {next_state, encrypt_message, State#state{pek=PEK, psk=PSK}, 0};

%% Default {{{2
wait_pubkey(Event, State) ->
    error_logger:warning_msg("Wrong event: ~p status ~p in ~p~n", [Event, ?MODULE, State]),
    {next_state, wait_pubkey, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Message encryption stage
%% 
%% @end
%%--------------------------------------------------------------------
-spec encrypt_message(term(), #state{}) ->  % {{{1
                  {next_state, NextStateName, NextState} |
                  {next_state, NextStateName, NextState, Timeout} |
                  {stop, Reason, NewState} when
      NextStateName :: atom(),
      NewState :: #state{},
      Timeout :: integer(),
      Reason :: term(),
      NewState :: atom().

%% Encrypt % {{{2
encrypt_message(timeout,
                #state{pek=PEK,
                       psk=PSK,
                       type=Type,
                       message = #message{payload=Payload} = Message} = State) ->
    error_logger:info_msg("Encrypting ~n"),
    IV = crypto:rand_bytes(16),
    {KeyR, Keyr} = crypto:generate_key(ecdh, secp256k1),
    XP = crypto:compute_key(ecdh, <<4, PEK/bytes>>, Keyr, secp256k1),
    <<E:32/bytes, M:32/bytes>> = crypto:hash(sha512, XP),
    PLength = 16 - (size(Payload) rem 16),
    Pad = << <<4>> || _<-lists:seq(1, PLength)>>,
    EMessage = crypto:block_encrypt(aes_cbc256, E, IV, <<Payload/bytes, Pad/bytes>>),
    <<4, X:32/bytes, Y:32/bytes>> = KeyR,
    HPayload = <<IV:16/bytes,
                16#02ca:16/big-integer,
                32:16/big-integer,
                X:32/bytes,
                32:16/big-integer,
                Y:32/bytes,
                EMessage/bytes>>,
    HMAC = crypto:hmac(sha256, M, HPayload),
    {next_state,
     make_inv,
     State#state{message = Message#message{payload = <<HPayload/bytes,
                                                       HMAC/bytes>> }},
     0};

%% Default {{{2
encrypt_message(Event, State) ->
    error_logger:warning_msg("Encrypting wrong event ~p~n", [Event]),
    {next_state, encrypt_message, State, 0}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Inv creating stage
%% 
%% @end
%%--------------------------------------------------------------------
-spec make_inv(term(), #state{}) ->  % {{{1
                  {next_state, NextStateName, NextState} |
                  {next_state, NextStateName, NextState, Timeout} |
                  {stop, Reason, NewState} when
      NextStateName :: atom(),
      NewState :: #state{},
      Timeout :: integer(),
      Reason :: term(),
      NewState :: atom().

%% Work cycle {{{2
make_inv(timeout,
         #state{type=Type,
                callback=Callback,
                message= #message{hash=MID,
                                  payload = Payload,
                                  to=To,
                                  from=From}=Message}=State) ->
    Time = bm_types:timestamp() + 86400 * 2, %crypto:rand_uniform(-300, 300),
    PPayload = case Type of 
        msg ->
            #address{stream=Stream} = bm_auth:decode_address(To),
            bm_message_creator:create_obj(?MSG, 
                                          1, % Version
                                          Stream,
                                          Payload);

        broadcast ->
            #address{stream=Stream} = bm_auth:decode_address(From),
            bm_message_creator:create_obj(?BROADCAST, 
                                          5, % Version
                                          Stream,
                                          <<To:32/bytes,
                                          Payload/bytes>>)
        end,
    <<Hash:32/bytes, _/bytes>> = bm_auth:dual_sha(PPayload),
    NMessage = Message#message{status=case Type of 
                                          msg -> ackwait;
                                          broadcast -> ok
                                      end,
                               hash=Hash,
                               payload=PPayload},
    bm_db:delete(message, MID),
    bm_db:insert(message, [NMessage]),
    bm_db:insert(inventory, [#inventory{hash = Hash,
                                        type = case Type of
                                                   msg -> 2;
                                                   broadcast -> 3
                                               end,
                                        stream = Stream,
                                        payload = PPayload,
                                        time = Time
                                       }]),
    error_logger:info_msg("Msg ~p sent to ~p~n",
                          [
                           bm_types:binary_to_hexstring(Hash),
                           To
                          ]),
    bm_sender:send_broadcast(bm_message_creator:create_inv([Hash])),
    Callback:sent(Hash),
    {stop, normal, State};

%% Default {{{2
make_inv(_Event, State) ->
    {next_state, make_inv, State, 0}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_all_state_event/2, this function is called to handle
%% the event.
%%
%% @spec handle_event(Event, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
handle_event(_Event, StateName, State) ->  % {{{1
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_all_state_event/[2,3], this function is called
%% to handle the event.
%%
%% @spec handle_sync_event(Event, From, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------
handle_sync_event(_Event, _From, StateName, State) ->  % {{{1
    Reply = ok,
    {reply, Reply, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it receives any
%% message other than a synchronous or asynchronous event
%% (or a system message).
%%
%% @spec handle_info(Info,StateName,State)->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, StateName, State) ->  % {{{1
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_fsm terminates with
%% Reason. The return value is ignored.
%%
%% @spec terminate(Reason, StateName, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _StateName, _State) ->  % {{{1
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, StateName, State, Extra) ->
%%                   {ok, StateName, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, StateName, State, _Extra) ->  % {{{1
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% Send to all encrypotors
-spec send_all([pid()], term()) -> ok.  % {{{1
send_all([], _Msg) ->
    ok;
send_all([Pid|Rest], Msg) ->  % {{{1
    {_, P, _, _} = Pid,
    gen_fsm:send_event(P, Msg),
    send_all(Rest, Msg).
