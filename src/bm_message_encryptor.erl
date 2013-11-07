-module(bm_message_encryptor).

-behaviour(gen_fsm).

-include("../include/bm.hrl").
%% API
-export([start_link/1]).

%% gen_fsm callbacks
-export([init/1,
         wait_pubkey/2,
         encrypt_message/2,
         make_inv/2,
         state_name/3,
         handle_event/3,
         handle_sync_event/4,
         handle_info/3,
         terminate/3,
         code_change/4]).
-export([pubkey/1]).

-record(state, {type, message, pek, psk, hash}).

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
start_link(DMessage) ->
    io:format("~p~n", [DMessage]),
    gen_fsm:start_link(?MODULE, DMessage, []).

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
init(#message{to=To, from=From, subject=Subject, enc=Enc, text=Text,type=Type, status=Status}=Message) when Status == encrypt_message; Status == wait_pubkey ->
    #address{ripe=Ripe} = bm_auth:decode_address(To),
    {ok, wait_pubkey, #state{type=msg, message=Message, hash=Ripe}, 2};
init(#message{to=To, from=From, subject=Subject, enc=Enc, text=Text, status=new, type=msg} = Message) ->
    MyRipe = case bm_auth:decode_address(From) of
    #address{ripe = <<0,0,R/bytes>>} when size(R) == 18 -> 
            R;
    #address{ripe = <<0,R/bytes>>} when size(R) == 19 -> 
            R;
    #address{ripe = <<R/bytes>>} when size(R) == 20 -> 
            R
    end,
    #address{ripe=Ripe} = bm_auth:decode_address(To),
    %error_logger:info_msg("Sending msg from ~p to ~p ~n", [MyRipe, To]),
    {MyPek, MyPSK, PubKey} = case bm_db:lookup(privkey, MyRipe) of
        [#privkey{public=Pub, pek=EK, psk=SK, hash=MyRipe}] ->
            error_logger:info_msg(" My keys ~p ~p ~n", [EK, SK]),
            {EK, SK, Pub};
        [] ->
            error_logger:info_warning("No addres ~n"),
            {stop, {shudown, "Not my address"}}
    end,
    
    Time = bm_types:timestamp() + crypto:rand_uniform(-300, 300),
    AckData = <<Time:64/big-integer, 1, (crypto:rand_bytes(32))/bytes>>,
    POW = bm_pow:make_pow(AckData),
    Ack = <<POW:64/big-integer, AckData/bytes>>,
    MSG = <<"Subject:", Subject/bytes, 10, "Body:", Text/bytes>>,
    error_logger:info_msg("MSG ~p ~n", [MSG]),
    UPayload = <<1, %MSG version
                 3, %Address version
                 1, %Stream number
                 1:32/big-integer, %Bitfield
                 PubKey:128/bytes,
                 (bm_types:encode_varint(320))/bytes, %NonceTrialsPerByte
                 (bm_types:encode_varint(14000))/bytes, % ExtraBytes
                 Ripe/bytes,
                 Enc, % Message encoding
                 (bm_types:encode_varint(byte_size(MSG)))/bytes,
                 MSG/bytes,
                 (bm_types:encode_varint(byte_size(Ack)))/bytes,
                 Ack/bytes>>,
    %error_logger:info_msg("Message ~p ~n", [UPayload]),
    Sig = crypto:sign(ecdsa, sha, UPayload, [MyPSK, secp256k1]),
    %error_logger:info_msg("Sig ~p ~n", [Sig]),
    Payload = <<UPayload/bytes, (bm_types:encode_varint(byte_size(Sig)))/bytes, Sig/bytes>>,
    error_logger:info_msg("Message ~p ~n", [Payload]),
    <<Hash:32/bytes, _/bytes>>  = crypto:hash(sha512, Payload),
    NMessage = Message#message{payload=Payload, hash=Hash, ackdata=AckData, status=wait_pubkey},
    {ok, wait_pubkey, #state{type=msg, hash=Ripe, message=NMessage}, 2}.


%init([#message{to=To, from=From, subject=Subject, text=Text}=Message, broadcast=Type]) ->
%    #address{ripe=MyRipe} = bm_auth:decode_address(From),
%    #address{ripe=Ripe} = bm_auth:decode_address(To),
%
%    {MyPek, MyPSK} = case bm_db:lookup(privkey, MyRipe) of
%        [#pubkey{pek=EK, psk=SK, hash=Ripe}] ->
%            {EK, SK};
%        [] ->
%            {stop, {shudown, "Not my address"}}
%    end,
%
%    AckData = crypto:rand_bytes(32),
%    MSG = <<"Subject:", Subject, 13, "Body:", Text>>,
%    UPayload = <<2, %Broadcast version
%                3, %Address version
%                1, %Stream number
%                1:32/big-integer, %Bitfield
%                MyPSK:64/bytes,
%                MyPek:64/bytes,
%                (bm_types:encode_varint(320))/bytes, %NonceTrialsPerByte
%                (bm_types:encode_varint(14000))/bytes, % ExtraBytes
%                (bm_types:encode_varint(byte_size(MSG)))/bytes,
%                 MSG/bytes,
%                 32/big-integer, %AckData length
%                 AckData:32/bytes>>,
%    Sig = crypto:sign(ecda, sha512, UPayload, [MyPSK, secp256k1]),
%    Payload = <<UPayload/bytes, (bm_types:encode_varint(byte_size(Sig)))/bytes, Sig/bytes>>,
%
%    case bm_db:lookup(pubkey, Ripe) of
%        [#pubkey{pek=PEK, psk=PSK, hash=Ripe}] ->
%            {ok, encrypt_message, #state{type=Type, message=Message, pek=PEK, psk=PSK}, 1};
%        [] ->
%            bm_sender:send_broadcast(bm_message_creator:create_getpubkey(To)),
%            {ok, wait_pybkey, #state{message=Message}}
%    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_event/2, the instance of this function with the same
%% name as the current state name StateName is called to handle
%% the event. It is also called if a timeout occurs.
%%
%% @spec state_name(Event, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
wait_pubkey(timeout, #state{message=#message{to=To}=Message}=State) ->
    #address{ripe=Ripe} = bm_auth:decode_address(To),
    case bm_db:lookup(pubkey, Ripe) of
        [#pubkey{pek=PEK, psk=PSK, hash=Ripe}] ->
                    NMessage = Message#message{status=encrypt_message,
                                               folder=sent},
                    bm_db:insert(sent, [NMessage]),
            {next_state, encrypt_message, State#state{type=msg, message=NMessage, pek=PEK, psk=PSK}, 1};
        [] ->
            error_logger:info_msg("No pubkey Sending msg: ~p~n", [Ripe]),
            bm_sender:send_broadcast(bm_message_creator:create_getpubkey(bm_auth:decode_address(To))),
            NMessage = Message#message{status=wait_pubkey,
                                       folder=sent},
            bm_db:insert(sent, [NMessage]),
            Timeout = application:get_env(bitmessage, max_time_to_wait_pubkey, 12 * 3600 * 1000),
            {next_state, wait_pubkey, State#state{type=msg, message=NMessage}, Timeout}
    end;
wait_pubkey({pubkey, #pubkey{pek=PEK, psk=PSK, hash=Ripe}}, #state{hash=Ripe, message=Message}=State) ->
            NMessage = Message#message{status=encrypt_message},
            bm_db:insert(sent, [NMessage]),
    {next_state, encrypt_message, State#state{pek=PEK, psk=PSK}, 0};
wait_pubkey(Event, State) ->
    error_logger:warning_msg("Wrong event: ~p status ~p in ~p~n", [Event, ?MODULE, State]),
    {next_state, wait_pubkey, State}.

encrypt_message(timeout, #state{pek=PEK, psk=PSK, hash=Ripe, type=Type, message = #message{payload=Payload} = Message} = State) ->
    error_logger:info_msg("Encrypting ~n"),
    IV = crypto:rand_bytes(16),
    {KeyR, Keyr} = crypto:generate_key(ecdh, secp256k1),
    XP = crypto:compute_key(ecdh, <<4, PEK/bytes>>, Keyr, secp256k1),
    <<E:32/bytes, M:32/bytes>> = crypto:hash(sha512, XP),
    PLength = 16 - (size(Payload) rem 16),
    Pad = << <<4>> || _<-lists:seq(1, PLength)>>,
    EMessage = crypto:block_encrypt(aes_cbc256, E, IV, <<Payload/bytes, Pad/bytes>>),
    HMAC = crypto:hmac(sha256, M, EMessage),
    <<4, X:32/bytes, Y:32/bytes>> = KeyR,
    {next_state, make_inv, State#state{message = Message#message{payload = <<IV:16/bytes, 16#02ca:16/big-integer, 32:16/big-integer,X:32/bytes, 32:16/big-integer, Y:32/bytes, EMessage/bytes, HMAC/bytes>> }}, 0};
encrypt_message(Event, State) ->
    error_logger:warning_msg("Encrypting wrong event ~p~n", [Event]),
    {next_state, encrypt_message, State, 0}.

make_inv(timeout, #state{type=Type, message= #message{hash=MID, payload = Payload, to=To, from=From}=Message}=State) ->
    Time = bm_types:timestamp() + crypto:rand_uniform(-300, 300),
    TPayload = case Type of 
        msg ->
            #address{stream=Stream} = bm_auth:decode_address(To),
            <<Time:64/big-integer, 
              (bm_types:encode_varint(Stream))/bytes, % Reciever's stream
              Payload/bytes>>;
        broadcast ->
            #address{stream=Stream} = bm_auth:decode_address(From),
            <<Time:64/big-integer, 
              (bm_types:encode_varint(2))/bytes,  % Broadcast version
              (bm_types:encode_varint(Stream))/bytes, % Sender's stream
              Payload/bytes>>
        end,
    POW = bm_pow:make_pow(TPayload),
    PPayload = <<POW:64/big-integer, TPayload/bytes>>,
    <<Hash:32/bytes, _/bytes>> = crypto:hash(sha512, PPayload),
    NMessage = Message#message{status=ackwait,
                               hash=Hash,
                               payload=PPayload},
    bm_db:delete(sent, MID),
    bm_db:insert(sent, [NMessage]),
    bm_db:insert(inventory, [#inventory{hash = Hash,
                                        type = atom_to_binary(Type, latin1),
                                        stream = Stream,
                                        payload = PPayload,
                                        time = Time
                                       }]),
    error_logger:info_msg("Msg sent to ~p~n", [To]),
    bm_sender:send_broadcast(bm_message_creator:create_inv([Hash])),
    {stop, {shutdown, "Ready"}, State};
make_inv(_Event, State) ->
    {next_state, make_inv, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_event/[2,3], the instance of this function with
%% the same name as the current state name StateName is called to
%% handle the event.
%%
%% @spec state_name(Event, From, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------
state_name(_Event, _From, State) ->
    Reply = ok,
    {reply, Reply, state_name, State}.

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
handle_event(_Event, StateName, State) ->
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
handle_sync_event(_Event, _From, StateName, State) ->
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
handle_info(_Info, StateName, State) ->
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
terminate(_Reason, _StateName, _State) ->
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
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
send_all([], _Msg) ->
    ok;
send_all([Pid|Rest], Msg) ->
    {_, P, _, _} = Pid,
    gen_fsm:send_event(P, Msg),
    send_all(Rest, Msg).
