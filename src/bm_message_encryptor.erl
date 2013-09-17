-module(bm_message_encryptor).

-behaviour(gen_fsm).

-include("../include/bm.hrl").
%% API
-export([start_link/2]).

%% gen_fsm callbacks
-export([init/1,
         wait_pubkey/2,
         encrypt_message/2,
         state_name/3,
         handle_event/3,
         handle_sync_event/4,
         handle_info/3,
         terminate/3,
         code_change/4]).
-export([pubkey/1]).

-record(state, {type, message, pek, psk, hash, payload}).

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
start_link(DMessage, Type) ->
    gen_fsm:start_link({local, ?MODULE}, ?MODULE, [DMessage, Type], []).

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
init([#message{to=To, from=From, subject=Subject, text=Text}=Message, message=Type]) ->
    #address{ripe = <<0,0,MyRipe/bytes>>} = bm_auth:decode_address(From),
    #address{ripe=Ripe} = bm_auth:decode_address(To),
    error_logger:info_msg("Sending msg from ~p to ~p ~n", [MyRipe, To]),
    {MyPek, MyPSK, PubKey} = case bm_db:lookup(privkey, MyRipe) of
        [#privkey{public=Pub, pek=EK, psk=SK, hash=MyRipe}] ->
            error_logger:info_msg("Keys ~p ~p ~n", [EK, SK]),
            {EK, SK, Pub};
        [] ->
            error_logger:info_warning("No Keys ~n"),
            {stop, {shudown, "Not my address"}}
    end,

    AckData = crypto:rand_bytes(32),
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
                 (bm_types:encode_varint(byte_size(MSG)))/bytes,
                 MSG/bytes,
                 32, %AckData length
                 AckData:32/bytes>>,
    error_logger:info_msg("Message ~p ~n", [UPayload]),
    Sig = crypto:sign(ecdsa, sha512, UPayload, [MyPSK, secp256k1]),
    error_logger:info_msg("Sig ~p ~n", [Sig]),
    Payload = <<UPayload/bytes, (bm_types:encode_varint(byte_size(Sig)))/bytes, Sig/bytes>>,
    error_logger:info_msg("Message ~p ~n", [Payload]),
    <<Hash:32/bytes, _/bytes>>  = crypto:hash(sha512, Payload),


    case bm_db:lookup(pubkey, Ripe) of
        [#pubkey{pek=PEK, psk=PSK, hash=Ripe}] ->
            error_logger:info_msg("Pubkey found Sending msg: ~p~n", [Payload]),
            bm_db:insert(sent, [Message#message{hash=Hash,
                                                ackdata=AckData,
                                                status=encrypting,
                                                folder=sent}]),
            {ok, encrypt_message, #state{type=Type, message=Message, pek=PEK, psk=PSK, payload=Payload}, 1};
        [] ->
            error_logger:info_msg("No pubkey Sending msg: ~p~n", [Ripe]),
            bm_sender:send_broadcast(bm_message_creator:create_getpubkey(bm_auth:decode_address(To))),
            bm_db:insert(sent, [Message#message{hash=Hash,
                                                ackdata=AckData,
                                                status=ackwait,
                                                folder=sent}]),
            {ok, wait_pybkey, #state{message=Message, payload=Payload}}
    end.
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
wait_pubkey({pubkey, #pubkey{pek=PEK, psk=PSK, hash=Ripe}}, #state{hash=Ripe}=State) ->
    {next_state, encrypt_message, State#state{pek=PEK, psk=PSK}, 1};
wait_pubkey(_Event, State) ->
    {next_state, wait_pubkey, State}.

encrypt_message(timeout, #state{pek=PEK, psk=PSK, hash=Ripe, type=Type, payload=Payload} = State) ->
    %MLength = byte_size(Payload),
    IV = crypto:rand_bytes(16),
    {KeyR, Keyr} = crypto:generate_key(ecdh, secp256k1),
    XP = crypto:compute_key(ecdh, PEK, Keyr, secp256k1),
    <<E:32/bytes, M:32/bytes>> = crypto:hash(sha512, XP),
    EMessage = crypto:block_encrypt(aes_cbc256, E, IV, Payload),
    HMAC = crypto:hmac(sha256, M, EMessage),
    <<4, X:32/bytes, Y:32/bytes>> = KeyR,
    case Type of 
        message ->
            bm_dispetcher:message_sent(<<IV:16/bytes, 16#02ca:16/big-integer, 32:16/big-integer,X:32/bytes, 32:16/big-integer, Y:32/bytes, EMessage/bytes, HMAC/bytes>>);
        broadcast ->
            bm_dispetcher:broadcast_sent(<<IV:16/bytes, 16#02ca:16/big-integer, 32:16/big-integer,X:32/bytes, 32:16/big-integer, Y:32/bytes, EMessage/bytes, HMAC/bytes>>)
    end,
    {stop, ready, State};
encrypt_message(_Event, State) ->
    {next_state, state_name, State}.

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
