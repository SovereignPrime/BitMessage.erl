-module(bm_reciever).
-compile([export_all]).
-include("../include/bm.hrl").

-record(init_stage, {verack_sent=false,verack_recv=false}).
-record(state, {socket, transport, version, stream = 1, init_stage = #init_stage{}, remote_streams, remote_addr}).

start_link(Ref, Socket, Transport, Opts) ->
    Pid = spawn_link(?MODULE, init, [Ref, Socket, Transport, Opts]),
    
    {ok, Pid}.

start_link() ->
    proc_lib:start_link(?MODULE, init, [self()]).

init(Ref, Socket, Transport, _Opts) ->
    ok = ranch:accept_ack(Ref),
    loop(#state{socket=Socket, transport=Transport}).

init(Parent) ->
    ok = proc_lib:init_ack(Parent, {ok, self()}),
    timer:sleep(1000),
    {Transport, Socket} =  bm_connetion_dispatcher:get_socket(),
    send_version(#state{socket=Socket, transport=Transport, remote_addr=#network_address{ip={127,0,0,1}, port=8444, time=bm_types:timestamp(), stream=1}}),
    loop(#state{socket=Socket, transport=Transport}).

loop(#state{socket = Socket, transport = Transport}=IState) ->
    case Transport:recv(Socket,0, 50000) of
        {ok, Packet} ->
            State = check_packet(Packet, IState),
            loop(State);
        {error, closed} ->
            bm_sender:unregister_peer(Socket),
            {NTransport, NSocket} =  bm_connetion_dispatcher:get_socket(),
            send_version(#state{socket=NSocket, transport=NTransport, remote_addr=#network_address{ip={127,0,0,1}, port=8444, time=bm_types:timestamp(), stream=1}}),
            loop(IState#state{socket=NSocket, transport=NTransport});
        {error, timeout} ->
            loop(IState);
        {error, R} ->
            bm_sender:unregister_peer(Socket),
            Transport:close(Socket),
            {NTransport, NSocket} = bm_connetion_dispatcher:get_socket(),
            send_version(#state{socket=NSocket, transport=NTransport, remote_addr=#network_address{ip={127,0,0,1}, port=8444, time=bm_types:timestamp(), stream=1}}),
            loop(#state{socket=NSocket, transport=NTransport, init_stage=#init_stage{}})
    end.

check_packet(<<?MAGIC, Command:12/bytes, Length:32, Check:4/bytes, Packet/bytes>>, State) when size(Packet) > Length ->
    <<NPacket:Length/bytes, Rest/bytes>> = Packet,
    NState = check_packet(<<?MAGIC, Command:12/bytes, Length:32, Check:4/bytes, NPacket/bytes>>, State),
    check_packet(Rest, NState);
check_packet(<<?MAGIC, Command:12/bytes, Length:32, Check:4/bytes, Packet/bytes>>, State) when size(Packet) == Length ->
    case crypto:hash(sha512, Packet) of
        <<Check:32/bits, _/bits>> ->
            update_peer_time(State),
            analyse_packet(Command, Length, Packet, State);
        _ ->
            State
    end;
check_packet(<<?MAGIC, _Command:12/bytes, Length:32, _Check:4/bytes, Packet/bytes>>=IPacket, #state{socket=Socket, transport=Transport}=State) when size(Packet) < Length ->
     case Transport:recv(Socket, Length - size(Packet), 5000) of
        {ok, Data} ->
                check_packet(<<IPacket/bytes, Data/bytes>>, State);
        {error, timeout} ->
                check_packet(IPacket, State);
        {error, close} ->
            bm_sender:unregister_peer(Socket),
            {NTransport, NSocket} =  bm_connetion_dispatcher:get_socket(),
            send_version(#state{socket=NSocket, transport=NTransport, remote_addr=#network_address{ip={127,0,0,1}, port=8444, time=bm_types:timestamp(), stream=1}}),
            loop(State#state{socket=NSocket, transport=NTransport});
        {error, R} ->
            bm_sender:unregister_peer(Socket),
            Transport:close(Socket),
            {NTransport, NSocket} = bm_connetion_dispatcher:get_socket(),
            send_version(#state{socket=NSocket, transport=NTransport, remote_addr=#network_address{ip={127,0,0,1}, port=8444, time=bm_types:timestamp(), stream=1}}),
            loop(State#state{socket=NSocket, transport=NTransport, init_stage=#init_stage{}})
    end;
check_packet(_, State) ->
    State.

%%%
%% Messages
%%%

analyse_packet(<<"version", _/bytes>>, Length, <<Version:32/big-integer,
                                           1:64/big-integer, % 'services' field of protocol
                                           Time:64/big-integer,
                                           _AddrRecv:26/bytes,
                                           AddrFrom:26/bytes,
                                           _Nonce:8/bytes,
                                           Data/bytes>>,
              #state{stream=Stream, init_stage=InitStage}=State) 
        when Length > 83, Version > 1 ->
    {_UA, StremsL} = bm_types:decode_varstr(Data),
    {Streams, _} = bm_types:decode_list(StremsL, fun bm_types:decode_varint/1),
    #state{transport=Transport, socket=Socket} = State,
    % Sending verack
    Transport:send(Socket, bm_message_creator:create_message(<<"verack">>, <<>>)),
    Stage = InitStage#init_stage{verack_sent=true},
    PeerAddr = <<Time:64/big-integer, Stream:32/big-integer, AddrFrom/bytes>>,
    {RAddr, _} = bm_types:decode_network(PeerAddr),
    OState = State#state{version=Version, init_stage=Stage, remote_streams=Streams, remote_addr=RAddr},

    if Stage#init_stage.verack_recv == false ->
            send_version(OState);
        true ->
            conection_fully_established(OState)
            
    end,
    OState;

analyse_packet(<<"verack", _/bytes>>, 0, <<>>, State) ->
    OState = State#state{init_stage=State#state.init_stage#init_stage{verack_recv=true}},
    conection_fully_established(OState),
    OState;

analyse_packet(<<"addr", _/bytes>>, _Length, Data, #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    {Addrs, _} = bm_types:decode_list(Data, fun bm_types:decode_network/1),
    bm_db:insert(addr, Addrs),
    State;
analyse_packet(<<"inv",_/bytes>>, Length, Packet, 
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    {ObjsToGet, _} = bm_types:decode_list(Packet, fun invs_to_list/1),
    send_getdata(ObjsToGet, State),
    State;
analyse_packet(<<"getdata", _/bytes>>, Length, Packet,
                 #state{transport=Transport, socket=Socket, init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    {ObjToSend, _} = bm_types:decode_list(Packet, fun(<<I:32/bytes, R/bytes>>) -> {I, R} end),
    MsgToSeend = lists:map(fun bm_message_creator:create_obj/1, ObjToSend),
    lists:foreach(fun(Msg) -> Transport:send(Socket, Msg) end, MsgToSeend),
    State;
analyse_packet(<<"ping", _>>, _Length, _Packet,
                 #state{transport=Transport, socket=Socket,init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    % Sending pong
    Transport:send(Socket, <<?MAGIC, "pong", 0:8/unit:8-integer, 0:32/integer, 16#cf83e135:32/big-integer>>),
    State;

%%%
%% Objects 
%%%

analyse_packet(<<"getpubkey", _/bytes>>, Length, <<PNonce:64/big-integer,
                                             Time:32/big-integer,
                                             AVer:8/big-integer,
                                             Packet/bytes>>=Payload,
                 #state{transport=Transport, socket=Socket, init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when Time /= 0, AVer >= 2->
    Fun = get_pubkey_fun_generator(Packet, State),
    process_object(<<"getpubkey">>, Payload, State, Fun);
analyse_packet(<<"getpubkey", _/bytes>>, Length, <<PNonce:64/big-integer,
                                             Time:64/big-integer,
                                             AVer:8/big-integer,
                                             Packet/bytes>>=Payload,
                 #state{transport=Transport, socket=Socket, init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when  Time /= 0, AVer >= 2->
    Fun = get_pubkey_fun_generator(Packet, State),
    process_object(<<"getpubkey">>, Payload, State, Fun);

analyse_packet(<<"pubkey", _/bytes>>, Length, <<PNonce:64/big-integer,
                                          Time:32/big-integer,
                                          AVer:8/big-integer,
                                          Packet/bytes>> = Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when Time /= 0, AVer >= 2 ->
    Fun = pubkey_fun_generator(Payload, Packet, Time, State),
    process_object(<<"pubkey">>, Payload, State, Fun);

analyse_packet(<<"pubkey", _/bytes>>, Length, <<PNonce:64/big-integer,
                                          Time:64/big-integer,
                                          AVer:8/big-integer,
                                          Packet/bytes>> = Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when Time /= 0, AVer >= 2 ->
    Fun = pubkey_fun_generator(Payload, Packet, Time, State),
    process_object(<<"pubkey">>, Payload, State, Fun);
analyse_packet(<<"msg", _/bytes>>, _Length, <<_POW:8/bytes, 
                                              Time:32/big-integer,
                                              Stream:8/integer, 
                                              EMessage/bytes>> = Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when Time /= 0 ->
    Fun = msg_fun_generator(EMessage, State),  
    process_object(<<"msg">>, Payload, State, Fun);
analyse_packet(<<"msg", _/bytes>>, _Length, <<_POW:8/bytes, 
                                              Time:64/big-integer,
                                              Stream:8/integer, 
                                              EMessage/bytes>> = Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State)
        when Time /= 0 ->
    Fun = msg_fun_generator(EMessage, State),  
    process_object(<<"msg">>, Payload, State, Fun);
analyse_packet(<<"broadcast", _/bytes>>, _Length, <<_POW:8/bytes, 
                                                    Time:32/big-integer,
                                                    BVer:8/big-integer,
                                                    _Stream:8/integer, 
                                                    EMessage/bytes>> = Payload,
               #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when Time /= 0, BVer >= 2 ->
    Fun =  broadcast_fun_generator(BVer, EMessage, State), 
    process_object(<<"broadcast">>, Payload, State, Fun);
analyse_packet(<<"broadcast", _/bytes>>, _Length, <<_POW:8/bytes, 
                                              Time:64/big-integer,
                                              BVer:8/big-integer, 
                                              _Stream:8/integer, 
                                              EMessage/bytes>> = Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when Time /= 0, BVer >= 2 ->
    Fun =  broadcast_fun_generator(BVer, EMessage, State), 
    process_object(<<"broadcast">>, Payload, State, Fun);
    
analyse_packet(Command, _, Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    error_logger:warning_msg("Other packet recieved.~n Command: ~p~nPayload: ~p~n", [Command, Payload]),
    State.
               
%%%
%% Responce sending routines
%%%

send_version(#state{transport=Transport, socket=Socket, stream=Stream, remote_addr=RAddr } = _State) ->
    send_version(Transport, Socket, Stream, RAddr). 
send_version(Transport, Socket, Stream, RAddr) ->
    {MSec, Sec, _} = now(),
    Time = trunc(MSec * 1.0e6 + Sec),
    {ok, {Ip, Port}} = inet:sockname(Socket),
    <<_:12/bytes, AddrRecv/bytes>> = bm_types:encode_network(RAddr),
    <<_:12/bytes, AddrFrom/bytes>> = bm_types:encode_network(#network_address{time=Time, stream=Stream, ip=Ip, port=Port}),
    Nonce = crypto:rand_bytes(8),
    Streams = bm_types:encode_list([Stream], fun bm_types:encode_varint/1),
    Message = <<2:32/big-integer,
                1:64/big-integer, % 'services' field of protocol
                Time:64/big-integer,
                AddrRecv:26/bytes,
                AddrFrom:26/bytes,
                Nonce:8/bytes,
                (bm_types:encode_varstr("/BitMessageErl:0.1/"))/bytes,
                Streams/bytes>>,
    Transport:send(Socket, bm_message_creator:create_message(<<"version">>, Message)).

send_getdata(Objs, #state{socket=Socket, transport=Transport} = _State) ->
    Payload = bm_types:encode_list(lists:flatten(Objs), fun(O) -> <<O/bytes>> end),
    Transport:send(Socket, bm_message_creator:create_message(<<"getdata">>, Payload)).



conection_fully_established(#state{socket=Socket, transport=Transport, stream=Stream, init_stage=#init_stage{verack_sent=true, verack_recv=true}}=State) ->
    bm_sender:register_peer(Socket),
    {ok, { Ip, Port }} = inet:peername(Socket),
    Time = bm_types:timestamp(),
    % Check after here
    bm_sender:send_broadcast(bm_message_creator:create_message(<<"addr">>, bm_types:encode_network(#network_address{ip=Ip, port=Port, time=Time, stream=Stream}))),
    Addrs = bm_message_creator:create_addrs_for_stream(Stream),
    lists:foreach(fun(Addr) ->
            Transport:send(Socket, Addr)
            end, Addrs),
    Invs = bm_message_creator:create_big_inv(Stream, []),
    lists:foreach(fun(I) -> Transport:send(Socket, I) end, Invs), %TODO: aware objects excluding
    State;
conection_fully_established(State) ->
    State.

%%%
%% Some packet decoders
%%%
    
invs_to_list(<<Inv:32/bytes, Rest/bytes>>) ->
    case bm_db:lookup(inventory, Inv) of
        [] ->
            {Inv , Rest};
        _ ->

            {[], Rest}
    end.

process_object(Type, <<POW:64/bits, Time:32/big-integer, AVer:8, Stream:8, Data/bytes>>, State, Fun) when Time /= 0 -> %Fix for 4 bytes time
    process_object(Type, <<POW:64/bits, Time:64/big-integer, AVer:8, Stream:8, Data/bytes>>, State, Fun);
process_object(<<"msg">>=Type, <<POW:64/bits, Time:64/big-integer, Stream:8, Data/bytes>>, State, Fun) when Time /= 0, Stream /= 0 -> %Fix for Msg w/o Addr Version
    process_object(Type, <<POW:64/bits, Time:64/big-integer, 0:8, Stream:8, Data/bytes>>, State, Fun);
process_object(Type, <<_:64/bits, Time:64/big-integer, _:8, Stream:8/big-integer, _Data/bytes>> = Payload, #state{stream=OStream}=State, Fun) ->
    CTime = bm_types:timestamp(),
    IsPOW = bm_pow:check_pow(Payload),
    if 
        Type == <<"pubkey">>, Time =< CTime - 30 * 24 * 3600 ->
            State;
        Type /= <<"pubkey">>, Time =< CTime - 48 * 3600 -> 
            State;
        Time > CTime + 10800 ->
            State;
        Stream == OStream, IsPOW ->
            <<Hash:32/bytes, _/bytes>> = bm_auth:dual_sha(Payload),
            case bm_db:lookup(inventory, Hash) of
                [_] ->
                    State;
                [] ->
                    bm_db:insert(inventory, [ #inventory{hash=Hash, payload=Payload, type=Type, time=Time, stream=Stream} ]),
                    bm_sender:send_broadcast(bm_message_creator:create_inv([ Hash ])),
                    Fun(Hash)
            end;
        true ->
            State
    end.
pubkey_fun_generator(Payload, Packet, Time, State) ->
    fun(_) ->
            {_, Data} = bm_types:decode_varint(Packet),
            <<_BBitField:32/big-integer, PSK:64/bytes, PEK:64/bytes, _/bytes>> = Data,
            Ripe = bm_auth:generate_ripe(binary_to_list(<<4, PSK/bytes, 4, PEK/bits>>)),
            Pubkey = #pubkey{hash=Ripe, data=Payload, time=Time, psk=PSK, pek=PEK},
            bm_db:insert(pubkey, [Pubkey]),
            bm_message_encryptor:pubkey(Pubkey),
            State 
    end.
get_pubkey_fun_generator(Packet, State) ->
    fun(_) ->
            {_, Ripe} = bm_types:decode_varint(Packet),
            RIPE = case Ripe of
                <<0, 0, R/bytes>> when size(R) == 18 ->
                    R;
                <<0, R/bytes>> when size(R) == 19 ->
                    R;
                R ->
                    R
            end,
            case bm_db:lookup(privkey, RIPE) of
                [#privkey{hash=RIPE, address=Addr, enabled=true}=PrKey] ->
                    #address{version=Version, stream=Stream, ripe=Ripe} = bm_auth:decode_address(Addr),
                    bm_sender:send_broadcast(bm_message_creator:create_pubkey(PrKey)),
                    State;
                [] ->
                    State
            end
    end.

msg_fun_generator(EMessage, State) ->
    fun(Hash) ->
            case check_ackdata(EMessage) of
                true ->
                    State;
                false ->
                    bm_message_decryptor:decrypt_message(EMessage, Hash),
                    State
            end
    end. 
broadcast_fun_generator(BVer, EMessage, State) ->
    fun(Hash) ->
            case BVer of
                1 ->
                    bm_dispatcher:broadcast_arrived(EMessage, Hash, broadcast);
                2 ->
                    bm_message_decryptor:decrypt_broadcast(EMessage, Hash);
                _ ->
                    ok
            end,
            State
    end.

%%%
%% Helpers
%%%

update_peer_time(#state{socket=Socket, stream=Stream}) ->
    {MSec, Sec, _} = now(),
    Time = trunc(MSec * 1.0e6 + Sec),
    {ok, {Ip, Port}} = inet:peername(Socket),
    bm_db:insert(addr, [#network_address{time=Time, ip=Ip, port=Port, stream=Stream}]).

check_ackdata(Payload) ->
    case bm_db:match(sent, #message{ackdata=Payload, status=ackwait, _='_'}) of
        [] ->
            false;
        [Message] ->
            bm_db:insert(sent, Message#message{status=ok}),
            true
    end.
