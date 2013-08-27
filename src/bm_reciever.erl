-module(bm_reciever).
-compile([export_all]).
-include("../include/bm.hrl").

-record(init_stage, {verack_sent=false,verack_recv=false}).
-record(state, {socket, transport, version, stream = 1, init_stage = #init_stage{}, remote_streams, remote_addr}).

start_link(Ref, Socket, Transport, Opts) ->
    Pid = spawn_link(?MODULE, init, [Ref, Socket, Transport, Opts]),

    {ok, Pid}.
init(Ref, Socket, Transport, _Opts) ->
    %ok = ranch:accept_ack(Ref),
    loop(#state{socket=Socket, transport=Transport}).

loop(#state{socket = Socket, transport = Transport}=IState) ->
    case Transport:recv(Socket,0, 5000) of
        {ok, Packet} ->
            %error_logger:info_msg("Packet recv: ~p~n", [Packet]),
            State = check_packet(Packet, IState),
            loop(State);
        _ ->
            loop(IState)
    end.

check_packet(<<?MAGIC, Command:12/bytes, Length:32, Check:4/bytes, Packet/bytes>>, State) when size(Packet) > Length ->
    <<NPacket:Length/bytes, Rest/bytes>> = Packet,
    NState = check_packet(<<?MAGIC, Command:12/bytes, Length:32, Check:4/bytes, NPacket/bytes>>, State),
    check_packet(Rest, NState);
check_packet(<<?MAGIC, Command:12/bytes, Length:32, Check:4/bytes, Packet/bytes>>, State) when size(Packet) == Length ->
    <<Check:32/bits, _/bits>> = crypto:hash(sha512, Packet),
    analyse_packet(Command, Length, Packet, State);
check_packet(<<?MAGIC, Command:12/bytes, Length:32, _Check:4/bytes, Packet/bytes>>, #state{socket=Socket, transport=Transport}=State) when size(Packet) < Length ->
    {ok, Data} = Transport:recv(Socket, Length - size(Packet), 5000),
    error_logger:info_msg("Packet recv: ~p~n", [Data]),
    analyse_packet(Command, Length, <<Packet/bytes, Data/bytes>>, State);
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
    error_logger:info_msg("Version packet recieved.~n Version: ~p~nAddrFrom: ~p~nStreams:~p~n", [Version, AddrFrom, Streams]),
    #state{transport=Transport, socket=Socket} = State,
    % Sending verack
    Transport:send(Socket, create_message(<<"verack">>, <<>>)),
    Stage = InitStage#init_stage{verack_sent=true},
    PeerAddr = <<Time:64/big-integer, Stream:32/big-integer, AddrFrom/bytes>>,
    {RAddr, _} = bm_types:decode_network(PeerAddr),
    OState = State#state{version=Version, init_stage=Stage, remote_streams=Streams, remote_addr=RAddr},

    if Stage#init_stage.verack_recv == false ->
            send_version(OState);
        true ->
            ok
            
    end,
    OState;

analyse_packet(<<"verack", _/bytes>>, 0, <<>>, State) ->
    error_logger:info_msg("Verack recieved."),
    State#state{init_stage=State#state.init_stage#init_stage{verack_recv=true}};

analyse_packet(<<"addr", _/bytes>>, _Length, Data, #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    {Addrs, _} = bm_types:decode_list(Data, fun bm_types:decode_network/1),
    error_logger:info_msg("Addr packet recieved.~n Addrs: ~p~n", [Addrs]),
    ets:insert(addr, Addrs),
    State;
analyse_packet(<<"inv",_/bytes>>, Length, Packet, 
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    {ObjsToGet, _} = bm_types:decode_list(Packet, fun invs_to_list/1),
    error_logger:info_msg("Inv packet recieved.~n Invs: ~p~n", [ObjsToGet]),
    send_getdata(ObjsToGet, State),
    State;
analyse_packet(<<"getdata", _/bytes>>, Length, Packet,
                 #state{transport=Transport, socket=Socket, init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    {ObjToSend, _} = bm_types:decode_list(Packet, fun(<<I:32/bytes, R/bytes>>) -> {I, R} end),
    MsgToSeend = lists:map(fun send_object/1, ObjToSend),
    error_logger:info_msg("GetData packet recieved.~n ObjToSen: ~p~n", [ObjToSend]),
    lists:map(fun(Msg) -> Transport:send(Socket, Msg) end, MsgToSeend);
analyse_packet(<<"ping", _>>, _Length, _Packet,
                 #state{transport=Transport, socket=Socket,init_stage=#init_stage{verack_recv=true, verack_sent=true}} = _State) ->
    error_logger:info_msg("Ping recieved."),
    % Sending pong
    Transport:send(Socket, <<?MAGIC, "pong", 0:8/unit:8-integer, 0:32/integer, 16#cf83e135:32/big-integer>>);

%%%
%% Objects 
%%%

analyse_packet(<<"getpubkey", _/bytes>>, Length, <<PNonce:64/big-integer,
                                             Time:64/big-integer,
                                             AVer:8/big-integer,
                                             Packet/bytes>>=Payload,
                 #state{transport=Transport, socket=Socket, init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when  AVer == 2->
    Fun = fun() ->
        {_, Ripe} = bm_types:decode_varint(Packet),
        case ets:lookup(pubkeys, Ripe) of
            [_] ->
                send_my_pubkey;%(Ripe); % TODO
            [] ->
                    State
        end
    end,
    error_logger:info_msg("GetPubKey packet recieved.~n Payload: ~p~n", [Payload]),
    process_object(<<"getpubkey">>, Payload, State, Fun);
analyse_packet(<<"pubkey", _/bytes>>, Length, <<PNonce:64/big-integer,
                                          Time:64/big-integer,
                                          AVer:8/big-integer,
                                          Packet/bytes>> = Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when AVer == 2 ->
    Fun = fun() ->
            {_, Data} = bm_types:decode_varint(Packet),
            <<BBitField:32/big-integer, PSK:64/bytes, PEK:64/bytes>> = Data,
            Ripe = bm_auth:generate_ripe(binary_to_list(<<4, PSK/bytes, 4, PEK/bits>>)),
            State % TODO
    end,
    error_logger:info_msg("PubKey packet recieved.~n Payload: ~p~n", [Payload]),
    process_object(<<"getpubkey">>, Payload, State, Fun);

analyse_packet(<<"msg", _/bytes>>, Length, Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    error_logger:info_msg("Msg packet recieved.~n Payload: ~p~n", [Payload]),
    impl; % TODO
analyse_packet(<<"broadcast", _/bytes>>, Length, Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    error_logger:info_msg("Broadcast packet recieved.~n Payload: ~p~n", [Payload]),
    impl; % TODO
    
analyse_packet(Command, _, Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    error_logger:info_msg("Other packet recieved.~n Command: ~p~n Payload: ~p~n", [Command,Payload]),
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
    %AddrRecv = RAddr,
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
    error_logger:info_msg("Sending version message ~n~p~n", [create_message(<<"version">>,Message)]),
    Transport:send(Socket, create_message(<<"version">>, Message)).

send_getdata(Objs, #state{socket=Socket, transport=Transport} = _State) ->
    Payload = bm_types:encode_list(Objs, fun(O) -> <<O/bytes>> end),
    Transport:send(Socket, create_message(<<"getdata">>, Payload)).

create_message(Command, Payload) ->
    Length = size(Payload),
    CL = byte_size(Command),
    C = <<Command/bytes, 0:(12 - CL)/unit:8>>,
    <<Check:4/bytes, _/bytes>> = crypto:hash(sha512, Payload),
    %error_logger:info_msg("Sending  message ~nCommand: ~p~nPayload: ~p~nLength: ~p~n, Check: ~p~n", [C, Payload, Length, Check]),
    <<?MAGIC, C:12/bytes, Length:32/big-integer, Check:4/bytes, Payload/bytes>>.

send_object(Hash) ->
    [#object{type=Type, payload=Payload}] = ets:lookup(Hash),
    create_message(Type, Payload).
%%%
%% Some packet decoders
%%%
    
invs_to_list(<<Inv:32/bytes, Rest/bytes>>) ->
    case ets:lookup(inventory, Inv) of
        [] ->
            {Inv , Rest};
        _ ->

            {[], Rest}
    end.

check_object(Time, Stream, #state{stream=OStream}) ->
    {MSec, Sec, _} = now(),
    CTime = MSec * 1.0e6 + Sec,
    if 
        Time > CTime, Time =< CTime - 48 * 3600 ->
            false;
        Stream == OStream ->
            true
    end.
process_object(Type, <<_:64/bits, Time:64/big-integer, _:8, Data/bytes>> = Payload, #state{stream=OStream}=State, Fun) ->
    {MSec, Sec, _} = now(),
    CTime = MSec * 1.0e6 + Sec,
    {Stream, _} = bm_types:decode_varint(Data),
    if 
        Time > CTime, Time =< CTime - 48 * 3600 ->
            State;
        Stream == OStream ->
            <<Hash:32/bytes, _>> = bm_auth:dual_sha(Payload),
            case ets:lookup(objects, Hash) of
                [_] ->
                    State;
                [] ->
                    ets:insert(inventory, #object{hash=Hash, payload=Payload, type=Type, time=Time}),
                    %broadcast_inv(Hash), % TODO
                    Fun()
            end
    end.
