-module(bm_reciever).
-compile([export_all]).
-include("../include/bm.hrl").

-record(init_stage, {verack_sent=false,verack_recv=false}).
-record(state, {socket, transport, version, stream = 1, init_stage = #init_stage{}, remote_streams, remote_addr}).

start_link(Ref, Socket, Transport, Opts) ->
    Pid = spawn_link(?MODULE, init, [Ref, Socket, Transport, Opts]),
    
    {ok, Pid}.

start_link() ->
    %error_logger:info_msg("Starting reciever: ~p~n", [self()]),
    proc_lib:start_link(?MODULE, init, [self()]).

init(Ref, Socket, Transport, _Opts) ->
    error_logger:info_msg("Started reciever for incoming connection: ~p~n", [self()]),
    ok = ranch:accept_ack(Ref),
    loop(#state{socket=Socket, transport=Transport}).

init(Parent) ->
    ok = proc_lib:init_ack(Parent, {ok, self()}),
    timer:sleep(1000),
    {Transport, Socket} =  bm_connetion_dispatcher:get_socket(),
    error_logger:info_msg("Started reciever: ~p~n", [self()]),
    send_version(#state{socket=Socket, transport=Transport, remote_addr=#network_address{ip={127,0,0,1}, port=8444, time=bm_types:timestamp(), stream=1}}),
    loop(#state{socket=Socket, transport=Transport}).

loop(#state{socket = Socket, transport = Transport}=IState) ->
    case Transport:recv(Socket,0, 50000) of
        {ok, Packet} ->
            %error_logger:info_msg("Packet recv: ~p~n", [Packet]),
            State = check_packet(Packet, IState),
            loop(State);
        {error, closed} ->
            error_logger:info_msg("Socket closed: ~p~n", [self()]),
            bm_sender:unregister_peer(Socket),
            {NTransport, NSocket} =  bm_connetion_dispatcher:get_socket(self()),
            send_version(#state{socket=NSocket, transport=NTransport, remote_addr=#network_address{ip={127,0,0,1}, port=8444, time=bm_types:timestamp(), stream=1}}),
            loop(IState#state{socket=NSocket, transport=NTransport});
        {error, R} ->
            error_logger:info_msg("Socket error: ~p~p~n", [R, self()]),
            bm_sender:unregister_peer(Socket),
            Transport:close(Socket),
            {NTransport, NSocket} = bm_connetion_dispatcher:get_socket(),
            send_version(#state{socket=NSocket, transport=NTransport, remote_addr=#network_address{ip={127,0,0,1}, port=8444, time=bm_types:timestamp(), stream=1}}),
            loop(IState#state{socket=NSocket, transport=NTransport, init_stage=#init_stage{}})
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
    {ok, Data} = Transport:recv(Socket, Length - size(Packet), 5000),
    check_packet(<<IPacket/bytes, Data/bytes>>, State);
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
    error_logger:info_msg("Version packet recieved. ~p~n", [self()]),
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
    error_logger:info_msg("Verack recieved.~p~n", [self()]),
    OState = State#state{init_stage=State#state.init_stage#init_stage{verack_recv=true}},
    conection_fully_established(OState),
    OState;

analyse_packet(<<"addr", _/bytes>>, _Length, Data, #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    error_logger:info_msg("Addr packet recieved.~p~n", [self()]),
    {Addrs, _} = bm_types:decode_list(Data, fun bm_types:decode_network/1),
    error_logger:info_msg("Addr packet recieved.~n Addrs: ~p Pid: ~p~n", [length(Addrs), self()]),
    bm_db:insert(addr, Addrs),
    %error_logger:info_msg("Addr packet recieved.~n Addrs: ~p Pid: ~p~n", [length(Addrs), self()]),
    State;
analyse_packet(<<"inv",_/bytes>>, Length, Packet, 
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    error_logger:info_msg("Inv packet recieved.~p~n", [self()]),
    {ObjsToGet, _} = bm_types:decode_list(Packet, fun invs_to_list/1),
    %error_logger:info_msg("Inv packet recieved.~n Invs: ~p~n", [ObjsToGet]),
    send_getdata(ObjsToGet, State),
    State;
analyse_packet(<<"getdata", _/bytes>>, Length, Packet,
                 #state{transport=Transport, socket=Socket, init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    error_logger:info_msg("GetData packet recieved.~p~n", [self()]),
    {ObjToSend, _} = bm_types:decode_list(Packet, fun(<<I:32/bytes, R/bytes>>) -> {I, R} end),
    MsgToSeend = lists:map(fun bm_message_creator:create_inv/1, ObjToSend),
    %error_logger:info_msg("GetData packet recieved.~n ObjToSen: ~p~n", [length(ObjToSend)]),
    lists:map(fun(Msg) -> Transport:send(Socket, Msg) end, MsgToSeend);
analyse_packet(<<"ping", _>>, _Length, _Packet,
                 #state{transport=Transport, socket=Socket,init_stage=#init_stage{verack_recv=true, verack_sent=true}} = _State) ->
    error_logger:info_msg("Ping recieved.~p~n", [self()]),
    % Sending pong
    Transport:send(Socket, <<?MAGIC, "pong", 0:8/unit:8-integer, 0:32/integer, 16#cf83e135:32/big-integer>>);

%%%
%% Objects 
%%%

analyse_packet(<<"getpubkey", _/bytes>>, Length, <<PNonce:64/big-integer,
                                             Time:32/big-integer,
                                             AVer:8/big-integer,
                                             Packet/bytes>>=Payload,
                 #state{transport=Transport, socket=Socket, init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when Time /= 0, AVer >= 2->
    error_logger:info_msg("GetPubKey packet recieved.~p~n", [self()]),
    Fun = fun(_) ->
        {_, Ripe} = bm_types:decode_varint(Packet),
        case bm_db:lookup(pubkey, Ripe) of
            [_] ->
                %TODO: 
                %send_my_pubke(),
                State;
            [] ->
                State
        end
    end,
    %error_logger:info_msg("GetPubKey packet recieved.~n Payload: ~p~n", [Payload]),
    process_object(<<"getpubkey">>, Payload, State, Fun);
analyse_packet(<<"getpubkey", _/bytes>>, Length, <<PNonce:64/big-integer,
                                             Time:64/big-integer,
                                             AVer:8/big-integer,
                                             Packet/bytes>>=Payload,
                 #state{transport=Transport, socket=Socket, init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when  Time /= 0, AVer >= 2->
    error_logger:info_msg("GetPubKey packet recieved.~p~n", [self()]),
    Fun = fun(_) ->
        {_, Ripe} = bm_types:decode_varint(Packet),
        case bm_db:lookup(pubkey, Ripe) of
            [_] ->
                %TODO: 
                %send_my_pubke(),
                State;
            [] ->
                State
        end
    end,
    %error_logger:info_msg("GetPubKey packet recieved.~n Payload: ~p~n", [Payload]),
    process_object(<<"getpubkey">>, Payload, State, Fun);

analyse_packet(<<"pubkey", _/bytes>>, Length, <<PNonce:64/big-integer,
                                          Time:32/big-integer,
                                          AVer:8/big-integer,
                                          Packet/bytes>> = Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when Time /= 0, AVer >= 2 ->
    error_logger:info_msg("PubKey packet recieved.~p~n", [self()]),
    Fun = fun(_) ->
            error_logger:info_msg("PubKey packet recieved1.~p~n", [self()]),
            {_, Data} = bm_types:decode_varint(Packet),
            error_logger:info_msg("PubKey packet recieved2.~p~n ~p~n", [size(Data), self()]),
            <<_BBitField:32/big-integer, PSK:64/bytes, PEK:64/bytes, _/bytes>> = Data,
            error_logger:info_msg("PubKey packet recieved PSK.~p~n", [PSK]),
            Ripe = bm_auth:generate_ripe(binary_to_list(<<4, PSK/bytes, 4, PEK/bits>>)),
            error_logger:info_msg("PubKey packet recieved RIPE.~p~n", [Ripe]),
            bm_db:insert(pubkey, [ #pubkey{hash=Ripe, data=Payload, time=Time, psk=PSK, pek=PEK} ]),
            %TODO
            %advertise_pubkey(),
            State 
    end,
    %error_logger:info_msg("PubKey packet recieved.~n Payload: ~p~n", [Payload]),
    process_object(<<"pubkey">>, Payload, State, Fun);

analyse_packet(<<"pubkey", _/bytes>>, Length, <<PNonce:64/big-integer,
                                          Time:64/big-integer,
                                          AVer:8/big-integer,
                                          Packet/bytes>> = Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
        when Time /= 0, AVer >= 2 ->
    error_logger:info_msg("PubKey packet recieved.~p~n", [self()]),
    Fun = fun(_) ->
            {_, Data} = bm_types:decode_varint(Packet),
            <<_BBitField:32/big-integer, PSK:64/bytes, PEK:64/bytes, _/bytes>> = Data,
            Ripe = bm_auth:generate_ripe(binary_to_list(<<4, PSK/bytes, 4, PEK/bits>>)),
            bm_db:insert(pubkey, [ #pubkey{hash=Ripe, data=Payload, time=Time, psk=PSK, pek=PEK} ]),
            %TODO
            %advertise_pubkey(),
            State 
    end,
    %error_logger:info_msg("PubKey packet recieved.~n Payload: ~p~n", [Payload]),
    process_object(<<"pubkey">>, Payload, State, Fun);
%analyse_packet(<<"msg", _/bytes>>, _Length, <<_POW:8/bytes, 
%                                              Time:32/big-integer,
%                                              Stream:8/integer, 
%                                              EMessage/bytes>> = Payload,
%                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
%        when Time /= 0 ->
%    error_logger:info_msg("Msg packet recieved. ~p~n", [self()]),
%    Fun = fun(Hash) ->
%            % TODO:
%            % check_ackdata(Payload),
%            bm_message_decryptor:decrypt_message(EMessage, Hash),
%            State
%    end, 
%    process_object(<<"msg">>, Payload, State, Fun);
%analyse_packet(<<"msg", _/bytes>>, _Length, <<_POW:8/bytes, 
%                                              Time:64/big-integer,
%                                              Stream:8/integer, 
%                                              EMessage/bytes>> = Payload,
%                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State)
%        when Time /= 0 ->
%    error_logger:info_msg("Msg packet recieved. ~p~n", [self()]),
%    Fun = fun(Hash) ->
%            % TODO:
%            % check_ackdata(Payload),
%            bm_message_decryptor:decrypt_message(EMessage, Hash),
%            State
%    end, 
%    process_object(<<"msg">>, Payload, State, Fun);
%analyse_packet(<<"broadcast", _/bytes>>, _Length, <<_POW:8/bytes, 
%                                                    Time:32/big-integer,
%                                                    BVer:8/big-integer,
%                                                    _Stream:8/integer, 
%                                                    EMessage/bytes>> = Payload,
%               #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
%        when Time /= 0, BVer =< 2 ->
%    error_logger:info_msg("Broadcast packet recieved.~n Pid: ~p~n", [self()]),
%    Fun = fun(Hash) ->
%            case BVer of
%                1 ->
%                    bm_dispatcher:broadcast_arrived(EMessage, Hash, broadcast);
%                2 ->
%                    bm_message_decryptor:decrypt_broadcast(EMessage, Hash);
%                _ ->
%                    ok
%            end,
%            State
%    end, 
%    process_object(<<"broadcast">>, Payload, State, Fun);
%analyse_packet(<<"broadcast", _/bytes>>, _Length, <<_POW:8/bytes, 
%                                              Time:64/big-integer,
%                                              BVer:8/big-integer, 
%                                              _Stream:8/integer, 
%                                              EMessage/bytes>> = Payload,
%                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) 
%        when Time /= 0, BVer =< 2 ->
%    error_logger:info_msg("Broadcast packet recieved.~n Pid: ~p~n", [self()]),
%    Fun = fun(Hash) ->
%            case BVer of
%                1 ->
%                    bm_dispatcher:broadcast_arrived(EMessage, Hash, broadcast);
%                2 ->
%                    bm_message_decryptor:decrypt_broadcast(EMessage, Hash);
%                _ ->
%                    ok
%            end,
%            State
%    end, 
%    process_object(<<"broadcast">>, Payload, State, Fun);
    
analyse_packet(Command, _, Payload,
                 #state{init_stage=#init_stage{verack_recv=true, verack_sent=true}} = State) ->
    error_logger:info_msg("Other packet recieved.~n Command: ~p~nPayload: ~p~n", [Command, Payload]),
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
    %error_logger:info_msg("Sending version message ~n~p~n", [bm_message_creator:create_message(<<"version">>,Message)]),
    Transport:send(Socket, bm_message_creator:create_message(<<"version">>, Message)).

send_getdata(Objs, #state{socket=Socket, transport=Transport} = _State) ->
    error_logger:info_msg("Getdata packet sent.~n"),
    Payload = bm_types:encode_list(lists:flatten(Objs), fun(O) -> <<O/bytes>> end),
    Transport:send(Socket, bm_message_creator:create_message(<<"getdata">>, Payload)).



conection_fully_established(#state{socket=Socket, transport=Transport, stream=Stream, init_stage=#init_stage{verack_sent=true, verack_recv=true}}=State) ->
    bm_sender:register_peer(Socket),
    {ok, { Ip, Port }} = inet:peername(Socket),
    Time = bm_types:timestamp(),
    error_logger:info_msg("Connection to ~p fully established ~p~n", [Ip, self()]),
    % Check after here
    bm_sender:send_broadcast(bm_message_creator:create_message(<<"addr">>, bm_types:encode_network(#network_address{ip=Ip, port=Port, time=Time, stream=Stream}))),
    case bm_message_creator:create_addrs_for_stream(Stream) of
        {ok, Addrs, _} ->
            Transport:send(Socket, Addrs);
        empty ->
            ok
    end,
    case bm_message_creator:create_big_inv(Stream, []) of
        {ok, Invs, _} ->
            Transport:send(Socket, Invs); %TODO: aware objects excluding
        empty ->
            ok
    end,
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
    io:format("32 bit time ~p~n", [Type]),
    process_object(Type, <<POW:64/bits, Time:64/big-integer, AVer:8, Stream:8, Data/bytes>>, State, Fun);
process_object(<<"msg">>=Type, <<POW:64/bits, Time:64/big-integer, Stream:8, Data/bytes>>, State, Fun) when Time /= 0 -> %Fix for Msg w/o Addr Version
    process_object(Type, <<POW:64/bits, Time:64/big-integer, 0:8, Stream:8, Data/bytes>>, State, Fun);
process_object(Type, <<_:64/bits, Time:64/big-integer, _:8, Stream:8/big-integer, Data/bytes>> = Payload, #state{stream=OStream}=State, Fun) ->
    io:format("64 bit time ~p~n", [Type]),
    {MSec, Sec, _} = now(),
    CTime = MSec * 1.0e6 + Sec,
    if 
        Time > CTime; Time =< CTime - 48 * 3600 ->
            io:format("Error time ~p~n", [Time]),
            State;
        Stream == OStream ->
            io:format("OK time ~p~n", [Time]),
            <<Hash:32/bytes, _/bytes>> = bm_auth:dual_sha(Payload),
            case bm_db:lookup(inventory, Hash) of
                [_] ->
                    io:format("Has ~p~n", [Hash]),
                    State;
                [] ->
                    io:format("New ~p~n", [Hash]),
                    bm_db:insert(inventory, [ #inventory{hash=Hash, payload=Payload, type=Type, time=Time, stream=Stream} ]),
                    %broadcast_inv(Hash), % TODO
                    Fun(Hash)
            end;
        true ->
            State
    end.

update_peer_time(#state{socket=Socket, stream=Stream}) ->
    {MSec, Sec, _} = now(),
    Time = trunc(MSec * 1.0e6 + Sec),
    {ok, {Ip, Port}} = inet:peername(Socket),
    bm_db:insert(addr, [#network_address{time=Time, ip=Ip, port=Port, stream=Stream}]).

