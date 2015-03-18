-module(bm_reciever).
-include("../include/bm.hrl").

-behaviour(ranch_protocol).

%% API {{{1
-ifdef(TEST).
-compile([export_all]).
-else.
-export([
         start_link/4,
         start_link/0,
         init/0,
         init/4
        ]).
-endif.
%}}}

-record(init_stage,
        {
         verack_sent=false ::boolean(),
         verack_recv=false ::boolean()
        }).

-record(state,
        {
         socket :: inet:socket(),
         transport=gen_tcp :: module(),
         version :: integer(),
         stream=1 :: integer(),
         init_stage = #init_stage{} :: #init_stage{},
         remote_streams :: [integer()],
         remote_addr :: #network_address{},
         timeout=50000 :: non_neg_integer(),
         callback=bitmessage
        }).


%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec start_link(Ref, Socket, Transport, Opts) ->  {ok, Pid} when % {{{1
      Ref :: ranch:ref(),
      Socket :: inet:socket(),
      Transport :: module(),
      Opts :: [Opt],
      Opt :: term(),
      Pid :: pid().
start_link(Ref, Socket, Transport, Opts) ->
    proc_lib:start_link(?MODULE, init, [Ref, Socket, Transport, Opts], 10000).

-spec start_link() -> {ok, pid()} | {error, Reason :: term()}.  % {{{1
start_link() ->
    proc_lib:start_link(?MODULE, init, []).

%%%===================================================================
%%% callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @end
%%--------------------------------------------------------------------
-spec init(Ref, Socket, Transport, Opts) -> no_return() when  % {{{1
      Ref :: ranch:ref(),
      Socket :: inet:socket(),
      Transport :: module(),
      Opts :: [Opt],
      Opt :: term().
init(Ref, Socket, Transport, _Opts) ->
    ok = proc_lib:init_ack({ok, self()}),
    ok = ranch:accept_ack(Ref),
    loop(#state{socket=Socket, transport=Transport}).

-spec init() ->  no_return(). % {{{1
init() ->
    ok = proc_lib:init_ack({ok, self()}),
    bm_db:wait_db(),
    Socket =  connect_peer(),
    error_logger:info_msg("Connected ~p~n", [Socket]),
    send_version(#state{socket=Socket,
                        remote_addr=#network_address{ip={127,0,0,1},
                                                     port=8444,
                                                     time=bm_types:timestamp(),
                                                     stream=1}}),
    loop(#state{socket=Socket}).

%%%===================================================================
%%% Internal functions TODO: refactor to 2 mod
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Main loop
%%
%% @end
%%--------------------------------------------------------------------
-spec loop(#state{}) -> no_return().  % {{{1
loop(#state{socket = Socket,
            transport = Transport,
            callback=Callback,
            timeout=Timeout}=IState) ->
    case Transport:recv(Socket,0, Timeout) of
        {ok, Packet} ->
            State = check_packet(Packet, IState),
            loop(State);
        {error, closed} ->
            error_logger:info_msg("Socket ~p closed~n", [Socket]),
            bm_sender:unregister_peer(Socket),
            NSocket =  connect_peer(),
            error_logger:info_msg("NConnected ~p~n", [Socket]),
            send_version(#state{socket=NSocket,
                                transport=Transport,
                                remote_addr=#network_address{ip={127,0,0,1},
                                                             port=8444,
                                                             time=bm_types:timestamp(),
                                                             stream=1}}),
            loop(IState#state{socket=NSocket,
                             init_stage=#init_stage{}});
        {error, R} ->
            error_logger:warning_msg("Socket ~p error: ~p~n", [Socket, R]),
            Transport:close(Socket),
            loop(IState)
    end.
%%--------------------------------------------------------------------
%% @private
%% @doc
%% Check packet correctnes
%%
%% @end
%%--------------------------------------------------------------------
-spec check_packet(binary(), #state{}) -> #state{}.  % {{{1

%% Packet has full message and more  {{{2
check_packet(<<?MAGIC,
               Command:12/bytes,
               Length:32,
               Check:4/bytes,
               Packet/bytes>>,
             State) when size(Packet) > Length ->
    <<NPacket:Length/bytes, Rest/bytes>> = Packet,
    NState = check_packet(<<?MAGIC,
                            Command:12/bytes,
                            Length:32,
                            Check:4/bytes,
                            NPacket/bytes>>,
                          State),
    check_packet(Rest, NState);

%% Packet has only full message  {{{2
check_packet(<<?MAGIC,
               Command:12/bytes,
               Length:32,
               Check:4/bytes,
               Packet/bytes>>,
             State) when size(Packet) == Length ->
    case crypto:hash(sha512, Packet) of
        <<Check:32/bits, _/bits>> ->
            update_peer_time(State),
            analyse_packet(Command, Length, Packet, State);
        _ ->
            State
    end;

%% Packet doesn't have full message  {{{2
check_packet(<<?MAGIC,
               _Command:12/bytes,
               Length:32,
               _Check:4/bytes,
               Packet/bytes>>=IPacket,
             #state{socket=Socket,
                    timeout=Timeout,
                    transport=Transport}=State) when size(Packet) < Length ->

     case Transport:recv(Socket, Length - size(Packet), Timeout) of
        {ok, Data} ->
                check_packet(<<IPacket/bytes, Data/bytes>>, State);
        {error, timeout} ->
                check_packet(IPacket, State);
        {error, close} ->
            loop(State#state{socket=Socket,
                             transport=Transport});
        {error, R} ->
            loop(State)
    end;

%% Default  % {{{2
check_packet(_, State) ->
    State.

%%--------------------------------------------------------------------
%% @doc
%% Analysing packets structure
%%
%% @end
%%--------------------------------------------------------------------
-spec analyse_packet(Command, Length, Payload, State) -> State when  % {{{1
      Command :: <<_:96>>,
      Length :: non_neg_integer(),
      Payload :: binary(),
      State :: #state{}.

%% Messages {{{2

%% Version packet  {{{3
analyse_packet(<<"version",
                 _/bytes>>,
               Length,
               <<Version:32/big-integer,
                 1:64/big-integer, % 'services' field of protocol
                 Time:64/big-integer,
                 _AddrRecv:26/bytes,
                 AddrFrom:26/bytes,
                 _Nonce:8/bytes,
                 Data/bytes>>,
              #state{stream=Stream,
                     init_stage=InitStage}=State) when Length > 83,
                                                       Version >= 3 ->
    {_UA, StremsL} = bm_types:decode_varstr(Data),
    {Streams, _} = bm_types:decode_list(StremsL, fun bm_types:decode_varint/1),
    #state{transport=Transport, socket=Socket} = State,
    % Sending verack
    Transport:send(Socket, bm_message_creator:create_message(<<"verack">>, <<>>)),
    Stage = InitStage#init_stage{verack_sent=true},
    PeerAddr = <<Time:64/big-integer,
                 Stream:32/big-integer,
                 AddrFrom/bytes>>,
    {RAddr, _} = bm_types:decode_network(PeerAddr),
    OState = State#state{version=Version,
                         init_stage=Stage,
                         remote_streams=Streams,
                         remote_addr=RAddr},

    if Stage#init_stage.verack_recv == false ->
            send_version(OState);
        true ->
            conection_fully_established(OState)
            
    end,
    OState;

analyse_packet(<<"version",
                 _/bytes>>,
               Length,
               <<Version:32/big-integer,
                 1:64/big-integer, % 'services' field of protocol
                 _Time:64/big-integer,
                 _AddrRecv:26/bytes,
                 _AddrFrom:26/bytes,
                 _Nonce:8/bytes,
                 _Data/bytes>>,
              #state{transport=Transport,
                     socket=Socket}=State) when Version < 3 ->
    Transport:close(Socket),
    State;
%% Verack maessage  {{{3
analyse_packet(<<"verack", _/bytes>>, 0, <<>>, State) ->
    OState = State#state{
               init_stage=State#state.init_stage#init_stage{
                                        verack_recv=true
                                       }},
    conection_fully_established(OState),
    OState;

%% Addr message  {{{3
analyse_packet(<<"addr", _/bytes>>,
               _Length,
               Data,
               #state{
                  init_stage=#init_stage{
                                verack_recv=true,
                                verack_sent=true
                               }} = State) ->
    {Addrs, _} = bm_types:decode_list(Data, fun bm_types:decode_network/1),
    bm_db:insert(addr, lists:flatten(Addrs)),
    State;

%% Inv message  {{{3
analyse_packet(<<"inv",_/bytes>>,
               Length,
               Packet, 
               #state{
                  init_stage=#init_stage{
                                verack_recv=true,
                                verack_sent=true
                               }} = State) ->
    {ObjsToGet, _} = bm_types:decode_list(Packet, fun invs_to_list/1),
    send_getdata(ObjsToGet, State),
    State;

%% GetData message  {{{3
analyse_packet(<<"getdata", _/bytes>>,
               Length,
               Packet,
               #state{transport=Transport,
                      socket=Socket,
                      init_stage=#init_stage{verack_recv=true,
                                             verack_sent=true}} = State) ->
    {ObjToSend, _} = bm_types:decode_list(Packet,
                                          fun(<<I:32/bytes,
                                                R/bytes>>) -> {I, R} end),

    MsgToSeend = lists:map(fun create_obj/1, ObjToSend),
    lists:foreach(fun(Msg) -> Transport:send(Socket, Msg) end, MsgToSeend),
    State;

%% Ping message (seems obsolated) {{{3
analyse_packet(<<"ping", _>>,
               _Length,
               _Packet,
                 #state{
                    transport=Transport,
                    socket=Socket,
                    init_stage=#init_stage{
                                  verack_recv=true,
                                  verack_sent=true
                                 }} = State) ->
    % Sending pong
    Transport:send(Socket,
                   <<?MAGIC,
                     "pong",
                     0:8/unit:8-integer,
                     0:32/integer,
                     16#cf83e135:32/big-integer>>),
    State;

%%%
%% Objects  {{{2
%%%

%% Object for v3
analyse_packet(<<"object", _/bytes>>,
               _Length,
               <<PNonce:64/big-integer,
                 Time:64/big-integer,
                 Type:32/big-integer,
                 Packet/bytes>>=Payload,
               #state{transport=Transport,
                      socket=Socket,
                      stream=Stream,
                      init_stage=#init_stage{
                                    verack_recv=true,
                                    verack_sent=true
                                   }} = State) ->
    POW = bm_pow:check_pow(Payload),
    TTL = Time - bm_types:timestamp(),
    <<Hash:32/bytes, _/bytes>> = bm_auth:dual_sha(Payload),
    error_logger:info_msg("Received object: ~p~n", [bm_types:binary_to_hexstring( Hash )]),
    if 
        not POW; 
          TTL > 28 * 24 * 60 * 60 + 10800;
          TTL < -3600 -> 
            State;
        true ->
            {Version, R} = bm_types:decode_varint(Packet),
            case bm_types:decode_varint(R) of
                 {Stream, R1} ->
                    file:write_file(".test/data/broadcast1.bin", Payload),
                    process_object(Hash, Payload, State);
                _ when Stream == 1, Version == 1; Type == 2 ->
                    process_object(Hash, Payload, State);
                _ ->
                    State
            end
    end;
           
%% Unexpected message {{{3
analyse_packet(Command,
               _,
               Payload,
               State) ->
    error_logger:warning_msg("Other packet recieved.~n Command: ~p~nPayload: ~p~n State: ~p~n", [Command, Payload, State]),
    State.
               
%--------------------------------------------------------------------
%% @doc
%% Analyses objects
%%
%% @end
%%--------------------------------------------------------------------
-spec analyse_object(Type, Version, Time, InvHash, Payload, State) -> State when % {{{1
      Type :: object_type(),
      Time :: non_neg_integer(),
      Version :: non_neg_integer(),
      InvHash :: binary(),
      Payload :: binary(),
      State :: #state{}.
analyse_object(?GET_PUBKEY, 3, _Time, InvHash, Data, State) when size(Data) == 20 ->  % {{{2
    error_logger:info_msg("Requested AVer: 3~n"),
    RIPE = case Data of
               <<0, 0, R/bytes>> when size(R) == 18 ->
                   R;
               <<0, R/bytes>> when size(R) == 19 ->
                   R;
               R ->
                   R
           end,
    Stream = State#state.stream,
    case bm_db:lookup(privkey, RIPE) of
        [#privkey{hash=RIPE,
                  address=Addr,
                  enabled=true}=PrKey] ->
            #address{version=3,
                     stream=Stream,
                     ripe=Ripe} = bm_auth:decode_address(Addr),
            error_logger:info_msg("It's my address - sending pubkey~n"),
            bm_sender:send_broadcast(bm_message_creator:create_pubkey(PrKey)),
            State;
        [] ->
            State
    end;
analyse_object(?GET_PUBKEY, 4, _Time, InvHash, Data, State) when size(Data) /= 32 ->  % {{{2
    error_logger:info_msg("Requested AVer: 4~n"),
    case bm_db:lookup(privkey, Data) of
        [#privkey{hash=RIPE,
                  address=Addr,
                  enabled=true}=PrKey] ->
            #address{version=4,
                     stream=Stream,
                     ripe=Ripe} = bm_auth:decode_address(Addr),
            error_logger:info_msg("It's my address - sending pubkey~n"),
            bm_sender:send_broadcast(bm_message_creator:create_pubkey(PrKey)),
            State;
        [] ->
            State
    end;
analyse_object(?PUBKEY, 3, Time, InvHash, Data, State) when size(Data) >= 170 ->  % {{{2
    <<_BBitField:32/big-integer,
      PSK:64/bytes,
      PEK:64/bytes,
      Rest/bytes>> = Data,
    Ripe = bm_auth:generate_ripe(binary_to_list(<<4, PSK/bytes, 4, PEK/bits>>)),
    {NTpB, R} = bm_types:decode_varint(Rest),
    {PLEB, _R1} = bm_types:decode_varint(Rest),
    Pubkey = #pubkey{hash=Ripe,
                     data=Data, % Seems useless ???
                     time=Time,
                     ntpb=NTpB,
                     pleb=PLEB,
                     psk=PSK,
                     pek=PEK},
    bm_db:insert(pubkey, [Pubkey]),
    bm_message_encryptor:pubkey(Pubkey),
    State;
analyse_object(?PUBKEY,  % {{{2
               4,
               Time,
               InvHash,
               Data,
               State) when size(Data) >= 350 ->
    %% TODO
    <<_Tag:32/bytes, Encrypted/bytes>> = Data,
    bm_message_decryptor:decrypt(Encrypted, InvHash),
    State;
analyse_object(?MSG,  % {{{2
               _Version,
               Time,
               InvHash,
               Data,
               State) ->
    case check_ackdata(Data) of
        true ->
            error_logger:info_msg("This is ACK for me"),
            State;
        false ->
            error_logger:info_msg("This is not ACK for me, trying to decrypt"),
            bm_message_decryptor:decrypt(Data, InvHash),
            State
    end;
analyse_object(?BROADCAST,  % {{{2
               Version,
               _Time,
               InvHash,
               Data,
               State) when size(Data) > 160 ->
            case Version of
                V when V ==2; 
                       V == 3 ->
                    bm_message_decryptor:decrypt(Data, InvHash),
                    State;
                V when V == 4; 
                       V == 5 ->
                    <<_Tag:32/bytes, Encrypted/bytes>> = Data,
                    bm_message_decryptor:decrypt(Encrypted, InvHash),
                    State;
                _ ->
                    State
            end;
analyse_object(?GETFILECHUNK,  % {{{2
               1,
               _Time,
               InvHash,
               Data,
               State) when size(Data) > 160 ->
    <<FileHash:64/bytes, ChunkHash:64/bytes>> = Data,
    bm_attachment_srv:send_chunk(FileHash, ChunkHash);
analyse_object(_, _Data, _Time, _InvHash, _Payload, State) ->  % {{{2
    State.
%%%
%% Responce sending routines
%%%

%% Send version
-spec send_version(#state{}) -> ok | {error, atom()}.  % {{{1
send_version(#state{transport=Transport,
                    socket=Socket,
                    stream=Stream,
                    remote_addr=RAddr } = _State) ->
    send_version(Transport, Socket, Stream, RAddr). 

-spec send_version(Transport, Socket, Stream, Addr) -> ok   % {{{1
                                                       | {error, atom()} when
      Transport :: atom(),
      Socket :: inet:socket(),
      Stream :: integer(),
      Addr :: #network_address{}.
send_version(Transport, Socket, Stream, RAddr) ->
    Time = bm_types:timestamp(),
    {ok, {Ip, Port}} = inet:sockname(Socket),
    <<_:12/bytes,
      AddrRecv/bytes>> = bm_types:encode_network(RAddr),
    <<_:12/bytes,
      AddrFrom/bytes>> = bm_types:encode_network(#network_address{time=Time,
                                                                  stream=Stream,
                                                                  ip=Ip,
                                                                  port=Port}),
    Nonce = crypto:rand_bytes(8),
    Streams = bm_types:encode_list([Stream], fun bm_types:encode_varint/1),
    Message = <<3:32/big-integer,
                1:64/big-integer, % 'services' field of protocol
                Time:64/big-integer,
                AddrRecv:26/bytes,
                AddrFrom:26/bytes,
                Nonce:8/bytes,
                (bm_types:encode_varstr("/BitMessageErl:0.1/"))/bytes,
                Streams/bytes>>,
    Transport:send(Socket, bm_message_creator:create_message(<<"version">>, Message)).

-spec send_getdata(list(), #state{}) -> ok | {error, atom()}.  % {{{1
send_getdata(Objs,
             #state{socket=Socket,
                    transport=Transport} = _State) ->
    Payload = bm_types:encode_list(lists:flatten(Objs), fun(O) -> <<O/bytes>> end),
    Transport:send(Socket, bm_message_creator:create_message(<<"getdata">>, Payload)).



-spec conection_fully_established(#state{}) -> #state{}.  % {{{1
conection_fully_established(#state{socket=Socket,
                                   transport=Transport,
                                   stream=Stream,
                                   callback=Callback,
                                   init_stage=#init_stage{
                                                 verack_sent=true,
                                                 verack_recv=true
                                                }}=State) ->
    bm_sender:register_peer(Socket),
    {ok, { Ip, Port }} = inet:peername(Socket),
    Time = bm_types:timestamp(),
    % Check after here

    bm_sender:send_broadcast(
      bm_message_creator:create_message(
        <<"addr">>,
        bm_types:encode_network(
          #network_address{ip=Ip,
                           port=Port,
                           time=Time,
                           stream=Stream}))),

    Addrs = bm_message_creator:create_addrs_for_stream(Stream),
    lists:foreach(fun(Addr) ->
                          Transport:send(Socket, Addr),
                          ok
            end, Addrs),
    Invs = bm_message_creator:create_big_inv(Stream, []),
    lists:foreach(fun(I) ->
                          Transport:send(Socket, I),
                          ok 
                  end,
                  Invs), %TODO: aware objects excluding
    State#state{timeout=600000};
conection_fully_established(State) ->
    State.

%%%
%% Some packet decoders
-spec invs_to_list(binary()) -> {binary() | [], binary()}.  % {{{1
invs_to_list(<<Inv:32/bytes, Rest/bytes>>) ->
    case bm_db:lookup(inventory, Inv) of
        [] ->
            error_logger:info_msg("Sending get_data for: ~p~n", [bm_types:binary_to_hexstring(Inv)]),
            {Inv , Rest};
        _ ->

            {[], Rest}
    end.
%% Process object
-spec process_object(Hash, Payload, State) -> State when  % {{{1
      Hash :: binary(),
      Payload :: binary(),
      State :: #state{}.
process_object(Hash,
                     <<_POW:64/big-integer,
                       Time:64/big-integer,
                       Type:32/big-integer,
                       Packet/bytes>>=Payload,
                     #state{
                        stream=Stream
                       } = State) ->
    {Version, R1} = bm_types:decode_varint(Packet),
     R = case bm_types:decode_varint(R1) of
         {Stream, R2} ->
             R2;
         R2 ->
             R2
     end,
    case bm_db:lookup(inventory, Hash) of
        [_] ->
            State;
        [] ->
            bm_db:insert(inventory,
                         [ #inventory{hash=Hash,
                                      payload=Payload,
                                      type=Type,
                                      time=Time,
                                      stream=Stream} ]),
            bm_sender:send_broadcast(
              bm_message_creator:create_inv([ Hash ])),
            error_logger:info_msg("Requested Type: ~p Ver: ~p Size: ~p~n", [Type, Version, size(R)]),

            analyse_object(Type, Version, Time, Hash, R, State)
    end.

%%%
%% Helpers
%%%

-spec update_peer_time(#state{}) -> any().  % {{{1  ???
update_peer_time(#state{socket=Socket, stream=Stream}) ->
    {MSec, Sec, _} = now(),
    Time = trunc(MSec * 1.0e6 + Sec),
    {ok, {Ip, Port}} = inet:peername(Socket),
    bm_db:insert(addr,
                 [#network_address{time=Time,
                                   ip=Ip,
                                   port=Port,
                                   stream=Stream}]).

-spec check_ackdata(binary()) -> boolean().  % {{{1
check_ackdata(Payload) ->
    case bm_db:match(message,
                     #message{ackdata=Payload,
                              folder=sent,
                              status=ackwait,
                              _='_'}) of
        [] ->
            false;
        [ Message ] ->
            error_logger:info_msg("Recv ack: ~p~n", [Message#message.hash]),
            bm_db:insert(message, [Message#message{status=ok}]),
            true
    end.

%% @private
%% @doc Creates object message by inventory hash
%%
%% Creates object message looking inventory for `Hash`
%% in database and creating `Message`
-spec create_obj([Hash]) -> message_bin() | no_return() when   % {{{1 ???
      Hash ::binary().
create_obj(Hash) ->
    case bm_db:lookup(inventory, Hash) of
        [#inventory{payload=Payload}] -> 
            bm_message_creator:create_message(<<"object">>, Payload);
        _ ->
            error_logger:warning_msg("Can't find inv ~p~n", [Hash])
    end.

-spec connect_peer() -> Ret when  % {{{1
      Ret :: inet:socket().
connect_peer() ->
    #network_address{ip=Ip,
                     port=Port,
                     stream=_Stream,
                     time=_Time} = bm_db:get_net(), 

    case gen_tcp:connect(Ip,
                         Port,
                         [inet,
                          binary,
                          {active,false},
                          {reuseaddr, true},
                          {packet, raw}],
                         10000) of
        {ok, Socket} ->
            Socket;
        {error, _Reason} ->
            connect_peer()
    end.
