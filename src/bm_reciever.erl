-module(bm_reciever).
-include("../include/bm.hrl").

-compile([export_all]).
%% API {{{1
-export([
         start_link/4,
         start_link/0,
         init/1,
         init/4
        ]).
%}}}

-record(init_stage,
        {
         verack_sent=false ::boolean(),
         verack_recv=false ::boolean()
        }).

-record(state,
        {
         socket :: gen_tcp:socket(),
         transport :: atom(),
         version :: integer(),
         stream=1 :: integer(),
         init_stage = #init_stage{} :: #init_stage{},
         remote_streams :: [integer()],
         remote_addr :: #network_address{}
        }).


%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
start_link(Ref, Socket, Transport, Opts) ->  % {{{1
    proc_lib:start_link(?MODULE, init, [Ref, Socket, Transport, Opts]).

start_link() ->  % {{{1
    proc_lib:start_link(?MODULE, init, [self()]).

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
init(Ref, Socket, Transport, _Opts) ->  % {{{1
    ok = ranch:accept_ack(Ref),
    loop(#state{socket=Socket, transport=Transport}).

init(Parent) ->  % {{{1
    ok = proc_lib:init_ack(Parent, {ok, self()}),
    timer:sleep(1000),
    {Transport, Socket} =  bm_connetion_dispatcher:get_socket(),
    send_version(#state{socket=Socket, transport=Transport, remote_addr=#network_address{ip={127,0,0,1}, port=8444, time=bm_types:timestamp(), stream=1}}),
    loop(#state{socket=Socket, transport=Transport}).

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
-spec loop(#state{}) -> no_return().
loop(#state{socket = Socket, transport = Transport}=IState) ->  % {{{1
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
                    transport=Transport}=State) when size(Packet) < Length ->

     case Transport:recv(Socket, Length - size(Packet), 5000) of
        {ok, Data} ->
                check_packet(<<IPacket/bytes, Data/bytes>>, State);
        {error, timeout} ->
                check_packet(IPacket, State);
        {error, close} ->
            bm_sender:unregister_peer(Socket),
            {NTransport, NSocket} =  bm_connetion_dispatcher:get_socket(),
            send_version(#state{
                            socket=NSocket,
                            transport=NTransport,
                            remote_addr=#network_address{
                                           ip={127,0,0,1},
                                           port=8444,
                                           time=bm_types:timestamp(),
                                           stream=1}}),
            loop(State#state{socket=NSocket,
                             transport=NTransport});
        {error, R} ->
            bm_sender:unregister_peer(Socket),
            Transport:close(Socket),
            {NTransport, NSocket} = bm_connetion_dispatcher:get_socket(),
            send_version(#state{
                            socket=NSocket,
                            transport=NTransport,
                            remote_addr=#network_address{
                                           ip={127,0,0,1},
                                           port=8444,
                                           time=bm_types:timestamp(),
                                           stream=1}}),
            loop(State#state{socket=NSocket,
                             transport=NTransport,
                             init_stage=#init_stage{}})
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
    bm_db:insert(addr, Addrs),
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
                      init_stage=#init_stage{
                                    verack_recv=true,
                                    verack_sent=true
                                   }} = State) ->
    POW = bm_pow:check_pow(Payload),
    TTL = Time - bm_types:timestamp(),
    error_logger:info_msg("POW: ~p TTL: ~p~n", [POW, TTL]),
    if 
        not POW; 
          TTL > 28 * 24 * 60 * 60 + 10800;
          TTL < -3600 -> 
            State;
        true ->
            bm_reciever:analyse_object(Type, Packet, State)
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
-spec analyse_object(Payload, State) -> State when % {{{1
      Payload :: binary(),
      State :: #state{}.
analyse_object(0, Data, State) when size(Data) > 22,
                                    size(Data) < 180 ->
    {Version, R} = bm_types:decode_varint(Data),
    {Stream, R1} = bm_types:decode_varint(R),
analyse_object(1, Data, State) when size(Data) > 125,
                                    size(Data) < 421 ->
    {Version, R} = bm_types:decode_varint(Data),
    {Stream, R1} = bm_types:decode_varint(R),
analyse_object(2, Data, State) ->
    %{Version, R} = bm_types:decode_varint(Data),
    R = Data,
    {Stream, R1} = bm_types:decode_varint(R),
analyse_object(3, Data, State) when size(Data) > 160 ->
    {Version, R} = bm_types:decode_varint(Data),
    {Stream, R1} = bm_types:decode_varint(R),
analyse_object(_, Payload, State) ->
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
      Socket :: gen_tcp:socket(),
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
    State;
conection_fully_established(State) ->
    State.

%%%
%% Some packet decoders
-spec invs_to_list(binary()) -> {binary() | [], binary()}.  % {{{1
invs_to_list(<<Inv:32/bytes, Rest/bytes>>) ->
    case bm_db:lookup(inventory, Inv) of
        [] ->
            {Inv , Rest};
        _ ->

            {[], Rest}
    end.

%% Process object
-spec process_object(Type, Object, State, Fun) -> #state{} when  % {{{1
      Type :: binary(),
      Object :: binary(),
      State :: #state{},
      Fun :: fun((binary()) -> #state{}).

%% Process object w/32 bit time {{{2
process_object(Type,
               <<POW:64/bits,
                 Time:32/big-integer,
                 AVer:8,
                 Stream:8,
                 Data/bytes>> = Payload,
               State,
               Fun) when Time /= 0 -> %Fix for 4 bytes time
    process_object(Type, <<POW:64/bits, Time:64/big-integer, AVer:8, Stream:8, Data/bytes>>, State, Fun, bm_pow:check_pow(Payload));

%% Process msg object w/o address version {{{2
process_object(<<"msg">>=Type,
               <<POW:64/bits,
                 Time:64/big-integer,
                 Stream:8,
                 Data/bytes>> = Payload,
               State,
               Fun) when Time /= 0,
                         Stream /= 0 -> %Fix for Msg w/o Addr Version
    process_object(Type, <<POW:64/bits, Time:64/big-integer, 0:8, Stream:8, Data/bytes>>, State, Fun, bm_pow:check_pow(Payload));

%% Process default object  {{{2
process_object(Type, Payload, State, Fun) ->
    process_object(Type, Payload, State, Fun, bm_pow:check_pow(Payload)).

-spec process_object(Type, Object, State, Fun, POW) -> #state{} when  % {{{1
      Type :: binary(),
      Object :: binary(),
      State :: #state{},
      POW :: boolean(),
      Fun :: fun((binary()) -> #state{}).

%% Process object  {{{2
process_object(Type,
               <<_:64/bits,
                 Time:64/big-integer,
                 _:8,
                 Stream:8/big-integer,
                 _Data/bytes>> = Payload,
               #state{stream=OStream}=State,
               Fun,
               true) ->
    CTime = bm_types:timestamp(),
    if 
        Type == <<"pubkey">>, Time =< CTime - 30 * 24 * 3600 ->
            State;
        Type /= <<"pubkey">>, Time =< CTime - 48 * 3600 -> 
            State;
        Time > CTime + 10800 ->
            State;
        Stream == OStream ->
            <<Hash:32/bytes, _/bytes>> = bm_auth:dual_sha(Payload),
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
                    bm_sender:send_broadcast(bm_message_creator:create_inv([ Hash ])),
                    Fun(Hash)
            end;
        true ->
            State
    end;
%% Process object w/o POW  {{{2
process_object(_Type, _Payload, State, _Fun, false) ->
    State.

%% Fun generators for different objects  {{{1
-spec pubkey_fun_generator(binary(),  % {{{2
                           binary(),
                           integer(),
                           #state{}) -> fun((binary()) -> #state{}).
pubkey_fun_generator(Payload, Packet, Time, State) ->
    fun(_) ->
            {_, Data} = bm_types:decode_varint(Packet),
            <<_BBitField:32/big-integer, PSK:64/bytes, PEK:64/bytes, _/bytes>> = Data,
            Ripe = bm_auth:generate_ripe(binary_to_list(<<4, PSK/bytes, 4, PEK/bits>>)),
            Pubkey = #pubkey{hash=Ripe,
                             data=Payload,
                             time=Time,
                             psk=PSK,
                             pek=PEK},
            bm_db:insert(pubkey, [Pubkey]),
            bm_message_encryptor:pubkey(Pubkey),
            State 
    end.

-spec get_pubkey_fun_generator(binary(),  %% {{{2
                              #state{}) -> fun((binary()) -> #state{}).
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
                [#privkey{hash=RIPE,
                          address=Addr,
                          enabled=true}=PrKey] ->
                    #address{version=Version,
                             stream=Stream,
                             ripe=Ripe} = bm_auth:decode_address(Addr),
                    bm_sender:send_broadcast(bm_message_creator:create_pubkey(PrKey)),
                    State;
                [] ->
                    State
            end
    end.

-spec msg_fun_generator(binary(), State) -> fun((binary()) -> State) when  %  {{{2
 State :: #state{}.
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

-spec broadcast_fun_generator(integer(),  % {{{2
                              binary(),
                              State) ->  fun((binary()) -> State) when
      State :: #state{}.
broadcast_fun_generator(BVer, EMessage, State) ->
    fun(Hash) ->
            case BVer of
                1 ->
                    bm_dispatcher:broadcast_arrived(EMessage,
                                                    Hash,
                                                    <<"broadcast">>), %% DEPRECATED
                    State;
                2 ->
                    bm_message_decryptor:decrypt_broadcast(EMessage, Hash),
                    State;
                _ ->
                    State
            end
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
    case bm_db:match(sent, #message{ackdata=Payload,
                                    status=ackwait,
                                    _='_'}) of
        [] ->
            false;
        [Message] ->
            error_logger:info_msg("Recv ack: ~p~n", [Message#message.hash]),
            bm_db:insert(sent, [Message#message{status=ok}]),
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
            [#inventory{type=Type, payload=Payload}] -> 
            bm_message_creator:create_message(Type, Payload);
        [] ->
            error_logger:warning_msg("Can't find inv ~p~n", [Hash])
    end.

