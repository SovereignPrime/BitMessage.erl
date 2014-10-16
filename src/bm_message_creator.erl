-module(bm_message_creator).
-compile([export_all]).

-include("../include/bm.hrl").

create_message(Command, Payload) ->  % {{{1
    Length = size(Payload),
    CL = byte_size(Command),
    C = <<Command/bytes, 0:(12 - CL)/unit:8>>,
    <<Check:4/bytes, _/bytes>> = crypto:hash(sha512, Payload),
    <<?MAGIC, C:12/bytes, Length:32/big-integer, Check:4/bytes, Payload/bytes>>.

create_obj(Hash) ->  % {{{1
    case bm_db:lookup(inventory, Hash) of
            [#inventory{type=Type, payload=Payload}] -> 
            create_message(Type, Payload);
        [] ->
            error_logger:warning_msg("Can't find inv ~p~n", [Hash])
    end.

create_inv(Hash) ->  % {{{1
    create_message(<<"inv">>, bm_types:encode_list(Hash, fun(H) -> H end)).

create_big_inv(Stream, Exclude) ->  % {{{1
    {ok, PubKeyAge} = application:get_env(bitmessage, 'max_age_of_public_key'),
    {ok, InvAge} = application:get_env(bitmessage, 'max_age_of_inventory'),
    {MSec, Sec, _} = now(),
    Time = trunc(MSec * 1.0e6 + Sec),
    PubOld = Time - PubKeyAge,
    Old = Time - InvAge,
    InvList =  bm_db:select(inventory, [
                {#inventory{stream=Stream, hash='$1', time='$2', type = <<"pubkey">>, _='_'}, [{'>', '$2', PubOld}], ['$1']},
                {#inventory{stream=Stream, hash='$1', time = '$2', type='$3', _='_'}, [{'>', '$2', Old}, {'/=', '$3', <<"pubkey">>}], ['$1']}
                ], 5000),
    lists:map(fun(Inv) ->
                create_message(<<"inv">>, bm_types:encode_list(Inv, fun(O) -> <<O/bytes>> end))
        end, InvList).

create_addrs_for_stream(Stream) ->  % {{{1
    {ok, NodeAge} = application:get_env(bitmessage, 'max_age_of_node'),
    {MSec, Sec, _} = now(),
    Time = trunc(MSec * 1.0e6 + Sec),
    Old = Time - NodeAge,
    Hashes = bm_db:select(addr, [
                {#network_address{stream=Stream, time='$2', ip='$3', port='$4'}, [{'>', '$2', Old}], ['$_']},
                {#network_address{stream=Stream * 2, time='$2', ip='$3', port='$4'}, [{'>', '$2', Old}], ['$_']},
                {#network_address{stream=Stream * 2 + 1, time='$2', ip='$3', port='$4'}, [{'>', '$2', Old}], ['$_']}
                ], 1000),
            lists:map(fun(Hash) ->  
                    create_message(<<"addr">>, bm_types:encode_list(Hash, fun bm_types:encode_network/1))
        end, Hashes).

create_pubkey(#privkey{hash=RIPE,  % {{{1
                       psk=PSK,
                       pek=PEK,
                       public=Pub,
                       address=Addr}) ->
    Time = bm_types:timestamp() + crypto:rand_uniform(-300, 300),
    #address{stream=Stream, version=AVer} = bm_auth:decode_address(Addr),
    Payload = <<Time:64/big-integer,
                AVer,
                Stream,
                1:32/big-integer,
                Pub:128/bytes,
                (bm_types:encode_varint(320))/bytes,
                (bm_types:encode_varint(14000))/bytes>>,
    Sig = crypto:sign(ecdsa, sha, Payload, [PSK, secp256k1]),
    NPayload = <<Payload/bytes, (bm_types:encode_varint(size(Sig)))/bytes, Sig/bytes>>,
    POW = bm_pow:make_pow(NPayload),
    PPayload = <<POW:64/big-integer, NPayload/bytes>>,
    <<Hash:32/bytes, _/bytes>> = crypto:hash(sha512, PPayload),
    bm_db:insert(inventory, [#inventory{hash=Hash,
                                       payload = PPayload,
                                       type = <<"pubkey">>,
                                       time=Time,
                                        stream=Stream}]),
    create_inv([ Hash ]).
                                       
create_getpubkey(#address{ripe=RIPE, version=Version, stream=Stream}) ->  % {{{1
    Time = bm_types:timestamp() + crypto:rand_uniform(-300, 300),
    UPayload = <<(bm_types:timestamp() + crypto:rand_uniform(-300, 300)):64/big-integer,
                 (bm_types:encode_varint(Version))/bytes,
                 (bm_types:encode_varint(Stream))/bytes,
                 RIPE:20/bytes>>,
    POW = bm_pow:make_pow(UPayload),
    Payload = <<POW:64/big-integer, UPayload/bytes>>,
    <<Hash:32/bytes, _/bytes>> = crypto:hash(sha512, Payload),
    bm_db:insert(inventory, [#inventory{hash=Hash,
                                       payload = Payload,
                                       type = <<"getpubkey">>,
                                       time=Time,
                                        stream=Stream}]),
    create_inv([ Hash ]).

create_ack(#message{ackdata=Payload, from=Addr}) ->  % {{{1
    <<_:16/bytes, PLen:32/big-integer, _:4/bytes, PPayload/bytes>> = Payload,
    <<Hash:32/bytes, _/bytes>> = bm_auth:dual_sha(PPayload),
    error_logger:info_msg("Sending ack: ~p~n", [bm_types:binary_to_hexstring(Hash)]),
    <<_:8/bytes, Time:64/big-integer, Stream, _/bytes>> = PPayload,
    bm_db:insert(inventory, [#inventory{hash=Hash,
                                       payload = PPayload,
                                       type = <<"msg">>,
                                       time=Time,
                                       stream=Stream}]),
    create_inv([ Hash ]).
