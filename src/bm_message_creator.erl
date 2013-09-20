-module(bm_message_creator).
-compile([export_all]).

-include("../include/bm.hrl").

create_message(Command, Payload) ->
    Length = size(Payload),
    CL = byte_size(Command),
    C = <<Command/bytes, 0:(12 - CL)/unit:8>>,
    <<Check:4/bytes, _/bytes>> = crypto:hash(sha512, Payload),
    %error_logger:info_msg("Sending  message ~nCommand: ~p~nPayload: ~p~nLength: ~p~n, Check: ~p~n", [C, Payload, Length, Check]),
    <<?MAGIC, C:12/bytes, Length:32/big-integer, Check:4/bytes, Payload/bytes>>.

create_obj(Hash) ->
    [#inventory{type=Type, payload=Payload}] = bm_db:lookup(Hash),
    create_message(Type, Payload).

create_inv(Hash) ->
    create_message(<<"inv">>, bm_types:encode_list(Hash, fun(H) -> H end)).

create_big_inv(Stream, Exclude) ->
    PubKeyAge = application:get_env(bitmessage, 'max_age_of_public_key', 2 * 24 * 3600),
    InvAge = application:get_env(bitmessage, 'max_age_of_inventory', 2 * 24 * 3600),
    {MSec, Sec, _} = now(),
    Time = trunc(MSec * 1.0e6 + Sec),
    PubOld = Time - PubKeyAge,
    Old = Time - InvAge,
    error_logger:info_msg("Creating big inv: ~p~n", [Old]),
    case bm_db:select(inventory, [
                {#inventory{stream=Stream, hash='$1', time='$2', type = <<"pubkey">>, _='_'}, [{'>', '$2', PubOld}], ['$1']},
                {#inventory{stream=Stream, hash='$1', time = '$2', type='$3', _='_'}, [{'>', '$2', Old}, {'/=', '$3', <<"pubkey">>}], ['$1']}
                ], 5000) of
        '$end_of_table' ->
            empty;
        {Hashes, Cont} ->
            Payload = bm_types:encode_list(Hashes, fun(O) -> <<O/bytes>> end),
            {ok, create_message(<<"inv">>, Payload), Cont}
    end.

create_addrs_for_stream(Stream) ->
    NodeAge = application:get_env(bitmessage, 'max_age_of_node', 2 * 24 * 3600),
    {MSec, Sec, _} = now(),
    Time = trunc(MSec * 1.0e6 + Sec),
    Old = Time - NodeAge,
    case bm_db:select(addr, [
                {#network_address{stream=Stream, time='$2', ip='$3', port='$4'}, [{'>', '$2', Old}], ['$_']},
                {#network_address{stream=Stream * 2, time='$2', ip='$3', port='$4'}, [{'>', '$2', Old}], ['$_']},
                {#network_address{stream=Stream * 2 + 1, time='$2', ip='$3', port='$4'}, [{'>', '$2', Old}], ['$_']}
                ], 1000) of
        '$end_of_table' ->
            empty;
        {Hashes, Cont} ->
            Payload = bm_types:encode_list(Hashes, fun bm_types:encode_network/1),
            {ok, create_message(<<"addr">>, Payload), Cont};
        R ->
            error_logger:info_msg("Geting addrs for stream: ~p~n", [R])
    end.

create_pubkey(#privkey{hash=Hash, psk=PSK, public=Pub, address=Addr}) ->
    Time = bm_types:timestamp() + crypto:rand_uniform(-300, 300),
    #address{stream=Stream, version=AVer} = bm_auth:decode_address(Addr),
    Payload = <<Time:64/big-integer,
                AVer,
                Stream,
                1:32/big-integer,
                Pub:128/bytes,
                (bm_types:encode_varint(320)):2/bytes,
                (bm_types:encode_varint(14000))/bytes>>,
    Sig = crypto:sign(ecdsa, sha512, Payload, [PSK, secp256k1]),
    NPayload = <<Payload/bytes, (bm_types:encode_varint(size(Sig)))/bytes, Sig/bytes>>,
    POW = bm_pow:make_pow(NPayload),
    PPayload = <<POW/bytes, NPayload/bytes>>,
    <<Hash:32/bytes, _/bytes>> = crypto:hash(sha512, PPayload),
    bm_db:insert(inventory, #inventory{hash=Hash,
                                       payload = PPayload,
                                       type = <<"pubkey">>,
                                       time=Time,
                                       stream=Stream}),
    create_inv([ Hash ]).
                                       
create_getpubkey(#address{ripe=RIPE, version=Version, stream=Stream}) ->
    UPayload = <<(bm_types:timestamp() + crypto:rand_uniform(-300, 300)):64/big-integer,
                 (bm_types:encode_varint(Version))/bytes,
                 (bm_types:encode_varint(Stream))/bytes,
                 RIPE:20/bytes>>,
    POW = bm_pow:make_pow(UPayload),
    create_message(<<"getpubkey">>, <<POW:64/big-integer, UPayload/bytes>>).
