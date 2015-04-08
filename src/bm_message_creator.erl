-module(bm_message_creator).
-compile([export_all]).

-include("../include/bm.hrl").

%% @doc Creates message 
%%
%% Creates message from `Command` and `Payload`
-spec create_message(Command, Payload) -> message_bin() when  % {{{1
      Command :: binary(),
      Payload :: binary().
create_message(Command, Payload) ->
    Length = size(Payload),
    CL = byte_size(Command),
    C = <<Command/bytes, 0:(12 - CL)/unit:8>>,
    <<Check:4/bytes,
      _/bytes>> = crypto:hash(sha512, Payload),
    <<?MAGIC,
      C:12/bytes,
      Length:32/big-integer,
      Check:4/bytes,
      Payload/bytes>>.


%% @doc Creates object message
%%
%% Creates object message looking inventory for `Hash`
%% in database and creating `Message`
-spec create_obj(Type, Version, Stream, Payload) -> binary()    % {{{1 ???
                                                    | no_return() when
      Type :: object_type(),
      Version :: non_neg_integer(),
      Stream :: non_neg_integer(),
      Payload :: binary().
create_obj(Type, Version, Stream, Payload) ->
    Time = bm_types:timestamp() + 28 * 24 * 60 * 60,
    create_obj(Type, Version, Stream, Time, Payload).

-spec create_obj(Type, Version, Stream, Time, Payload) -> binary()    % {{{1 ???
                                                    | no_return() when
      Type :: object_type(),
      Version :: non_neg_integer(),
      Stream :: non_neg_integer(),
      Time :: non_neg_integer(),
      Payload :: binary().
create_obj(Type, Version, Stream, Time, Payload) ->
    VVersion = bm_types:encode_varint(Version),
    VStream = bm_types:encode_varint(Stream),
    NoPOW = <<Time:64/big-integer,
              Type:32/big-integer,
              VVersion/bytes,
              VStream/bytes,
              Payload/bytes>>,

    bm_pow:make_pow(NoPOW).


%% @doc Creates inv message from inventory hash list
%%
%% Creates inv message from hashlist `Hash`
-spec create_inv(Hashes) -> message_bin() when  % {{{1
      Hashes :: [Hash],
      Hash :: binary().
create_inv(Hashes) ->
    create_message(<<"inv">>, bm_types:encode_list(Hashes, fun(H) -> H end)).

%% @doc Creates inv message finding data in db
%%
%% Creates inv message finding data in db by `Stream` 
%% TODO: make `Excludes` work to exclude already known invs
%% Takes age parameters from config file
-spec create_big_inv(Stream, Exclude) -> [message_bin()] when  % {{{1
      Stream :: integer(),
      Exclude :: list().
create_big_inv(Stream, Exclude) ->
    Time = bm_types:timestamp(),
    InvList =  bm_db:select(inventory,
                            [
                             {#inventory{stream=Stream,
                                         hash='$1',
                                         time='$2',
                                         _='_'},
                              [{'>', '$2', Time}],
                              ['$1']}
                            ],
                            5000),
    lists:map(fun(Inv) ->
                      create_message(<<"inv">>,
                                     bm_types:encode_list(Inv,
                                                          fun(O) -> <<O/bytes>> end))
              end,
              InvList).

%% @doc Creates addr message
%%
%% Creates addr message for `Stream`
-spec create_addrs_for_stream(Stream) -> [message_bin()] when  % {{{1
      Stream :: integer().
create_addrs_for_stream(Stream) ->
    {ok, NodeAge} = application:get_env(bitmessage, 'max_age_of_node'),
    {MSec, Sec, _} = now(),
    Time = trunc(MSec * 1.0e6 + Sec),
    Old = Time - NodeAge,
    Hashes = bm_db:select(addr, [
                {#network_address{stream=Stream,
                                  time='$2',
                                  ip='$3',
                                  port='$4'},
                 [{'>',
                   '$2',
                   Old}],
                 ['$_']},

                {#network_address{stream=Stream * 2,
                                  time='$2',
                                  ip='$3',
                                  port='$4'},
                 [{'>',
                   '$2',
                   Old}],
                 ['$_']},

                {#network_address{stream=Stream * 2 + 1,
                                  time='$2',
                                  ip='$3',
                                  port='$4'},
                 [{'>',
                   '$2',
                   Old}],
                 ['$_']}
                ],
                          1000),
            lists:map(
              fun(Hash) ->  
                    create_message(
                      <<"addr">>,
                      bm_types:encode_list(
                        Hash,
                        fun bm_types:encode_network/1))
              end,
              Hashes).

%% @doc Creates pubkey inventory from privkey structure
%%
-spec create_pubkey(#privkey{}) -> message_bin().  % {{{1
create_pubkey(#privkey{hash=RIPE,
                       psk=PSK,
                       pek=PEK,
                       public=Pub,
                       address=Addr}) ->
    Time = bm_types:timestamp(),
    ETime = Time + 28 * 24 * 60 * 60,
    #address{stream=Stream, version=AVer} = bm_auth:decode_address(Addr),
    error_logger:info_msg("Creating PubKey"),
    Payload = <<ETime:64/big-integer,
                ?PUBKEY:32/big-integer,
                AVer,
                Stream,
                1:32/big-integer,
                Pub:128/bytes,
                (bm_types:encode_varint(?MIN_NTPB))/bytes,
                (bm_types:encode_varint(?MIN_PLEB))/bytes>>,
    error_logger:info_msg("Signing PubKey"),
    Sig = crypto:sign(ecdsa, sha, Payload, [PSK, secp256k1]),
    NPayload = <<Payload/bytes,
                 (bm_types:encode_varint(size(Sig)))/bytes,
                 Sig/bytes>>,
    error_logger:info_msg("Creating object for PubKey"),
    PPayload = bm_pow:make_pow(NPayload),
    error_logger:info_msg("Pow ready for PubKey"),
    <<Hash:32/bytes, _/bytes>> = bm_auth:dual_sha(PPayload),
    bm_db:insert(inventory, [#inventory{hash=Hash,
                                       payload = PPayload,
                                       type = 1,
                                       time=Time,
                                        stream=Stream}]),
    error_logger:info_msg("Advertising pubkey inv: ~p~n", [bm_types:binary_to_hexstring(Hash)]),
    create_inv([ Hash ]).
                                       
%% @doc Creates getpubkey object and inv message for it
%%
%% Creates getpubkey object and saves it to DB and 
%% returnd inv message
-spec create_getpubkey(#address{}) -> message_bin().  % {{{1
create_getpubkey(#address{ripe=RIPE,
                          version=Version,
                          stream=Stream}) ->
    <<_:64/bits,
      Time:64/big-integer,
      _/bytes>> = Payload = case Version of
                                3 ->
                                    create_obj(0, Version, Stream, RIPE);
                                4 ->
                                    <<_:32/bytes,
                                      TAG:32/bytes>> = 
                                        bm_auth:dual_sha(
                                          <<(bm_types:encode_varint(Version))/bytes,
                                            (bm_types:encode_varint(Stream))/bytes,
                                            RIPE/bytes>>),

                                    create_obj(0, Version, Stream, TAG)
                            end,
    <<Hash:32/bytes, _/bytes>> = crypto:hash(sha512, Payload),
    bm_db:insert(inventory, [#inventory{hash=Hash,
                                       payload = Payload,
                                       type = 0,
                                       time=Time,
                                       stream=Stream}]),
    error_logger:info_msg("Advertising GetPubkey inv: ~p~n", [bm_types:binary_to_hexstring(Hash)]),
    create_inv([ Hash ]).

%% @doc Creates ack message object and inv message for it
%%
%% Creates ack message object and saves it to DB and 
%% returnd inv message
-spec create_ack(#message{}) -> message_bin().  % {{{1
create_ack(#message{ackdata=Payload, from=Addr}) ->
    <<_:16/bytes, PLen:32/big-integer, _:4/bytes, PPayload/bytes>> = Payload,
    <<Hash:32/bytes, _/bytes>> = bm_auth:dual_sha(PPayload),
    error_logger:info_msg("Sending ack: ~p~n", [bm_types:binary_to_hexstring(Hash)]),
    <<_:8/bytes, Time:64/big-integer, Stream, _/bytes>> = PPayload,
    bm_db:insert(inventory, [#inventory{hash=Hash,
                                       payload = PPayload,
                                       type = 2,
                                       time=Time,
                                       stream=Stream}]),
    create_inv([ Hash ]).

-spec create_getchunk(FileHash, ChunkHash) -> message_bin() when % {{{1
      FileHash :: binary(),
      ChunkHash :: binary().
create_getchunk(FileHash, ChunkHash) ->
    Payload = <<FileHash:64/bytes, ChunkHash:64/bytes>>,
    Obj = create_obj(?GETFILECHUNK, 1, 1, Payload),
    save_obj(Obj).

-spec save_obj(binary()) -> message_bin().  % {{{1
save_obj(<<_:64/bits,
           Time:64/big-integer,
           Type:32/big-integer,
           _Version/integer,
           Stream/integer,
           _/bytes>> = Payload) ->
    <<Hash:32/bytes, _/bytes>> = crypto:hash(sha512, Payload),
    bm_db:insert(inventory, [#inventory{hash=Hash,
                                        payload = Payload,
                                        type = Type,
                                        time=Time,
                                        stream=Stream}]),
    %error_logger:info_msg("Advertising ~p inv: ~p~n", [Type, bm_types:binary_to_hexstring(Hash)]),
    create_inv([ Hash ]).

