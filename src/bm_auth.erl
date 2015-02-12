-module(bm_auth).
-include_lib("eunit/include/eunit.hrl").
-compile([export_all]).
-include("../include/bm.hrl").


-define(P, bm_types:pow(2,256)-bm_types:pow(2,32)-bm_types:pow(2,9)-bm_types:pow(2,8)-bm_types:pow(2,7)-bm_types:pow(2,6)-bm_types:pow(2,4)-1).
%%%
%% @doc Mercle tree root calculation
%%%
-spec mercle_root([iodata()]) -> binary().  % {{{2
mercle_root(Chunks) ->
    Hashes = lists:map(fun dual_sha/1, Chunks),
    mercle_root(Hashes, []).

-spec mercle_root([binary()], [binary()]) -> binary().  % {{{2
mercle_root([H], []) ->
    H;
mercle_root([H1, H2], []) ->
    dual_sha(<<H1/bytes, H2/bytes>>);
mercle_root([], Acc) ->
    mercle_root(lists:reverse(Acc), []);
mercle_root([H], Acc) ->
    mercle_root([], [dual_sha(<<H/bytes, H/bytes>>) | Acc]);
mercle_root([H1, H2 | Hashes], Acc) ->
    mercle_root(Hashes, [dual_sha(<<H1/bytes, H2/bytes>>) | Acc]).
    

%%%
%% Address encoding and decoding routines
%%%

%% @doc Encode address from structure
%%
-spec encode_address(#address{}) -> binary().  % {{{2
encode_address(#address{version=Version, stream=Stream, ripe = Ripe}) ->
    Data = <<(bm_types:encode_varint(Version))/bitstring,
             (bm_types:encode_varint(Stream))/bitstring,
             Ripe/bitstring>>,
    Check = dual_sha(Data),
    OData = crypto:bytes_to_integer(<<Data/bitstring,
                                      Check:32/bitstring>>),
    <<"BM-", (list_to_binary(base58:encode(OData)))/bytes>>.

%% @doc Encode address from separate fields
%%
-spec encode_address(Version, Stream, Ripe) -> binary() when  % {{{2
      Version :: integer(),
      Stream :: integer(),
      Ripe :: binary().
encode_address(Version, Stream, <<0, 0,  Ripe/bits>>) when Version >=2, size(Ripe) == 18 ->
    encode_address(#address{version=Version, stream=Stream, ripe = Ripe});
encode_address(Version, Stream, <<0, Ripe/bits>>) when Version >=2, size(Ripe) == 19 ->
    encode_address(#address{version=Version, stream=Stream, ripe = Ripe});
encode_address(Version, Stream, Ripe) when Version >=2, size(Ripe) == 20 ->
    encode_address(#address{version=Version, stream=Stream, ripe = Ripe});
encode_address(_, _, _) ->
    <<"">>.

%% @doc Decodes address structure from address
%%
-spec decode_address(binary() | string()) -> #address{}. % {{{2
decode_address(Data) when is_list(Data) ->
    decode_address(list_to_binary(Data));
decode_address(<<"BM-",Data/bytes>>) ->
    DData = bm_types:integer_to_bytes(base58:decode(binary_to_list(Data))),
    IData = binary:part(DData, 0, byte_size(DData) - 4),
    Check = binary:part(DData, byte_size(DData), -4 ),
    %io:format("~p~n~p~n", [IData, Check]),
    Check = <<(dual_sha(IData)):32/bits>>,
    {Version, R} = bm_types:decode_varint(IData),
    {Stream, Ripe} = bm_types:decode_varint(R),
    case size(Ripe) of
        20 ->
            #address{version=Version, stream=Stream, ripe=Ripe};
        19 ->
            #address{version=Version, stream=Stream, ripe= <<0, Ripe/bits>>};
        18 ->
            #address{version=Version, stream=Stream, ripe= <<0, 0, Ripe/bits>>}
      end.

%% @doc Generates ripe from data
%%
-spec generate_ripe(iolist() | binary()) -> binary(). % {{{2
generate_ripe(Str) ->
    crypto:hash(ripemd160, crypto:hash(sha512, Str)).

%% @doc TODO: Generates PrivKey for Broadcast
%%
-spec broadcast_key(binary()) -> {binary(), binary()}. % ??? % {{{2
broadcast_key(Address) ->
    #address{version=V,
             stream=S,
             ripe=R} = bm_auth:decode_address(Address),

    <<PrivKey:32/bytes,
      Tag/bytes>> = bm_auth:dual_sha(<<(bm_types:encode_varint(V))/bytes,
                                     (bm_types:encode_varint(S))/bytes,
                                     R/bytes>>),
    {PrivKey, Tag}.

%% @doc TODO: Generates PubKey from Private
%%
-spec pubkey(integer() | binary()) -> binary(). % ??? % {{{2
pubkey(PrKey) when is_binary(PrKey) ->
    pubkey(crypto:bytes_to_integer(PrKey));
pubkey(PrKey) when is_integer(PrKey) ->
    {{prime_field,
      <<Prime:256/integer>>},
     _PP,
     <<4, GX:256, GY:256>>,
     _Order,
     _CoFactor} = crypto:ec_curve(secp256k1),
    G = {GX, GY},
    {X, Y} = point_mult(G, PrKey, Prime, G),
    io:format("X: ~p Y: ~p~n", [X, Y]),
    <<X:256/integer, Y:256/integer>>.


%%%
%% Helper routines
%%%

%% @doc Double sha512 hashing
%%
-spec dual_sha(iodata()) -> binary().  % {{{2
dual_sha(Data) ->
    crypto:hash(sha512, crypto:hash(sha512, Data)).

%%%
%% Private functions {{{1
%%%
-type point(Num) :: {Num, Num}.

%% @private
%% @doc Point add {{{1
%%
-spec point_add(point(integer()), point(integer()), integer()) -> point(integer()).
point_add(A, A, Prime) ->
    point_double(A, Prime);
point_add({Px, Py}, {Qx, Qy}, Prime) ->
    Lambda = mod((Qy - Py) * inv(Qx - Px, Prime), Prime),
    X = mod((bm_types:pow(Lambda, 2) - Px - Qx), Prime),
    Y = mod((Lambda * (Px - X) - Py), Prime),
    {X, Y}. 

%% @private
%% @doc Point double {{{1
%%
-spec point_double(point(integer()), integer()) -> point(integer()).
point_double({Px, Py}, Prime) ->
    Lambda = mod(3 * bm_types:pow(Px, 2) * inv(2 * Py, Prime), Prime),
    X = mod(bm_types:pow(Lambda, 2) - 2 * Px, Prime),
    Y = mod(Lambda * (Px -X) - Py, Prime),
    {X, Y}.

%% @private
%% @doc Point multiply {{{1
%%
-spec point_mult(point(integer()), integer(), integer(), point(integer())) -> point(integer()).
point_mult(_, 0, _, G) -> G; % 0 in WiKi ???
point_mult(P, 1, _, _) -> P;
point_mult(P, N, Prime, G) when N rem 2 == 1 ->
    point_add(P, point_double(point_mult(P, N div 2, Prime, G), Prime), Prime);
point_mult(P, N, Prime, G) ->
    point_double(point_mult(P, N div 2, Prime, G), Prime).

-spec inv(integer(), integer()) -> integer().
inv(N, Prime) ->
    mod(inv(mod(N, Prime), Prime, 1, 0), Prime).

-spec inv(integer(), integer(), integer(), integer()) -> integer().
inv(Low, Hight, L, H) when Low > 1 ->
    R = Hight div Low,
    NM = H - L * R,
    New = Hight - Low * R,
    inv(New, Low, NM, L);
inv(_Low, _Hight, L, _H) ->
    L.

-spec mod(integer(), integer()) -> non_neg_integer().
mod(0, _B) ->
    0;
mod(A, B) when A > 0 ->
    A rem B;
mod(A, B) when A < 0 ->
    B + (A rem B).
