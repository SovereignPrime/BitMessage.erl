-module(bm_auth).
-include_lib("eunit/include/eunit.hrl").
-compile([export_all]).
-include("../include/bm.hrl").


-define(P, bm_types:pow(2,256)-bm_types:pow(2,32)-bm_types:pow(2,9)-bm_types:pow(2,8)-bm_types:pow(2,7)-bm_types:pow(2,6)-bm_types:pow(2,4)-1).
%%%
%% Address encoding and decoding routines
%%%

%% @doc Encode address from structure
%%
-spec encode_address(#address{}) -> binary().
encode_address(#address{version=Version, stream=Stream, ripe = Ripe}) ->
    Data = <<(bm_types:encode_varint(Version))/bitstring, (bm_types:encode_varint(Stream))/bitstring, Ripe/bitstring>>,
    Check = dual_sha(Data),
    OData = crypto:bytes_to_integer(<<Data/bitstring, Check:32/bitstring>>),
    <<"BM-", (list_to_binary(base58:encode(OData)))/bytes>>.

%% @doc Encode address from separate fields
%%
-spec encode_address(Version, Stream, Ripe) -> binary() when 
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
-spec decode_address(binary() | string()) -> #address{}.
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
-spec generate_ripe(iolist() | binary()) -> binary().
generate_ripe(Str) ->
    crypto:hash(ripemd160, crypto:hash(sha512, Str)).

%% @doc TODO: Generates PubKey from Private
%%
-spec pubkey(integer() | binary()) -> point(integer()). % ???
pubkey(PrKey) when is_binary(PrKey) ->
    pubkey(crypto:bytes_to_integer(PrKey));
pubkey(PrKey) when is_integer(PrKey) ->
    G = {55066263022277343669578718895168534326250603453777594175500187360389116729240,
         32670510020758816978083085130507043184471273380659243275938904335757337482424},
    point_mult(G, PrKey).


%%%
%% Helper routines
%%%

%% @doc Double sha512 hashing
%%
-spec dual_sha(iodata()) -> binary().
dual_sha(Data) ->
    crypto:hash(sha512, crypto:hash(sha512, Data)).

%%%
%% Private functions
%%%
-type point(Num) :: {Num, Num}.

%% @private
%% @doc Point add
%%
-spec point_add(point(integer()), point(integer())) -> point(integer()).
point_add({Px, Py}, {Qx, Qy}) ->
    Lambda = (Qy -Py) div (Qx -Px),
    X = bm_types:pow(Lambda, 2) -Px -Qx,
    Y = Lambda * (Px - X) - Py,
    {X, Y}. 

%% @private
%% @doc Point double
%%
-spec point_double(point(integer())) -> point(integer()).
point_double({Px, Py}) ->
    Lambda = 3 * bm_types:pow(Px, 2) div (2 * Py),
    X = bm_types:pow(Lambda, 2) - 2 * Px,
    Y = Lambda * (Px -X) - Py,
    {X, Y}.

%% @private
%% @doc Point multiply
%%
-spec point_mult(point(integer()), integer()) -> point(integer()).
point_mult(_, 0) -> 0;
point_mult(P, 1) -> P;
point_mult(P, N) when N rem 2 == 1 ->
    point_add(P, point_mult(P, N - 1));
point_mult(P, N) ->
    point_mult(point_double(P), N div 2).
