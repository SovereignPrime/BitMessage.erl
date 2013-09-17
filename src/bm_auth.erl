-module(bm_auth).
-include_lib("eunit/include/eunit.hrl").
-compile([export_all]).
-include("../include/bm.hrl").

%%%
%% Address encoding and decoding routines
%%%

encode_address(#address{version=Version, stream=Stream, ripe = Ripe}) ->
    Data = <<(bm_types:encode_varint(Version))/bitstring, (bm_types:encode_varint(Stream))/bitstring, Ripe/bitstring>>,
    Check = dual_sha(Data),
    OData = crypto:bytes_to_integer(<<Data/bitstring, Check:32/bitstring>>),
    <<"BM-", (list_to_binary(base58:encode(OData)))/bytes>>.

encode_address(Version, Stream, <<0, 0,  Ripe/bits>>) when Version >=2, size(Ripe) == 18 ->
    encode_address(#address{version=Version, stream=Stream, ripe = Ripe});
encode_address(Version, Stream, <<0, Ripe/bits>>) when Version >=2, size(Ripe) == 19 ->
    encode_address(#address{version=Version, stream=Stream, ripe = Ripe});
encode_address(Version, Stream, Ripe) when Version >=2, size(Ripe) == 20 ->
    encode_address(#address{version=Version, stream=Stream, ripe = Ripe});
encode_address(_, _, _) ->
    <<"">>.

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

generate_ripe(Str) ->
    crypto:hash(ripemd160, crypto:hash(sha512, Str)).



%%%
%% Helper routines
%%%

dual_sha(Data) ->
    crypto:hash(sha512, crypto:hash(sha512, Data)).

%% Test cases


dual_sha_test_() ->
    [
        ?_assert("0592a10584ffabf96539f3d780d776828c67da1ab5b169e9e8aed838aaecc9ed36d49ff1423c55f019e050c66c6324f53588be88894fef4dcffdb74b98e2b200" == bm_types:binary_to_hexstring(dual_sha("hello")))
        ].

generate_ripe_test_() ->
    [
        ?_assert("79a324faeebcbf9849f310545ed531556882487e" == bm_types:binary_to_hexstring(generate_ripe("hello")))
        ].

encode_address_test_() ->
    [
        ?_assert(encode_address(#address{version=2, stream=1, ripe = <<"12345678901234567890">>}) == <<"BM-4ZVsZN4foCh82rehBbDkHvRWdtEJyvNMBce">>),
        ?_assert(encode_address(2, 1, <<"12345678901234567890">>) == <<"BM-4ZVsZN4foCh82rehBbDkHvRWdtEJyvNMBce">>),
        ?_assert(encode_address(2, 1, <<0, "1234567890123456789">>) == <<"BM-onWacauk6NKp6MmuF6cBdaCFFKsozCr5v">>),
        ?_assert(encode_address(2, 1, <<0, 0, "123456789123456789">>) == <<"BM-BbnDboCVo5NwApkngoNwb2JZA1wSevkg">>)

        ].

decode_encode_address_test_() ->
    [
        ?_assert(decode_address(encode_address(#address{version=2, stream=1, ripe = <<"12345678901234567890">>})) == #address{version=2, stream=1, ripe = <<"12345678901234567890">>}),
        ?_assert(decode_address(encode_address(2, 1, <<"12345678901234567890">>)) == #address{version=2, stream=1, ripe= <<"12345678901234567890">>}),
        ?_assert(decode_address(encode_address(2, 1, <<0, "1234567890123456789">>)) == #address{version=2, stream=1, ripe= <<0, "1234567890123456789">>}),
        ?_assert(decode_address(encode_address(2, 1, <<0, 0, "123456789123456789">>)) == #address{version=2, stream=1, ripe= <<0, 0, "123456789123456789">>})

        ].
