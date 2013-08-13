-module(bm_auth).
-include_lib("eunit/include/eunit.hrl").
-compile([export_all]).
-record(address, {version, stream, ripe}).

%%%
%% Address encoding and decoding routines
%%%

encode_address(#address{version=Version, stream=Stream, ripe = Ripe}) ->
    Data = <<(encode_varint(Version))/bitstring, (encode_varint(Stream))/bitstring, Ripe/bitstring>>,
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

decode_address(<<"BM-",Data/bytes>>) ->
    DData = integer_to_bytes(base58:decode(binary_to_list(Data))),
    IData = binary:part(DData, 0, byte_size(DData) - 4),
    Check = binary:part(DData, byte_size(DData), -4 ),
    io:format("~p~n~p~n", [IData, Check]),
    Check = <<(dual_sha(IData)):32/bits>>,
    {Version, R} = decode_varint(IData),
    {Stream, Ripe} = decode_varint(R),
    case size(Ripe) of
        20 ->
            #address{version=Version, stream=Stream, ripe=Ripe};
        19 ->
            #address{version=Version, stream=Stream, ripe= <<0, Ripe/bits>>};
        18 ->
            #address{version=Version, stream=Stream, ripe= <<0, 0, Ripe/bits>>}
      end.



%%%
%% Integer packing and unpacking to VariantInt
%%%

encode_varint(Num) when Num < 16#fd ->
    <<Num:8>>;
encode_varint(Num) when Num =< 16#ffff ->
    <<16#fd,Num:16>>;
encode_varint(Num) when Num =< 16#ffffffff ->
    <<16#fe,Num:32>>;
encode_varint(Num) ->
    <<16#ff,Num:64>>.

decode_varint(<<Len:8/integer, Rest/bits>>) when Len <16#fd ->
    {Len, Rest};
decode_varint(<<16#fd, Num:16/integer, Rest/bits>>) ->
    {Num, Rest};
decode_varint(<<16#fe, Num:32/integer, Rest/bits>>) ->
    {Num, Rest};
decode_varint(<<16#ff, Num:64/integer, Rest/bits>>) ->
    {Num, Rest}.

%%%
%% Helper routines
%%%

dual_sha(Data) ->
    crypto:hash(sha512, crypto:hash(sha512, Data)).

binary_to_hexstring(Data) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Data]).

integer_to_bytes(0) ->
    <<>>;
integer_to_bytes(Num) ->
    <<(integer_to_bytes(Num div 256))/bits, (Num rem 256)/integer>>.

%% Test cases

integer_to_bytes_test_() ->
    [
        ?_assert(integer_to_bytes(crypto:bytes_to_integer(<<"TEST">>)) == <<"TEST">>)
        ].

dual_sha_test_() ->
    [
        ?_assert("0592a10584ffabf96539f3d780d776828c67da1ab5b169e9e8aed838aaecc9ed36d49ff1423c55f019e050c66c6324f53588be88894fef4dcffdb74b98e2b200" == binary_to_hexstring(dual_sha("hello")))
        ].
encode_varint_test_() ->
    [
        ?_assert(encode_varint(10) == <<10>>),
        ?_assert(encode_varint(253) == <<16#fd, 00, 253>>),
        ?_assert(encode_varint(252) == <<252>>),
        ?_assert(encode_varint(65535) == <<16#fd,16#ff, 16#ff>>),
        ?_assert(encode_varint(65536) == <<16#fe, 00, 01, 00, 00>>),
        ?_assert(encode_varint(4294967295) == <<16#fe, 16#ff, 16#ff, 16#ff, 16#ff>>),
        ?_assert(encode_varint(4294967296) == <<16#ff, 00, 00, 00, 01, 00, 00, 00, 00>>)
        ].
decode_encode_varint_test_() ->
    [
        ?_assert(decode_varint(encode_varint(10))== {10, <<>>}),
        ?_assert(decode_varint(encode_varint(253))== {253, <<>>}),
        ?_assert(decode_varint(encode_varint(252))== {252, <<>>}),
        ?_assert(decode_varint(encode_varint(65535))== {65535, <<>>}),
        ?_assert(decode_varint(encode_varint(65536))== {65536, <<>>}),
        ?_assert(decode_varint(encode_varint(4294967295))== {4294967295, <<>>}),
        ?_assert(decode_varint(encode_varint(4294967296))== {4294967296, <<>>}),
        ?_assert(decode_varint(<<(encode_varint(4294967296))/bits, <<"test">>/bits>>)== {4294967296, <<"test">>})
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
