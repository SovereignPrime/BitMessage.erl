-module(bitmessage_auth).
-include_lib("eunit/include/eunit.hrl").
-compile([export_all]).

%addresstostream(<<"BM-",Address/binary>>) ->
%    DAddress = b58:decode(Address),
%    PDAddress = if length(DAddress) rem 2 /= 0 ->
%            "0" ++ DAddress;
%        true ->
%            DAddress
%    end,
%    double_sha(DAddress).

encode_address(Version, Stream, <<0, 0,  Ripe>>) when Version >=2, size(Ripe) == 20 ->
    encode_address(Version, Stream, Ripe);
encode_address(Version, Stream, <<0, Ripe>>) when Version >=2, size(Ripe) == 20 ->
    encode_address(Version, Stream, Ripe);
encode_address(Version, Stream, Ripe) when Version >=2, size(Ripe) == 20 ->
    Data = <<(encode_varint(Version))/bitstring, (encode_varint(Stream))/bitstring, Ripe/bitstring>>,
    Check = dual_sha(Data),
    OData = crypto:bytes_to_integer(<<Data/bitstring, Check:32/bitstring>>),
    <<"BM-", (list_to_binary(base58:encode(OData)))/bytes>>;
encode_address(_, _, _) ->
    <<"">>.

dual_sha(Data) ->
    crypto:hash(sha512, crypto:hash(sha512, Data)).
binary_to_hexstring(Data) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Data]).

encode_varint(Num) when Num < 16#fd ->
    <<Num:8>>;
encode_varint(Num) when Num =< 16#ffff ->
    <<16#fd,Num:16>>;
encode_varint(Num) when Num =< 16#ffffffff ->
    <<16#fe,Num:32>>;
encode_varint(Num) ->
    <<16#ff,Num:64>>.

%% Test cases

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

encode_address_test_() ->
    [
        ?_assert(encode_address(2, 1, <<"12345678901234567890">>) == <<"BM-4ZVsZN4foCh82rehBbDkHvRWdtEJyvNMBce">>),
        ?_assert(encode_address(2, 1, <<"01234567890123456789">>) == <<"BM-4ZVnFV7q49aFtUBMSXun2bgGxMhLYHEAHaC">>),
        ?_assert(encode_address(2, 1, <<"00123456789123456789">>) == <<"BM-4ZVnEHN7dWddScFKn5URYhC5i4Bh3PjVxDG">>)

        ].

