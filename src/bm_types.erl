-module(bm_types).
-compile([export_all]).

-include_lib("eunit/include/eunit.hrl").

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

decode_varint(<<Len:8/big-integer, Rest/bits>>) when Len <16#fd ->
    {Len, Rest};
decode_varint(<<16#fd, Num:16/big-integer, Rest/bits>>) ->
    {Num, Rest};
decode_varint(<<16#fe, Num:32/big-integer, Rest/bits>>) ->
    {Num, Rest};
decode_varint(<<16#ff, Num:64/big-integer, Rest/bits>>) ->
    {Num, Rest}.

%%%
%% String packing and unpacking to VariantInt
%%%

encode_varstr(Str) ->
    Len = length(Str),
    <<(encode_varint(Len))/bytes, (list_to_binary(Str))/bytes>>.

decode_varstr(VStr) ->
    {Len, S} = decode_varint(VStr),
    <<Str:Len/bytes, Rest/bytes>> = S,
    {binary_to_list(Str), Rest}.

%%%
%% Helpers
%%%

integer_to_bytes(0) ->
    <<>>;
integer_to_bytes(Num) ->
    <<(integer_to_bytes(Num div 256))/bits, (Num rem 256)/big-integer>>.

binary_to_hexstring(Data) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Data]).

%%
%% Test cases
%%

integer_to_bytes_test_() ->
    [
        ?_assert(integer_to_bytes(crypto:bytes_to_integer(<<"TEST">>)) == <<"TEST">>)
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

encode_varstr_test_() ->
    [
        ?_assert(encode_varstr("1234567890") == <<10,"1234567890">>)
        ].
decode_encode_varstr_test_() ->
    [
        ?_assert(decode_varstr(encode_varstr("TEST")) == {"TEST", <<>>})
                ].
