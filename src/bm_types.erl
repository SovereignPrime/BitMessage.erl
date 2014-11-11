-module(bm_types).
-compile([export_all]).
-include("../include/bm.hrl").


-export_type([
              timestamp/0
             ]).
%% Unix Timestamp type
-type timestamp() :: integer().

%%%
%% Integer packing and unpacking to VariantInt
%%%

-spec encode_varint(integer()) -> binary().
encode_varint(Num) when Num < 16#fd ->
    <<Num:8>>;
encode_varint(Num) when Num =< 16#ffff ->
    <<16#fd,Num:16>>;
encode_varint(Num) when Num =< 16#ffffffff ->
    <<16#fe,Num:32>>;
encode_varint(Num) ->
    <<16#ff,Num:64>>.

-spec decode_varint(<<_:8, _:_*1>>) -> {non_neg_integer(), binary()}.
decode_varint(<<Len:8/big-integer, Rest/bits>>) when Len <16#fd ->
    {Len, Rest};
decode_varint(<<16#fd, Num:16/big-integer, Rest/bits>>) ->
    {Num, Rest};
decode_varint(<<16#fe, Num:32/big-integer, Rest/bits>>) ->
    {Num, Rest};
decode_varint(<<16#ff, Num:64/big-integer, Rest/bits>>) ->
    {Num, Rest}.

%%%
%% String packing and unpacking to VariantStr
%%%

-spec encode_varstr(string()) -> binary().
encode_varstr(Str) ->
    Len = length(Str),
    <<(encode_varint(Len))/bytes, (list_to_binary(Str))/bytes>>.

-spec decode_varstr(binary()) -> {string(), binary()}.
decode_varstr(VStr) ->
    {Len, S} = decode_varint(VStr),
    <<Str:Len/bytes, Rest/bytes>> = S,
    {binary_to_list(Str), Rest}.

-spec decode_varbin(binary()) -> {binary(), binary()}.
decode_varbin(VStr) ->
    {Len, S} = decode_varint(VStr),
    <<Str:Len/bytes, Rest/bytes>> = S,
    {Str, Rest}.

%%%
%% List of any packing and unpacking to VariantIntList
%%%

-spec encode_list(list(TList), fun((TList) -> binary())) -> binary().
encode_list(Lst, Fun) ->
    Len = length(Lst),
    BLst = << <<(Fun(I))/bytes>> || I <- Lst>>,
    <<(encode_varint(Len))/bytes, BLst/bytes>>.

-spec decode_list(binary(), fun((TList) -> binary())) -> {list(TList), binary()}.
decode_list(VLst, Fun) ->
    {Len, S} = decode_varint(VLst),
    decode_list(S, Len, [], Fun).

-spec decode_list(binary(), non_neg_integer(), list(), fun((TList) -> binary())) -> {list(TList), binary()}.
decode_list(B, 0, A, _Fun) ->
    {A, B};
decode_list(B, C, A, Fun) ->
    {I, R} = Fun(B),
     decode_list(R, C - 1, A ++ [I], Fun).

%%%
%% Network address packing and unpacking to NetworkAddressStruct
%%%

-spec encode_network(#network_address{}) -> binary().
encode_network(#network_address{time=Time,
                                stream=Stream,
                                ip={Ip1,Ip2,Ip3,Ip4},
                                services=1,
                                port=Port}) ->
    <<Time:64/big-integer,
      Stream:32/big-integer,
      1:64/big-integer,
      0:10/unit:8-integer,
      255,
      255,
      Ip1, Ip2, Ip3, Ip4,
      Port:16/big-integer>>.

-spec decode_network(binary()) -> {#network_address{}, binary()}.
decode_network(<<Time:64/big-integer,
                 Stream:32/big-integer,
                 1:64/big-integer,
                 0:10/unit:8-integer,
                 255,255,
                 Ip1, Ip2, Ip3, Ip4, % Ip address octets
                 Port:16/big-integer,
                 R/bytes>>) ->
    {#network_address{time=Time,
                      stream=Stream,
                      ip={Ip1,Ip2,Ip3,Ip4},
                      port=Port,
                      services=1},
     R}.

%%%
%% Helpers
%%%

-spec integer_to_bytes(integer()) -> binary().
integer_to_bytes(0) ->
    <<>>;
integer_to_bytes(Num) ->
    <<(integer_to_bytes(Num div 256))/bits, (Num rem 256)/big-integer>>.

-spec binary_to_hexstring(binary()) -> string().
binary_to_hexstring(Data) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Data]).

-spec timestamp() -> integer().
timestamp() ->
    {MSec, Sec, _} = now(),
    trunc(MSec * 1.0e6 + Sec).

-spec pow(integer(), integer()) -> integer().
pow(_, 0) ->
    1;
pow(Num, Pow) when Pow >= 0 ->
    Num * pow(Num, Pow - 1).

