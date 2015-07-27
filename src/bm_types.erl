-module(bm_types).
-compile([export_all]).
-include("../include/bm.hrl").


-export_type([
              timestamp/0
             ]).
%% Unix Timestamp type  % {{{1
-type timestamp() :: integer().

%%%
%% Integer packing and unpacking to VariantInt  % {{{1
%%%

-spec encode_varint(integer()) -> binary().  % {{{2
encode_varint(Num) when Num < 16#fd ->
    <<Num:8>>;
encode_varint(Num) when Num =< 16#ffff ->
    <<16#fd,Num:16>>;
encode_varint(Num) when Num =< 16#ffffffff ->
    <<16#fe,Num:32>>;
encode_varint(Num) ->
    <<16#ff,Num:64>>.

-spec decode_varint(<<_:8, _:_*1>>) -> {non_neg_integer(), binary()}.  % {{{2
decode_varint(<<Len:8/big-integer, Rest/bits>>) when Len <16#fd ->
    {Len, Rest};
decode_varint(<<16#fd, Num:16/big-integer, Rest/bits>>) ->
    {Num, Rest};
decode_varint(<<16#fe, Num:32/big-integer, Rest/bits>>) ->
    {Num, Rest};
decode_varint(<<16#ff, Num:64/big-integer, Rest/bits>>) ->
    {Num, Rest}.

%%%
%% String packing and unpacking to VariantStr  % {{{1
%%%

-spec encode_varstr(iodata()) -> binary().  % {{{2
encode_varstr(Str) when is_binary(Str) ->
    binary_to_list(Str);
encode_varstr(Str) ->
    Len = length(Str),
    <<(encode_varint(Len))/bytes, (list_to_binary(Str))/bytes>>.

-spec decode_varstr(binary()) -> {string(), binary()}.  % {{{2
decode_varstr(VStr) ->
    {Len, S} = decode_varint(VStr),
    <<Str:Len/bytes, Rest/bytes>> = S,
    {binary_to_list(Str), Rest}.

-spec decode_varbin(binary()) -> {binary(), binary()}.  % {{{2
decode_varbin(VStr) ->
    {Len, S} = decode_varint(VStr),
    <<Str:Len/bytes, Rest/bytes>> = S,
    {Str, Rest}.

%%%
%% List of any packing and unpacking to VariantIntList  % {{{1
%%%

-spec encode_list(list(TList), fun((TList) -> binary())) -> binary().  % {{{2
encode_list(Lst, Fun) ->
    Len = length(Lst),
    BLst = << <<(Fun(I))/bytes>> || I <- Lst>>,
   <<(encode_varint(Len))/bytes, BLst/bytes>>.

-spec decode_list(binary(), fun((TList) -> binary())) -> {list(TList), binary()}.  % {{{2
decode_list(VLst, Fun) ->
    {Len, S} = decode_varint(VLst),
    decode_list(S, Len, [], Fun).

-spec decode_list(binary(),  % {{{2
                  non_neg_integer(),
                  list(),
                  fun((TList) -> binary())) -> {list(TList),
                                                binary()}.
decode_list(B, 0, A, _Fun) ->
    {A, B};
decode_list(B, C, A, Fun) ->
    {I, R} = Fun(B),
     decode_list(R, C - 1, A ++ [I], Fun).

%%%
%% Network address packing and unpacking to NetworkAddressStruct  % {{{1
%%%

-spec encode_network(#network_address{}) -> binary().  % {{{2
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

-spec decode_network(binary()) -> {#network_address{} | [], binary()}.  % {{{2
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
     R};
% Skip IP6 at the moment
decode_network(<<Time:64/big-integer,
                 Stream:32/big-integer,
                 _:64/big-integer,
                 _:10/unit:8-integer,
                 _,_,
                 _Ip1, _Ip2, _Ip3, _Ip4, % Ip address octets
                 _Port:16/big-integer,
                 R/bytes>>) ->
    {[],
     R}.

%%%
%% Helpers  % {{{1
%%%

-spec shuffle([Type]) -> [Type].
shuffle(List) ->
    <<A:32, B:32, C:32>> = crypto:rand_bytes(12),
    random:seed({A, B, C}),
    [X || {_,X} <- lists:sort([ {random:uniform(), N} || N <- List])].

-spec integer_to_bytes(integer()) -> binary().  % {{{2
integer_to_bytes(0) ->
    <<>>;
integer_to_bytes(Num) ->
    <<(integer_to_bytes(Num div 256))/bits, (Num rem 256)/big-integer>>.

-spec binary_to_hexstring(binary()) -> string().  % {{{2
binary_to_hexstring(Data) ->
    lists:flatten([io_lib:format("~2.16.0b", [B]) || <<B>> <= Data]).

-spec timestamp() -> integer().  % {{{2
timestamp() ->
    {MSec, Sec, _} = now(),
    trunc(MSec * 1.0e6 + Sec).

%%%
%% Long Integer Math  % {{{1
%%%
-spec pow(integer(), integer()) -> integer().  % {{{2
pow(_, 0) ->
    1;
pow(Num, Pow) when Pow >= 0 ->
    Num * pow(Num, Pow - 1).

-spec sqrt(integer()) -> integer().  % {{{2
sqrt(Num) ->
    sqrti(Num, 1).

-spec sqrti(integer(), integer()) -> integer().  % {{{2
sqrti(0, C) ->
    (C - 1) div 2;
sqrti(Num, C) when C > 0 ->
    sqrti(Num - C, C + 2).
    
    

