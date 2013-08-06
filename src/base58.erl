-module(base58).
-include_lib("eunit/include/eunit.hrl").
-export([
        encode/2,
        encode/1,
        decode/2,
        decode/1
                ]).

encode(0, Alpa) ->
    [lists:nth(1, Alpa)];
encode(Num, Alpha) ->
    enc(Num, Alpha).
enc(0, _Alpha) ->
    [];
enc(Num, Alpha) ->
    Base = length(Alpha),
    C = Num rem Base,
    enc(Num div Base, Alpha) ++ [lists:nth(C + 1, Alpha)].


encode(Num) ->
    encode(Num, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz").

decode(Num) ->
    decode(Num, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz").

decode([C | Rest] = String, Alpha) ->
    Base = length(Alpha),
    Power = length(String) - 1,
    trunc((string:str(Alpha, [C]) - 1) * math:pow(Base, Power) + decode(Rest, Alpha));
decode([], _) ->
    0.

%% Test cases for eunit
encode_decode_test_() ->
    [?_assert(1234567890 =:= decode(encode(1234567890))),
     ?_assert(1 =:= decode(encode(1))),
     ?_assert("1" =:= encode(0)),
     ?_assert(254 =:= decode("5P")),
     ?_assert("5P" =:= encode(254))
    ].
