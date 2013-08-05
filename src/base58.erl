-module(base58).
-export([
        encode/2,
        encode/1,
        decode/2,
        decode/1
                ]).

encode(0, Alpa) ->
    lists:nth(0, Alpa);
encode(Num, Alpha) ->
    Base = length(Alpha),
    C = Num rem Base,
    encode(Num div Base, Alpha) ++ [lists:nth(C, Alpha)].

encode(Num) ->
    encode(Num, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz").

decode(Num) ->
    decode(Num, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz").

decode([C | Rest] = String, Alpha) ->
    Base = length(Alpha),
    Power = length(String) - 1,
    string:str(Alpha, C) * math:pow(Base, Power) + decode(Rest, Alpha);
decode([], _) ->
    0.
