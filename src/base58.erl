-module(base58).
-compile([export_all]).

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
