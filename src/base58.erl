-module(base58).
-include_lib("eunit/include/eunit.hrl").
-export([
        encode/2,
        encode/1,
        decode/2,
        decode/1
                ]).

%% @doc Base58 encode with custom alphabet
%%
-spec encode(integer(), string()) -> string().
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


%% @doc Base58 encode w/standart alphabet
%%
-spec encode(integer()) -> string().
encode(Num) ->
    encode(Num, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz").

%% @doc Base58 encode w/standart alphabet
%%
-spec decode(string()) -> integer().
decode(Num) ->
    decode(Num, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz").

%% @doc Base58 encode w/custom alphabet
%%
-spec decode(string(), string()) -> integer().
decode([C | Rest] = String, Alpha) ->
    Base = length(Alpha),
    Power = length(String) - 1,
    (string:str(Alpha, [C]) - 1) * pow(Base, Power) + decode(Rest, Alpha);
decode([], _) ->
    0.

%%%
%% Helpers
%%%

-spec pow(integer(), integer()) -> integer().
pow(Num, 0) when Num >= 0 ->
    1;
pow(Num, Pow) when Num >= 0 ->
    Num * pow(Num, Pow - 1).

%%%
%% Test cases for eunit
%%%

encode_decode_test_() ->
    [?_assert(1234567890 =:= decode(encode(1234567890))),
     %?_assert("123456789" =:= encode(decode("123456789"))),
     ?_assert("a123456789" =:= encode(decode("a123456789"))),
     ?_assert(1 =:= decode(encode(1))),
     ?_assert(0 =:= decode(encode(0))),
     ?_assert("1" =:= encode(0)),
     ?_assert(0 =:= decode("1")),

     ?_assert(254 =:= decode("5P")),
     ?_assert("4ZVsZN4foCh82rehBbDkHvRWdtEJyvNMBce" =:= encode(decode("4ZVsZN4foCh82rehBbDkHvRWdtEJyvNMBce"))),
     ?_assert("4ZVnFV7q49aFtUBMSXun2bgGxMhLYHEAHaC" =:= encode(decode("4ZVnFV7q49aFtUBMSXun2bgGxMhLYHEAHaC"))),
     ?_assert("4ZVnFV7q" =:= encode(decode("4ZVnFV7q"))),
     ?_assert(132595939334988 =:= decode("1234567891")),
     ?_assert(2286136885086 =:= decode("123456789")),
     ?_assert(7690564481429305 =:= decode("12345678912")),
     ?_assert(7690564481429860 =:= decode("123456789Ab")),
     ?_assert("5P" =:= encode(254))
    ].
