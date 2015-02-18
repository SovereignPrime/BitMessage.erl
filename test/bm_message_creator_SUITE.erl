-module(bm_message_creator_SUITE).
-include("../include/bm.hrl").

%% API
-export([all/0,
         suite/0,
         groups/0,
         init_per_suite/1,
         end_per_suite/1,
         group/1,
         init_per_group/2,
         end_per_group/2,
         init_per_testcase/2,
         end_per_testcase/2]).

%% Test cases
-export([
         create_message/0,
         create_message/1,
         create_obj_test/0,
         create_obj_test/1,
         create_inv/0,
         create_inv/1,
         create_big_inv/0,
         create_big_inv/1,
         save_obj_test/0,
         save_obj_test/1,
         create_getchunk_test/0,
         create_getchunk_test/1
        ]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Common Test callbacks {{{1
%%%===================================================================

all() ->  % {{{2
    [
     create_message,
     create_obj_test,
     create_inv,
     create_big_inv,
     save_obj_test,
     create_getchunk_test
    ].

suite() ->  % {{{2
    [{timetrap, {seconds, 30}}].

groups() ->  % {{{2
    [].

init_per_suite(Config) ->  % {{{2
    Config.

end_per_suite(_Config) ->  % {{{2
    ok.

group(_GroupName) ->  % {{{2
    [].

init_per_group(_GroupName, Config) ->  % {{{2
    Config.

end_per_group(_GroupName, _Config) ->  % {{{2
    ok.

init_per_testcase(_TestCase, Config) ->  % {{{2
     application:set_env(bitmessage, 'max_age_of_public_key', 1234),
     application:set_env(bitmessage, 'max_age_of_inventory', 1234),
    meck:new(bm_db),
    meck:new(bm_pow),
    Config.

end_per_testcase(_TestCase, _Config) ->  % {{{2
    meck:unload(),
    ok.

%%%===================================================================
%%% Test cases {{{1
%%%===================================================================

create_message() ->  % {{{2
    [].

create_message(_Config) ->  % {{{2
   <<233,190,180,217,77,83,71,0,0,0,0,0,0,0,0,0,0,0,0,4,123,250,149,166,84,69,83,
  84>> = bm_message_creator:create_message(<<"MSG">>, <<"TEST">>).

create_obj_test() ->  % {{{2
    [].

create_obj_test(_Config) ->  % {{{2
    meck:expect(bm_pow, make_pow, fun(Test) ->
                                          <<2048:64/big-integer, Test/bytes>>
                                  end),
    meck:expect(bm_pow, check_pow, fun(<<2048:64/big-integer, _Test/bytes>>) ->
                                          true
                                  end),
    MSG = bm_message_creator:create_obj(2,
                                        1,
                                        1,
                                        <<"Test Msg">>),
      <<0,0,0,0,0,0,8,0, % POW
      Time:64/big-integer,
      0,0,0,2, % Obj Type
      1, % Version
      1, % Stream
      "Test Msg">> = MSG,
    ?assert(Time >= bm_types:timestamp()),
    ?assert(meck:called(bm_pow, make_pow, '_')).

create_inv() -> % {{{2
    [].

create_inv(_Config) -> % {{{2
<<233,190,180,217,105,110,118,0,0,0,0,0,0,0,0,0,0,0,0,5,94,10,163,90,1,84,69,
  83,84>> = bm_message_creator:create_inv([<<"TEST">>]).

create_big_inv() -> % {{{2
    [].

create_big_inv(_Config) -> % {{{2
    meck:expect(bm_db,
                select,
                fun(inventory, _, 5000) ->
                        [[
                         <<"TEST">>],
                         [<<"REST">>,
                         <<"MOTHER">>
                        ]]
                end),

    [<<233,190,180,217,105,110,118,0,0,0,0,0,0,0,0,0,0,0,0,5,94,
       10,163,90,1,84,69,83,84>>,
     <<233,190,180,217,105,110,118,0,0,0,0,0,0,0,0,0,0,0,0,11,
       222,12,202,205,2,82,69,83,84,77,79,84,72,69,82>>] = 
    bm_message_creator:create_big_inv(1, []).

save_obj_test() -> % {{{2
    [].

save_obj_test(_Config) -> % {{{2
    meck:expect(bm_db,
                insert,
                fun(inventory,
                    [R]) ->
                        io:format("~p~n", [R]),
                        ok
                end),
    Time = 1424251288,
    MSG = <<0,0,0,0,0,0,8,0, % POW
            Time:64/big-integer,
            0,0,0,2, % Obj Type
            1, % Version
            1, % Stream
            "Test Msg">>,
    Inv = bm_message_creator:save_obj(MSG),
    ?assert(meck:called(bm_db, 
                        insert,
                        [inventory,
                         [#inventory{
                             hash = <<159,153,22,221,154,13,194,245,123,40,
                                      6,18,158,196,236,179,70,190,
                                      15,125,207,166,53,154,96,128,
                                      79,197,107,61,69,44>>,
                             stream = 1,
                             type = 2,
                             payload = <<0,0,0,0,0,0,8,0,0,0,0,0,84,228,
                                         89,152,0,0,0,2,1,1,84,101,115,116,
                                         32,77,115,103>>,
                             time='_'
                            }]])).

create_getchunk_test() -> % {{{2
    [].

create_getchunk_test(_Config) -> % {{{2
    meck:expect(bm_pow, make_pow, fun(Test) ->
                                          <<2048:64/big-integer, Test/bytes>>
                                  end),
    meck:expect(bm_pow, check_pow, fun(<<2048:64/big-integer, _Test/bytes>>) ->
                                          true
                                  end),
    meck:expect(bm_types, timestamp, fun() ->
                                         1426671437
                                  end),
    meck:expect(bm_db,
                insert,
                fun(inventory,
                    [R]) ->
                        io:format("~p~n", [R]),
                        ok
                end),
    Inv = bm_message_creator:create_getchunk(<<159,153,22,221,154,13,194,245,123,40,
                                               6,18,158,196,236,179,70,190,
                                               15,125,207,166,53,154,96,128,
                                               79,197,107,61,69,44>>,
                                             <<185,251,167,1,73,222,135,86,207,
                                               254,122,138,45,148,26,58,106,11,
                                               71,247,233,249,158,186,146,93,98,
                                               3,143,232,206,65>>),

    ?assert(meck:called(bm_db, 
                        insert,
                        [inventory,
                         [#inventory{
                             hash = <<71,105,77,205,43,215,125,94,156,163,
                                      196,224,38,103,219,52,116,182,
                                      55,199,46,143,56,20,125,100,82,
                                      196,183,250,46,68>>, 
                             stream = 1,
                             type = 5,
                             payload = <<0,0,0,0,0,0,8,0,0,0,0,0,85,
                                         46,49,77,0,0,0,5,1,1,159,153,22,221,
                                         154,13,194,245,123,40,6,18,158,196,236,
                                         179,70,190,15,125,207,166,
                                         53,154,96,128,79,197,107,61,69,44,
                                         185,251,167,1,73,222,135,86,207,
                                         254,122,138,45,148,26,58,106,11,71,
                                         247,233,249,158,186,146,93,98,
                                         3,143,232,206,65>>,
                             time='_'
                            }]])).
