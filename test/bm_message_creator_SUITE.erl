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
         create_big_inv/1
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
     create_big_inv
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

create_obj_test() ->
    [].

create_obj_test(_Config) ->
    meck:expect(bm_pow, make_pow, fun(Test) ->
                                          <<2048:64/big-integer, Test/bytes>>
                                  end),
    meck:expect(bm_pow, check_pow, fun(<<2048:64/big-integer, _Test/bytes>>) ->
                                          true
                                  end),
    MSG = bm_message_creator:create_obj(<<"msg">>,
                                        1,
                                        1,
                                        <<"Test Msg">>),
    <<233,190,180,217, % MAGIC
      109,115,103,0,0,0,0,0,0,0,0,0, % Command
      0,0,0,30, % Length
      _Check:32/big-integer,
      0,0,0,0,0,0,8,0, % POW
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
