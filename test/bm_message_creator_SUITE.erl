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
         create_inv/0,
         create_inv/1
        ]).

-include_lib("common_test/include/ct.hrl").

%%%===================================================================
%%% Common Test callbacks {{{1
%%%===================================================================

all() ->  % {{{2
    [
     create_message,
     create_inv
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
    meck:new(bm_db),
    Config.

end_per_testcase(_TestCase, _Config) ->  % {{{2
    ok.

%%%===================================================================
%%% Test cases {{{1
%%%===================================================================

create_message() ->  % {{{2
    [].

create_message(_Config) ->  % {{{2
   <<233,190,180,217,77,83,71,0,0,0,0,0,0,0,0,0,0,0,0,4,123,250,149,166,84,69,83,
  84>> = bm_message_creator:create_message(<<"MSG">>, <<"TEST">>).

create_inv() -> % {{{2
    [].

create_inv(_Config) -> % {{{2
<<233,190,180,217,105,110,118,0,0,0,0,0,0,0,0,0,0,0,0,5,94,10,163,90,1,84,69,
  83,84>> = bm_message_creator:create_inv([<<"TEST">>]).

create_big_inv() -> % {{{2
    [].

create_big_inv(_Config) -> % {{{2
<<233,190,180,217,105,110,118,0,0,0,0,0,0,0,0,0,0,0,0,5,94,10,163,90,1,84,69,
  83,84>> = bm_message_creator:create_big_inv(1, []).
