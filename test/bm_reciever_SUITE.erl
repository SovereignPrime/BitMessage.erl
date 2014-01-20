-module(bm_reciever_SUITE).

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
         full_message_arrived/1,
         part_message_arrived/1,
         socket_close_error/1,
         socket_timeout/1,
         socket_error/1

    ]).

-include_lib("common_test/include/ct.hrl").

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [
     full_message_arrived,
     part_message_arrived,
     socket_close_error,
     socket_timeout,
     socket_error
    ].

suite() ->
    [{timestamp, {seconds, 30}}].

groups() ->
    [].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

group(_GroupName) ->
    [].

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%%===================================================================
%%% Test cases
%%%===================================================================
full_message_arrived(_Config) ->
part_message_arrived(_Config) ->
socket_close_error(_Config) ->
socket_timeout(_Config) ->
socket_erro(_Config) ->
