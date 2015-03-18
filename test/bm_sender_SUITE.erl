-module(bm_sender_SUITE).

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
         register_peer_test/0,
         register_peer_test/1,
         unregister_peer_test/0,
         unregister_peer_test/1,
         send_broadcast_test/0,
         send_broadcast_test/1
        ]).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Common Test callbacks  {{{1
%%%===================================================================

all() ->  % {{{2
    [
     unregister_peer_test,
     register_peer_test,
     send_broadcast_test
    ].

suite() ->  % {{{2
    [{timetrap, {seconds, 300}}].

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
    meck:new(test,[non_strict]),
    meck:new(bm_dispatcher,[]),
    meck:expect(test, connected, fun(_) ->
                                         ok
                                 end),
    meck:expect(bm_dispatcher, get_callback, fun() ->
                                                     test
                                             end),
    bm_sender:start_link(test),
    Config.

end_per_testcase(_TestCase, _Config) ->  % {{{2
    meck:unload(),
    ok.

%%%===================================================================
%%% Test cases  % {{{1
%%%===================================================================

register_peer_test() ->  % {{{2
    [].

register_peer_test(_Config) ->  % {{{2
    Socket = gen_tcp:listen(0, []),
    ok=bm_sender:register_peer(Socket),
    timer:sleep(1),
    [{Socket, _}] = ets:lookup(addrs, Socket),
    1 = ets:info(addrs, size),
    ?assert(meck:called(test, connected, [1])).


unregister_peer_test() ->  % {{{2
    [].

unregister_peer_test(_Config) ->  % {{{2
    Socket = gen_tcp:listen(0, []),
    meck:expect(test, disconnected, fun(_) ->
                                         ok 
                                    end),
    ok=bm_sender:register_peer(Socket),
    timer:sleep(1),
    [{Socket, _}] = ets:lookup(addrs, Socket),
    1 = ets:info(addrs, size),
    ok=bm_sender:unregister_peer(Socket),
    timer:sleep(1),
    [] = ets:lookup(addrs, Socket),
    0 = ets:info(addrs, size),
    ?assert(meck:called(test, disconnected, [0])).

send_broadcast_test() ->  % {{{2
    [].

send_broadcast_test(_Config) ->  % {{{2
    {ok, Socket1} = gen_tcp:listen(0, [inet]),
    {ok, Socket2} = gen_tcp:listen(0, [inet]),
    {ok, Socket3} = gen_tcp:listen(0, [inet]),
    ok=bm_sender:register_peer(Socket1),
    ok=bm_sender:register_peer(Socket2),
    ok=bm_sender:register_peer(Socket3),
    meck:expect(test, send, fun(S, <<"test">>) when S == Socket1 ->
                                    io:format("~p~n", [S]),
                                    ok;
                               (S, <<"test">>) when S == Socket2 ->
                                    io:format("~p~n", [S]),
                                    {error, "test"};
                               (S, <<"test">>)  when S == Socket3 ->
                                    io:format("~p~n", [S]),
                                    {error, timeout}
                            end),

    ok=bm_sender:send_broadcast(<<"test">>),
    true=meck:validate(test),
    meck:wait(test, send, [Socket3, <<"test">>], 300),
    meck:wait(test, send, [Socket2, <<"test">>], 300),
    meck:wait(test, send, [Socket1, <<"test">>], 300),
    2=ets:info(addrs, size),
    [] = ets:lookup(addrs, Socket2).


