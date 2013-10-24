-module(bm_encryptor_SUITE).

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
-export([my_test_case/0,
         encrypt_with_ready_key/1]).

-include_lib("common_test/include/ct.hrl").

%%%===================================================================
%%% Common Test callbacks
%%%===================================================================

all() ->
    [encrypt_with_ready_key].

suite() ->
    [{timetrap, {seconds, 300}}].

groups() ->
    [].

init_per_suite(Config) ->
    application:start(crypto),
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
    meck:new(bm_db),
    meck:expect(bm_db, lookup, fun(pubkey, R) ->
                    [#pubkey{pek = <<4, 242,77,231,128,27,224,111,245,192,199,18,25,200,84,35,125,232,41,
           87,76,122,153,246,50,246,129,137,39,226,153,151,43,125,204,193,182,
           105,199,235,152,13,185,10,35,161,4,51,37,190,10,165,208,134,138,
           193,20,182,91,239,47,239,107,206,78>>, 
                            psk = <<4, 174,86,19,151,81,157,137,218,
           138,210,233,19,9,41,186,237,144,176,197,224,139,205,200,133,32,223,
           147,86,242,102,32,205,71,240,227,4,15,49,124,10,53,57,113,5,115,83,
                            252,103,30,12,31,65,157,136,193,92,218,6,17,0,147,238,192,241>>, hash=R}];
                (privkey, R) ->
                [#privkey{hash=R, public= <<242,77,231,128,27,224,111,245,192,199,18,25,200,84,35,125,232,41,
           87,76,122,153,246,50,246,129,137,39,226,153,151,43,125,204,193,182,
           105,199,235,152,13,185,10,35,161,4,51,37,190,10,165,208,134,138,
           193,20,182,91,239,47,239,107,206,78,174,86,19,151,81,157,137,218,
           138,210,233,19,9,41,186,237,144,176,197,224,139,205,200,133,32,223,
           147,86,242,102,32,205,71,240,227,4,15,49,124,10,53,57,113,5,115,83,
           252,103,30,12,31,65,157,136,193,92,218,6,17,0,147,238,192,241>>,
                         psk= <<224,52,139,152,175,93,114,87,34,73,222,49,226,165,179,237,160,219,
                                224,82,34,110,89,24,119,128,91,23,33,203,205,241>>}]
                             end),
    meck:expect(bm_db, insert, fun(T, B) -> io:format("Table: ~p. Data: ~p~n", [T, B])  end),
    meck:new(bm_pow),
    meck:expect(bm_pow, make_pow, fun(P) -> crypto:rand_bytes(64)  end),
    Config.

end_per_testcase(_TestCase, _Config) ->
    %meck:unload(bm_db),
    %meck:unload(bm_pow),
    ok.

%%%===================================================================
%%% Test cases
%%%===================================================================

my_test_case() ->
    [].

encrypt_with_ready_key(_Config) ->
    bm_message_encryptor:start_link(#message{to = "BM-GtjvocmYdaNZEzGHuABKTELKdC4QMJyg", from = "BM-GtjvocmYdaNZEzGHuABKTELKdC4QMJyg", subject= <<"Subject">>, text= <<"Text">>,type=msg, status=new}).
