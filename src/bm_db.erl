-module(bm_db).

-behaviour(gen_server).
-include("../include/bm.hrl").
-define(R(Type), #Type{}).
%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, %  {{{1
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]). %}}}
-export([ % {{{1
    insert/2,
    first/1,
    next/2,
    lookup/2,
    foldr/3, 
    select/3,
    match/2,
    delete/2,
    clear/1,
    ackselect/0,
    wait_db/0,
    get_net/0
    ]). %}}}

-record(state, {addr}).

-type type() :: message 
             | pubkey 
             | privkey
             | inventory
             | network_address.

-type table() :: type() 
                | 'incoming' 
                | 'sent' 
                | 'addr'.

-type type_record() :: #message{}
                    | #pubkey{}
                    | #privkey{}
                    | #inventory{}
                    | #network_address{}.

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error} %  {{{1
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%--------------------------------------------------------------------
%% @doc
%% Insert data into DB
%%
%% @end
%%--------------------------------------------------------------------
-spec insert(table(), [type_record()]) -> {atomic, ok} | {error, atom()}. %  {{{1
insert(Type, Data) ->
    gen_server:call(?MODULE, {insert, Type, Data}).

%% @doc Gets id of first element of `Type` table
%%
-spec first(table()) -> any(). %  {{{1
first(Type)->
    gen_server:call(?MODULE, {first, Type}).

%% @doc Gets id of next element of `Type` table
%%
-spec next(table(), any()) -> any(). %  {{{1
next(Type, Prev)->
    gen_server:call(?MODULE, {next, Type, Prev}).

%% @doc Gets element from `Type` table with `ID`
%%
-spec lookup(table(), term()) -> any(). %  {{{1
lookup(Type, Id)->
    gen_server:call(?MODULE, {get, Type, Id}).

%% @doc Fold `Fun` through all `Type` elements
%%
-spec foldr(fun((type_record(), TAcc) -> term()), TAcc, type()) -> any(). %  {{{1
foldr(Fun, Acc, Type)->
    gen_server:call(?MODULE, {foldr, Fun, Type, Acc}).

%% @doc Select `MatchSpec` for `Type` limit `N`
%%
-spec select(table(), [MatchSpec], non_neg_integer()) -> [type_record()] when  % {{{1
      MatchSpec :: {type_record(), [tuple()], [atom()]}.
select(Type, MatchSpec, N)->
    gen_server:call(?MODULE, {select, Type, MatchSpec, N}).

%% @doc Matches `MatchSpec` for `Type` 
%%
-spec match(table(), type_record()) -> [type_record()].  %  {{{1
match(Type, MatchSpec)->
    gen_server:call(?MODULE, {match, Type, MatchSpec}).

%% @doc Deletes element w/`Id` from `Type` table
%%
-spec delete(table(), term()) -> ok.
delete(Type, Id)-> %  {{{1
    gen_server:cast(?MODULE, {del, Type, Id}).

%% @doc Get next peer to connect
%%
-spec get_net() -> #network_address{}. %  {{{1
get_net()->
    gen_server:call(?MODULE, net).

%% @doc 
%% Clears DB from outdated data
%%
%% Used by bm_clear_fsm
%% @end
-spec clear(MaxAddrAge) -> ok when  % {{{1
      MaxAddrAge :: integer().
clear(Addr) ->
    gen_server:cast(?MODULE, {clear, Addr}).

%% @doc 
%% Selects messages w/o akc to resend
%%
%% Used by bm_clear_fsm ??? 
-spec ackselect() -> {atomic, [#message{}]} 
                     | {error, string()}.
ackselect() -> %  {{{1
    gen_server:call(?MODULE, ackselect).

%% @doc
%% Waits for DB to initialize
%%
%% @end
-spec wait_db() -> ok.
wait_db() -> %  {{{1
    Timeout = application:get_env(bitmessage, table_wait, 65536),
    OK = mnesia:wait_for_tables([privkey, addr, inventory, sent], Timeout),
    if OK == ok -> %  {{{2
            ok;
        true ->
            wait_db()
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) -> %  {{{1
    case mnesia:wait_for_tables([inventory, privkey, addr], 5000) of
        {timeout, [inventory, privkey, addr]}  ->
            mnesia:stop(),
            mnesia:create_schema([node()]),
            mnesia:start(),
            {atomic, ok} = mnesia:create_table(inventory, [{disc_copies, [node()]}, {attributes, record_info(fields, inventory)}, {type, set}]),
            {atomic, ok} = mnesia:create_table(pubkey, [{disc_copies, [node()]}, {attributes, record_info(fields, pubkey)}, {type, set}]),
            {atomic, ok} = mnesia:create_table(privkey, [{disc_copies, [node()]}, {attributes, record_info(fields, privkey)}, {type, set}]),
            {atomic, ok} = mnesia:create_table(addr, [{disc_copies, [node()]}, {attributes, record_info(fields, network_address)}, {type, set}, {record_name, network_address}]),
            {atomic, ok} = mnesia:create_table(incoming, [{disc_copies, [node()]}, {attributes, record_info(fields, message)}, {type, set}, {record_name, message}]),
            {atomic, ok} = mnesia:create_table(sent, [{disc_copies, [node()]}, {attributes, record_info(fields, message)}, {type, set}, {record_name, message}]);
        {timeout, _} ->
            timer:sleep(5000);
         ok ->
            ok;
        {error, R} -> 
            exit(R)
    end, % }}}
    {ok, #state{}}. % }}}

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(net, _From, #state{addr=Addr} = State) -> %  {{{1
    {atomic,
     [#network_address{ip=Ip}=Data]} = mnesia:transaction(
               fun() ->
                       Id = case Addr of
                           A when A == 'undefined';
                                  A == '$end_of_table' ->
                                    mnesia:first(addr);
                                A ->
                                    mnesia:next(addr, A)
                            end,
                       NA = mnesia:read(addr, Id)
               end),
    {reply, Data, State#state{addr=Ip}};
handle_call({first, Type}, _From, State) -> %  {{{1
    {atomic, Data} = mnesia:transaction(fun() ->
                    mnesia:first(Type)
            end),
    {reply, Data, State};
handle_call({next, Type, Prev}, _From, State) -> %  {{{1
    {atomic, Data} = mnesia:transaction(fun() ->
                    mnesia:next(Type, Prev)
            end),
    {reply, Data, State};
handle_call({get, Type, Key}, _From, State) -> %  {{{1
    {atomic, Data} = mnesia:transaction(fun() ->
                    mnesia:read(Type, Key)
            end),
    {reply, Data, State};
handle_call({foldr, Fun,  Type, Acc}, _From, State) -> %  {{{1
    {atomic, Data} = mnesia:transaction(fun() -> 
                    mnesia:foldr(Fun, Acc, Type)
            end),
    {reply, Data, State};
handle_call({select, Type, MatchSpec, N}, _From, State) -> %  {{{1
     {atomic, Data} = mnesia:transaction(fun() ->
                case mnesia:select(Type, MatchSpec, N, read) of
                    {D, C} ->
                        iterate(C, [ D ]);
                    '$end_of_table' ->
                        []
                end
            end),
        {reply, Data, State};
handle_call({match, Type, MatchSpec}, _From, State) -> %  {{{1
     {atomic, Data} = mnesia:transaction(fun() -> 
                    mnesia:match_object(Type, MatchSpec, read)
            end),
    {reply, Data, State};
handle_call({insert, Type, Data}, _From, State) -> %  {{{1
     R = mnesia:transaction(fun() -> 
                insert_obj(Type, Data)
        end),
    {reply, R, State};
handle_call(ackselect, _From, State) -> %  {{{1
    R = mnesia:transaction(fun() -> 
                                   A = mnesia:select(sent, [{#message{status=ackwait, _='_'}, [], ['$_']}]),
                                   CTime = bm_types:timestamp(),
                                   lists:filter(fun(#message{payload = <<_:64/bits, Time:64/big-integer, _/bytes>>}) ->
                                                        CTime > Time
                                                end, A)

                           end),
    {reply, R, State};
handle_call(_Request, _From, State) -> %  {{{1
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast({clear, Addr}, State) -> %  {{{1
    mnesia:transaction(fun() -> 
                               Time= bm_types:timestamp(),
                               Len = mnesia:table_info(inventory, size),
                               if Len >= 5000 ->
                                      Addrs = mnesia:select(addr,
                                                            [{#network_address{
                                                                 time='$1',
                                                                 _='_'},
                                                              [{'<',
                                                                '$1',
                                                                (Time - Addr)}],
                                                              ['$_']}]),

                                      lists:foreach(fun(A) -> 
                                                            mnesia:delete_object(A)
                                                    end, Addrs),
                                      Invs = mnesia:select(inventory,
                                                           [
                                                            {#inventory{time='$1',
                                                                        type='$2',
                                                                        _='_'},
                                                             [{'<',
                                                               '$1',
                                                               Time}],
                                                             ['$_']}
                                                           ]),
                                      lists:foreach(fun(A) ->
                                                            mnesia:delete_object(A)
                                                    end, Invs),
                                      PubKeys = mnesia:select(pubkey,
                                                              [{#pubkey{time='$1',
                                                                        _='_'},
                                                                [{'<',
                                                                  '$1',
                                                                  Time}],
                                                                ['$_']}]),

                                      lists:foreach(fun(A) ->
                                                            mnesia:delete_object(A)
                                                    end, PubKeys);
                                  true ->
                                      ok
                               end
                       end),
    {noreply, State};
handle_cast({insert, Type, Data}, State) -> %  {{{1
     R = mnesia:transaction(fun() -> 
                insert_obj(Type, Data)
        end),
    {noreply, State};
handle_cast({del, Type, Data}, State) -> %  {{{1
     R = mnesia:transaction(fun() -> 
                mnesia:delete({ Type, Data })
        end),
    {noreply, State};
handle_cast(_Msg, State) -> %  {{{1
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) -> %  {{{1
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) -> %  {{{1
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) -> %  {{{1
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
insert_obj(_, []) -> %  {{{1
    ok;
insert_obj(Type, [I|R]) -> %  {{{1
    mnesia:write(Type, I, write),
    insert_obj(Type, R).
iterate(C, Acc) -> %  {{{1
    case mnesia:select(C) of %  {{{2
        {D, Cont} -> 
            Acc ++ [D] ++ iterate(Cont, Acc);
        '$end_of_table' -> 
            Acc
    end.
