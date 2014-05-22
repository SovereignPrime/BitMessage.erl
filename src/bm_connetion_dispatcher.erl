-module(bm_connetion_dispatcher).

-behaviour(gen_server).

-include("../include/bm.hrl").

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1,  % {{{1
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).  % }}}

-export([get_socket/0]).

-record(state, {addr}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->  % {{{1
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

get_socket() ->  % {{{1
    bm_db:wait_db(),
    gen_server:call(?MODULE, register, infinity).

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
init([]) ->  % {{{1
    bm_db:wait_db(),
    NAddr = case bm_db:first(addr) of
        '$end_of_table' ->
            {ok, Ips} = inet:getaddrs("bootstrap8444.bitmessage.org", inet),
            
            %Ips= [{192,168,24,112}],
            ConfAddrs = lists:map(fun({I, P, S}) ->
                                         #network_address{ip=I,
                                                          port=P,
                                                          stream=S,
                                                          time=bm_types:timestamp()}
                                 end, 
                                 application:get_env(bitmessage, peers, [])),
            error_logger:info_msg("Recieved addrs ~p~n ~p~n", [Ips, ConfAddrs]),
            Addrs = lists:map(fun({Ip1, Ip2, Ip3, Ip4} = Ip) ->
                            {_MSec, Sec, MiSec} = now(),
                            Time = trunc( Sec*1.0e6 + MiSec),
                            #network_address{
                                time=Time, stream=1, ip=Ip, port=8444}
                    end, Ips),
            bm_db:insert(addr, Addrs),
            bm_db:insert(addr, ConfAddrs),
            bm_db:first(addr);
        Addr ->
            Addr
    end,
    {ok, #state{addr=NAddr}}.

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
handle_call(register, _From, #state{addr=Addr}=State) ->  % {{{1
    case connect_peer(Addr) of
        {ok, Socket, NAddr} ->
            %gen_tcp:controlling_process(Socket, From),
            {reply, {gen_tcp, Socket}, State#state{addr=NAddr}};
         E -> 
            {stop, E, State}
    end;
handle_call(_Request, _From, State) ->  % {{{1
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
handle_cast(_Msg, State) ->  % {{{1
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
handle_info(_Info, State) ->  % {{{1
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
terminate(_Reason, _State) ->  % {{{1
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->  % {{{1
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
connect_peer('$end_of_table') ->  % {{{1
    error_logger:info_msg("Connecton list ended~n"),
    timer:sleep(500000),
    connect_peer(bm_db:first(addr));
connect_peer(Addr) ->  % {{{1
    case bm_db:lookup(addr, Addr) of
        [ #network_address{ip=Ip, port=Port, stream=_Stream, time=_Time} ]  ->
            case gen_tcp:connect(Ip, Port, [inet,  binary, {active,false}, {reuseaddr, true}, {packet, raw}], 1000) of
                {ok, Socket} ->
                    {ok, Socket, bm_db:next(addr, Addr)};
                {error, _Reason} ->
                    connect_peer(bm_db:next(addr, Addr))
            end
    end.
