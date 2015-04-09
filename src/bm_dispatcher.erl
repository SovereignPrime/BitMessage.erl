-module(bm_dispatcher).

-behaviour(gen_server).

-include("../include/bm.hrl").

%% API  {{{1
-export([start_link/0]).
-export([
         register_receiver/1,
         send/1,
         get_attachment/2,
         generate_address/0,
         get_callback/0
]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).
% }}}

-record(state, {callback=bitmessage}).

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

%%--------------------------------------------------------------------
%% @doc
%% Callback when new incomming message or broadast arrived
%%
%% @end
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @doc
%% Send a message
%%
%% @end
%%--------------------------------------------------------------------
-spec send(#message{}) ->  ok. % {{{1
send(Message) ->
    NMessage = Message#message{hash=crypto:hash(sha512, Message#message.text),
                               folder=sent},
    mnesia:transaction(fun() ->
                               mnesia:write(message, NMessage, write)
                       end),
    gen_server:cast(?MODULE, {send, NMessage}).

%%--------------------------------------------------------------------
%% @doc
%% Generates new BM address
%%
%% @end
%%--------------------------------------------------------------------
-spec generate_address() ->  ok. % {{{1
generate_address() ->
    gen_server:cast(?MODULE, generate_address).

%%--------------------------------------------------------------------
%% @doc
%% Registers callback module
%%
%% @end
%%--------------------------------------------------------------------
-spec register_receiver(atom()) -> ok.  % {{{1
register_receiver(Callback) ->
    gen_server:cast(?MODULE, {register, Callback}).

%%--------------------------------------------------------------------
%% @doc
%% Get callback module
%%
%% @end
%%--------------------------------------------------------------------
-spec get_callback() -> module().  % {{{1
get_callback() ->
    gen_server:call(?MODULE, callback).

%%--------------------------------------------------------------------
%% @doc
%% Get attachment
%%
%% @end
%%--------------------------------------------------------------------
-spec get_attachment(binary(), string()) -> ok.  % {{{1
get_attachment(Hash, Path) ->
    gen_server:cast(?MODULE, {attachment, Hash, Path}).
%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @end
%%--------------------------------------------------------------------
-spec init([]) -> {ok, #state{}, non_neg_integer()}.  % {{{1
init([]) ->
    bm_db:wait_db(),
    {ok, #state{}, 0}.

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
handle_call(callback, _From, #state{callback=Callback}=State) ->  % {{{1
    {reply, Callback, State};
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
handle_cast({send, Message}, #state{callback=Callback}=State) ->  % {{{1
    error_logger:info_msg("Sending  ~p~n", [Message]),
    bm_encryptor_sup:add_encryptor(Message, Callback),
    {noreply, State};
handle_cast({attachment, Hash, Path}, #state{callback=Callback}=State) ->  % {{{1
    bm_attachment_sup:download_attachment(Hash, Path, Callback),
    {noreply, State};
handle_cast({register, Module}, State) ->  % {{{1
    {noreply, State#state{callback=Module}};
handle_cast(generate_address, #state{callback=Callback}=State) ->  % {{{1
    bm_address_generator:generate_random_address(make_ref(), 1, false, Callback),
    {noreply, State};
handle_cast(Msg, State) ->  % {{{1
    error_logger:warning_msg("Wrong cast ~p recved in ~p~n", [Msg, ?MODULE]),
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
handle_info(timeout, #state{callback=Callback}=State) ->  % {{{1
    Messages = bm_db:select(message,
                            [{#message{folder=sent,
                                       status='new',
                                       _='_'},
                              [],
                              ['$_']},
                             {#message{folder=sent,
                                       status='wait_pubkey',
                                       _='_'},
                              [],
                              ['$_']},
                             {#message{folder=sent,
                                       status='encrypt_message',
                                       _='_'},
                              [],
                              ['$_']}],
                            10000),
    error_logger:info_msg("Messages in progress: ~p~n", [Messages]),
    lists:foreach(fun(E) ->
                          bm_encryptor_sup:add_encryptor(E, Callback)
                  end,
                  lists:flatten(Messages)),
    Downloads = bm_db:match(bm_file, #bm_file{status=downloading,
                                              _='_'}),
    error_logger:info_msg("Downloads in progress: ~p~n", [Downloads]),
    lists:foreach(fun(#bm_file{
                         hash=Hash,
                         path=Path
                        }) ->
                          bm_attachment_sup:download_attachment(Hash, Path, Callback)
                  end,
                  Downloads),
    {noreply, State};
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
-spec save_files(binary()) -> [binary()].  % {{{1
save_files(Data) ->
    {Attachments,
     _} = bm_types:decode_list(Data,
                               fun(<<Hash:64/bytes,
                                     A/bytes>>) ->
                                       error_logger:info_msg("File: ~p~n", [A]),
                                       {Name,
                                        R1} = bm_types:decode_varstr(A),
                                       error_logger:info_msg("File: ~p, hash ~p~n", [Name, Hash]),
                                       {Size,
                                        R2} = bm_types:decode_varint(R1),
                                       error_logger:info_msg("File: ~p, size ~p~n", [Name, Size]),
                                       {Chunks,
                                        <<Key:32/bytes, 
                                          R3/bytes>>} = bm_types:decode_list(R2,
                                                                             fun(<<X:64/bytes,
                                                                                   Y/bytes>>) ->
                                                                                     {X, Y}
                                                                             end),
                                       {#bm_file{
                                           hash=Hash,
                                          name=Name,
                                          size=Size,
                                          chunks=Chunks,
                                          key={bm_auth:pubkey(Key), Key},
                                          time=calendar:universal_time()
                                         }, R3}
                               end), 
    bm_db:insert(bm_file, Attachments),
    lists:map(fun(#bm_file{hash=H}) ->
                      H
              end,
              Attachments).




