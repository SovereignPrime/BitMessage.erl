-module(bm_attachment_srv).

-behaviour(gen_server).
-include("../include/bm.hrl").

%% API functions
-export([start_link/3]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {
          callback=bitmessage :: module(),
          file :: #bm_file{},
          path="" :: string(),
          chunks :: [binary()],
          remaining :: [binary()],
          timeout=100 :: non_neg_integer()
         }).

%%%===================================================================
%%% API functions   {{{1
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Hash, Path, Callback) ->   % {{{2
    gen_server:start_link(?MODULE, [Hash, Path, Callback], []).

%%%===================================================================
%%% gen_server callbacks {{{1
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
init([Hash, Path, Callback]) ->   % {{{2
    Timeout = application:get_env(bitmessage, chunk_timeout, 15 * 60000),
    [
     #bm_file{
        chunks=Chunks
       } = File] = bm_db:lookup(bm_file, Hash),
     {ok,
      #state{
         path=Path,
         file=File,
         chunks=Chunks,
         remaining=Chunks,
         callback=Callback,
         timeout=Timeout
        }, 
      0}.

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
handle_call(_Request, _From, State) ->   % {{{2
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
handle_cast(_Msg, State) ->   % {{{2
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
handle_info(timeout,   % {{{2
            #state{
               file=File,
               path=Path,
               chunks=Chunks,
               callback=Callback,
               remaining=[]
                  } = State) ->
    case lists:foldl(fun(CID, Acc) ->
                             case bm_db:lookup(bm_filechunk, CID) of
                                 [] -> 
                                     [CID | Acc];
                                 [_] ->
                                     Acc
                             end
                     end,
                     [],
                     Chunks) of
        [] ->
            ok=save_file(File, Path),
            Callback:downloaded(File#bm_file.hash),
            {stop, normal, State};
        Remaining ->
            {noreply, State#state{remaining=Remaining}, 0}
    end;
handle_info(timeout,   % {{{2
            #state{
               file=#bm_file{hash=FHash},
               timeout=Timeout,
               remaining=Chunks
                  } = State) ->
    MaxNChunks = application:get_env(bitmessage, chunk_requests_at_once, 1024),
    Remaining = if length(Chunks) > MaxNChunks ->
                       {Send, Rem} = lists:split(MaxNChunks, Chunks),
                       lists:foreach(fun(C) ->
                                             send_chunk_request(FHash, C)
                                     end,
                                     Send),
                       Rem;
                   true ->
                       lists:foreach(fun(C) ->
                                             send_chunk_request(FHash, C)
                                     end,
                                     Chunks),
                       []
                end,
    {noreply, State#state{remaining=Remaining}, Timeout};
handle_info(Info, #state{timeout=Timeout} = State) ->
    error_logger:warning_msg("Wrong event in ~p: ~p state ~p~n", [?MODULE_STRING, Info, State]),
    {noreply, State, Timeout}.

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
terminate(_Reason, _State) ->   % {{{2
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->   % {{{2
    {ok, State}.

%%%===================================================================
%%% Internal functions   % {{{1
%%%===================================================================
-spec send_chunk_request(FHash, CID) -> ok when  % {{{2
      FHash :: binary(),
      CID :: binary().
send_chunk_request(FHash, CID) ->
    bm_sender:send_broadcast(bm_message_creator:create_getchunk(FHash, CID)).

-spec save_file(#bm_file{}, Path) -> 'ok' | 'incomplete' when  % {{{2
      Path :: string().
save_file(#bm_file{
             name=Name,
             hash=Hash,
             chunks=Chunks,
             size=Size
            } = File,
          Path) ->
    BChuncks = lists:map(fun(C) ->
                                 [#bm_filechunk{data=BC}] = bm_db:lookup(bm_filechunk,
                                                                         C),
                                 BC
                         end,
                         Chunks),
    TarFile = << <<D/bytes>> || D <- BChuncks>>,
    erl_tar:extract(TarFile, [compressed, {cwd, Path}]),
    FPath = Path ++ "/" ++ Name,
    RSiaze = filelib:file_size(FPath),
    MercleRoot = bm_auth:mercle_root(Chunks),
    if RSiaze == Size, MercleRoot == Hash ->
        bm_db:insert(bm_file, [File#bm_file{path=Path ++ "/" ++ Name}]),
        ok;
       true ->
           incomplete
    end.



