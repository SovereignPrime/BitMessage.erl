-module(bm_attachment_srv).

-behaviour(gen_server).
-include("../include/bm.hrl").

%% API functions  {{{1
-export([
         start_link/2, 
         send_chunk/2,
         progress/1,
         received_chunk/2
        ]).

%% gen_server callbacks  {{{1
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
start_link(Hash, Path) ->   % {{{2
    gen_server:start_link(?MODULE, [Hash, Path], []).

%%--------------------------------------------------------------------
%% @doc
%% Sends filechunk to network
%%
%%--------------------------------------------------------------------
-spec send_chunk(FileHash, ChunkHash) -> ok when  % {{{2
      FileHash :: binary(),
      ChunkHash :: binary().
send_chunk(FileHash, ChunkHash) ->
    Timeout = crypto:rand_uniform(0, 300),
    timer:sleep(Timeout),
    InNetwork = is_filchunk_in_network(ChunkHash),
    if InNetwork ->
           ok;
       true ->
           encode_filechunk(FileHash, ChunkHash)
    end.

-spec progress(FileHash) -> float() when  % {{{2
      FileHash :: binary().
progress(FileHash) ->
    case bm_db:lookup(bm_file, FileHash) of
        [#bm_file{hash=FileHash,
                  chunks=Chunks}] ->
            All = length(Chunks),
            Here = lists:foldl(fun(CID, Acc) ->
                                       case bm_db:lookup(bm_filechunk, CID) of
                                           [] -> 
                                               Acc;
                                           [#bm_filechunk{data=undefined,
                                                          hash=CID}] -> 
                                               Acc;
                                           [_] ->
                                               Acc + 1
                                       end
                               end,
                               0.0,
                               Chunks),
            Here / All;
        _ ->
            0.0
    end.

-spec received_chunk(FileHash, ChunkHash) -> ok when  % {{{2
      FileHash :: binary(),
      ChunkHash :: binary().
received_chunk(FileHash, ChunkHash) -> 
    Pids = supervisor:which_children(bm_attachment_sup),
    error_logger:info_msg("Chunks received for pids ~p", [Pids]),
    send_all(Pids, {received, FileHash, ChunkHash}).

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
init([Hash, Path]) ->   % {{{2
    Timeout = application:get_env(bitmessage, chunk_timeout, 15) * 60000,
    case bm_db:lookup(bm_file, Hash) of
        [#bm_file{
            status=downloaded,
            name=Name,
            path=OPath
           } = File] ->
            FPath = OPath ++ "/" ++ Name,
            IsFile = filelib:is_file(FPath),
            if IsFile ->
                   error_logger:info_msg("File ~p is here", [FPath]),
                   file:copy(FPath, Path ++ "/" ++ Name),
                   bitmessage:downloaded(Hash),
                   {stop, normal};
               true ->
                   error_logger:info_msg("File ~p is not here", [Name]),
                   download(Path, File, Timeout)
            end;
        [File] ->
            download(Path, File, Timeout)
    end.

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
handle_cast({received, FileHash, ChunkHash},   % {{{2
            #state{
               chunks=Chunks,
               timeout=Timeout
              }=State) ->
    error_logger:info_msg("Chunks received"),
    IsMy = lists:member(ChunkHash, Chunks),
    All = length(Chunks),
    Here = progress(FileHash),
    if IsMy, Here == All ->
           error_logger:info_msg("~p chunks remaining", [0]),
           {noreply, State, 0};
       true ->
           error_logger:info_msg("~p chunks downloaded", [Here]),
           {noreply, State, Timeout}
    end;
handle_cast(Msg, State) ->   % {{{2
    error_logger:warning_msg("Wrong msg ~p  received in ~p", [Msg, ?MODULE_STRING]),
    {noreply, State, 0}.

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
               remaining=[]
                  } = State) ->
    case lists:foldl(fun(CID, Acc) ->
                             case bm_db:lookup(bm_filechunk, CID) of
                                 [] -> 
                                     [CID | Acc];
                                 [#bm_filechunk{data=undefined,
                                                hash=CID}] -> 
                                     [CID | Acc];
                                 [_] ->
                                     Acc
                             end
                     end,
                     [],
                     Chunks) of
        [] ->
            save_file(File, Path),
            bitmessage:downloaded(File#bm_file.hash),
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
    lists:foreach(fun(C) ->
                          send_chunk_request(FHash, C)
                  end,
                  Chunks),
    {noreply, State#state{remaining=[]}, Timeout};
handle_info(Info, #state{timeout=Timeout} = State) ->
    error_logger:warning_msg("Wrong event in ~p: ~p state ~p~n",
                             [?MODULE_STRING,
                              Info,
                              State]),

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
    case bm_db:lookup(bm_filechunk, CID) of
        [#bm_filechunk{data=Data}] when Data /= undefined ->
            ok;
        _ ->
            bm_db:insert(bm_filechunk, [#bm_filechunk{hash=CID, file=FHash}]),
            bm_sender:send_broadcast(bm_message_creator:create_getchunk(FHash, CID))
    end.

-spec save_file(#bm_file{}, Path) -> 'ok' | 'incomplete' when  % {{{2
      Path :: string().
save_file(#bm_file{
             name=Name,
             hash=Hash,
             chunks=Chunks,
             size=Size
            } = File,
          Path) ->
    FPath = Path ++ "/" ++ Name,
    TarFile = FPath ++ ".rz.tar.gz",
    {ok, F} = file:open(TarFile, [binary, append]),

    lists:foreach(fun(C) ->
                          [#bm_filechunk{data=BC}] = bm_db:lookup(bm_filechunk,
                                                                  C),
                          file:write(F, BC)
                  end,
                  Chunks),

    erl_tar:extract(TarFile, [compressed, {cwd, Path}]),
    RSiaze = filelib:file_size(FPath),
    MercleRoot = bm_auth:mercle_root(Chunks),
    error_logger:info_msg("Saving ~p size ~p(~p)[~p]~n", [FPath, RSiaze, Size, filelib:file_size(TarFile)]),
    if RSiaze == Size,
       MercleRoot == Hash ->
            bm_db:insert(bm_file, [File#bm_file{
                                     status=downloaded
                                    }]),
            ok;
        true ->
            incomplete
    end.

-spec is_filchunk_in_network(ChunkHash) -> boolean() when  % {{{2
      ChunkHash :: binary().
is_filchunk_in_network(ChunkHash) ->
    FileChunkObjs = bm_db:match(inventory, #inventory{type=?FILECHUNK}),
    lists:any(fun(#inventory{payload = <<_:22/bytes,
                                      CH:64/bytes,
                                      _/bytes>>}) when CH == ChunkHash ->
                      true;
                 (_) -> false
              end,
              FileChunkObjs).

-spec encode_filechunk(FileHash, ChunkHash) -> ok when  % {{{2
      FileHash :: binary(),
      ChunkHash :: binary().
encode_filechunk(FileHash, ChunkHash) ->
    case bm_db:lookup(bm_filechunk, ChunkHash) of
        [#bm_filechunk{data=undefined}] ->
            create_filechunk_from_file(FileHash, ChunkHash);
        [] ->
            create_filechunk_from_file(FileHash, ChunkHash);
        [#bm_filechunk{data=Data, 
                       payload=Payload}] when Data /= undefined, 
                                              Payload /= undefined ->
            ok
    end.

-spec download(Path, File, Timeout) -> {ok, #state{}, Timeout} when  % {{{2
      Path :: string(),
      File :: #bm_file{},
      Timeout :: non_neg_integer().
download(Path, #bm_file{
                  name=Name,
                  key={_Pub, Priv},
                  chunks=Chunks
               } = File,
         Timeout) ->
    NFile = File#bm_file{
              path=Path,
              status=downloading
             },
    bm_db:insert(bm_file, [NFile]),
    bm_decryptor_sup:add_decryptor(#privkey{pek=Priv}),
    error_logger:info_msg("Starting file ~p download", [Name]),
    {ok,
     #state{
        path=Path,
        file=NFile,
        chunks=Chunks,
        remaining=[],
        timeout=Timeout
       }, 
     0}.

-spec create_filechunk_from_file(FileHash, ChunkHash) -> ok when  % {{{2
      FileHash :: binary(),
      ChunkHash :: binary().
create_filechunk_from_file(FileHash, ChunkHash) ->
    case bm_db:lookup(bm_file,
                      FileHash) of
        [ #bm_file{path=Path,
                   name=Name,
                   chunks=ChunkHashes
                  } ] ->
            ChunkSize = application:get_env(bitmessage, chunk_size, 1024),
            FPath = Path ++ "/" ++ Name,
            IsFile = filelib:is_file(FPath),
            if IsFile ->
                   Location = length(lists:takewhile(fun(CH) ->
                                                             CH /= ChunkHash 
                                                     end,
                                                     ChunkHashes)) * ChunkSize,
                   error_logger:info_msg("Chunk location: ~p~n", [Location]),
                   TarPath = FPath  ++ ".rz.tar.gz",
                   erl_tar:create(TarPath,
                                  [{Name, FPath}],
                                  [compressed]),
                   {ok, F} = file:open(TarPath, [binary, read]),
                   case file:pread(F, Location, ChunkSize) of
                       {ok, Data} ->
                           bm_message_encryptor:start_link(#bm_filechunk{
                                                              hash=ChunkHash,
                                                              size=size(Data),
                                                              data=Data,
                                                              file=FileHash
                                                             }),
                           file:close(F),
                           %file:delete(TarPath),
                           ok;
                       _ ->
                           ok
                   end;
               true -> 
                   ok
            end;
        _ -> ok
    end.

-spec send_all(PIDs, Msg) -> ok when % {{{2
      PIDs :: [pid()],
      Msg :: term().
send_all([], _Msg) ->
    ok;
send_all([Pid|Rest], Msg) ->
    {_, P, _, _} = Pid,
    error_logger:info_msg("Sending to ~p (self ~p)msgh ~p", [P, self(), Msg]),
    gen_server:cast(P, Msg),
    send_all(Rest, Msg).
