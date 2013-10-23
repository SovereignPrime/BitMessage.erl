
-module(bitmessage_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 5000, Type, [I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    error_logger:logfile({open, "out.log"}),
    {ok, { {one_for_one, 5, 10}, [
               ?CHILD(bm_db, worker),
               ?CHILD(bm_address_generator, worker),
               ?CHILD(bm_pow, worker),
               ?CHILD(bm_decryptor_sup, supervisor),
               ?CHILD(bm_encryptor_sup, supervisor),
               ?CHILD(bm_dispatcher, worker),
               ?CHILD(bm_peer_sup, supervisor) 
                ]} }.



