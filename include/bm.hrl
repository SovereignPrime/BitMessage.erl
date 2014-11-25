-define(MAGIC, 16#e9, 16#be, 16#b4, 16#d9).
-define(ADDR_PREFIX, "BM-").

%% POW constants
-define(MIN_NTPB, 1000).
-define(MIN_PLEB, 1000).

%% @doc Binary message type
-type message_bin() :: binary().

%% @doc Network address storing structure
-record(network_address,
        {
         ip={127, 0, 0, 1} :: inet:ip_address() | atom(),
         port=8444 ::inet:port_number() | atom(),
         time :: bm_types:timestamp() | atom(),
         stream=1 :: integer() | atom(),
         services=1 :: integer() | atom() 
        }).

%% @doc Decoded bitmessage address structure
-record(address,
        {
         version :: integer(),
         stream=1 :: integer(),
         ripe :: binary()
        }).

%% Inventory structure
-record(inventory,
        {
         hash ::binary() | atom(),
         stream=1 :: integer() | atom(),
         payload :: binary() | atom(),
         type :: binary() | atom(),
         time :: bm_types:timestamp() | atom()
        }).

%% Public Key storing structure
-record(pubkey,
        {
         hash :: binary() | atom(),
         data :: binary() | atom(),
         psk :: binary() | atom(),
         pek :: binary() | atom(),
         used=false :: boolean() | atom(),
         time :: bm_types:timestamp() | atom()
        }).

%% Private Keys storing structure
-record(privkey,
        {hash :: binary(),
         enabled=true :: boolean(),
         label :: any(),
         address :: binary(),  % ???
         psk :: binary(),
         pek :: binary(),
         time :: bm_types:timestamp(),
         public :: binary()
        }).

%% Messages and broadcasts storing structure
-record(message,
        {
         hash :: binary() | atom(),
         to :: binary() | atom(),
         from :: binary() | atom(),
         subject :: binary() | atom(),
         enc=2 :: integer() | atom(),
         folder :: string() | atom(),  % ???
         text :: binary() | atom(),
         status=new :: atom() | atom(),  % Variants
         ackdata :: binary() | atom(),
         payload :: binary() | atom(),
         type :: binary() | atom()
        }).

