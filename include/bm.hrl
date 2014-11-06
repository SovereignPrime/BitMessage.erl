-define(MAGIC, 16#e9, 16#be, 16#b4, 16#d9).
-define(ADDR_PREFIX, "BM-").

%% @doc Binary message type
-type message_bin() :: <<?MAGIC:4/bytes,
                         Command:12/bytes,
                         Length:32/big-integer,
                         Check:4/bytes,
                         Payload/bytes>>.

%% @doc Network address storing structure
-record(network_address,
        {
         ip :: inet:ip_address(),
         port ::inet:port_number(),
         time :: bm_types:timestamp(),
         stream=1 :: integer(),
         services=1 :: integer()
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
         hash ::binary(),
         stream=1 :: integer(),
         payload :: binary(),
         type :: binary(),
         time :: bm_types:timestamp()
        }).

%% Public Key storing structure
-record(pubkey,
        {
         hash :: binary(),
         data :: binary(),
         psk :: binary(),
         pek :: binary(),
         used=false :: boolean(),
         time :: bm_types:timestamp()
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
         public :: boolean()
        }).

%% Messages and broadcasts storing structure
-record(message,
        {
         hash :: binary(),
         to :: binary(),
         from :: binary(),
         subject :: binary(),
         enc=2 :: integer(),
         folder :: string(),  % ???
         text :: binary(),
         status=new :: atom(),  % Variants
         ackdata :: binary(),
         payload :: binary(),
         type :: binary()
        }).

