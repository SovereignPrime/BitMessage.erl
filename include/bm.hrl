-define(MAGIC, 16#e9, 16#be, 16#b4, 16#d9).
-define(ADDR_PREFIX, "BM-").
-record(network_address, {time, stream, services=1, ip, port}).
-record(address, {version, stream, ripe}).
-record(object, {hash, stream, payload, type, time}).
-record(pubkey, {hash, data, psk, pek, used, time}).
-record(privkey, {hash, enabled=true, label, address, psk, pek, time}).
-record(message, {hash, to, from, subject, enc, folder, read=false, text}).

