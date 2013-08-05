-module(bitmessage_auth).
-compile([export_all]).

addresstostream(<<"BM-",Address/binary>>) ->
    DAddress = b58:decode(Address),
    PDAddress = if length(DAddress) rem 2 /= 0 ->
            "0" ++ DAddress;
        true ->
            DAddress
    end,
    double_sha(DAddress).
    
