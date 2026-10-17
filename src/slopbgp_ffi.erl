-module(slopbgp_ffi).
-export([
    now_seconds/0,
    tcp_listen/2,
    tcp_accept/2,
    tcp_connect/3,
    tcp_send/2,
    tcp_recv/3,
    tcp_close/1,
    tcp_peername/1,
    tcp_setopts/2,
    parse_ip_tuple/1,
    get_args/0,
    math_pow/2,
    math_log/1,
    math_cos/1,
    math_sin/1
]).

get_args() ->
    [list_to_binary(A) || A <- init:get_plain_arguments()].

now_seconds() ->
    erlang:system_time(second).

tcp_listen(Port, IpStr) ->
    Opts = [
        binary,
        {packet, 0},
        {active, false},
        {reuseaddr, true},
        {nodelay, true}
    ],
    IpOpts = case parse_ip_tuple(IpStr) of
        {ok, {_, _, _, _} = V4} -> [{ip, V4}];
        {ok, {_, _, _, _, _, _, _, _} = V6} -> [inet6, {ip, V6}];
        _ -> [inet6]
    end,
    case gen_tcp:listen(Port, Opts ++ IpOpts) of
        {ok, Socket} -> {ok, Socket};
        {error, Reason} -> {error, atom_to_binary(Reason, utf8)}
    end.

tcp_accept(ListenSocket, Timeout) ->
    case gen_tcp:accept(ListenSocket, Timeout) of
        {ok, Socket} -> {ok, Socket};
        {error, Reason} -> {error, atom_to_binary(Reason, utf8)}
    end.

tcp_connect(HostStr, Port, Timeout) ->
    Opts = [
        binary,
        {packet, 0},
        {active, false},
        {nodelay, true}
    ],
    Host = binary_to_list(HostStr),
    case parse_ip_tuple(HostStr) of
        {ok, {_, _, _, _} = V4} ->
            case gen_tcp:connect(V4, Port, Opts, Timeout) of
                {ok, Socket} -> {ok, Socket};
                {error, Reason} -> {error, atom_to_binary(Reason, utf8)}
            end;
        {ok, {_, _, _, _, _, _, _, _} = V6} ->
            case gen_tcp:connect(V6, Port, [inet6 | Opts], Timeout) of
                {ok, Socket} -> {ok, Socket};
                {error, Reason} -> {error, atom_to_binary(Reason, utf8)}
            end;
        _ ->
            case gen_tcp:connect(Host, Port, Opts, Timeout) of
                {ok, Socket} -> {ok, Socket};
                {error, Reason} -> {error, atom_to_binary(Reason, utf8)}
            end
    end.

tcp_send(Socket, Data) ->
    case gen_tcp:send(Socket, Data) of
        ok -> {ok, nil};
        {error, Reason} -> {error, atom_to_binary(Reason, utf8)}
    end.

tcp_recv(Socket, Length, Timeout) ->
    case gen_tcp:recv(Socket, Length, Timeout) of
        {ok, Data} -> {ok, Data};
        {error, Reason} -> {error, atom_to_binary(Reason, utf8)}
    end.

tcp_close(Socket) ->
    gen_tcp:close(Socket),
    nil.

tcp_peername(Socket) ->
    case inet:peername(Socket) of
        {ok, {Ip, Port}} ->
            IpStr = list_to_binary(inet:ntoa(Ip)),
            {ok, {IpStr, Port}};
        {error, Reason} ->
            {error, atom_to_binary(Reason, utf8)}
    end.

tcp_setopts(Socket, Active) ->
    Opt = case Active of
        true -> {active, true};
        false -> {active, false};
        once -> {active, once}
    end,
    case inet:setopts(Socket, [Opt]) of
        ok -> {ok, nil};
        {error, Reason} -> {error, atom_to_binary(Reason, utf8)}
    end.

parse_ip_tuple(Bin) when is_binary(Bin) ->
    Str = binary_to_list(Bin),
    case inet:parse_address(Str) of
        {ok, IpTuple} -> {ok, IpTuple};
        {error, einval} -> {error, einval}
    end;
parse_ip_tuple(_) ->
    {error, einval}.

math_pow(Base, Exp) when is_integer(Base) ->
    math_pow(float(Base), Exp);
math_pow(Base, Exp) when is_integer(Exp) ->
    math_pow(Base, float(Exp));
math_pow(Base, Exp) ->
    math:pow(Base, Exp).

math_log(Val) when is_integer(Val) ->
    math:log(float(Val));
math_log(Val) ->
    math:log(Val).

math_cos(Val) when is_integer(Val) ->
    math:cos(float(Val));
math_cos(Val) ->
    math:cos(Val).

math_sin(Val) when is_integer(Val) ->
    math:sin(float(Val));
math_sin(Val) ->
    math:sin(Val).

