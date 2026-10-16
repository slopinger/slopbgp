import gleam/result
import slopbgp/bgp/message.{decode_message}
import slopbgp/types.{type BgpMessage}

pub type Socket

@external(erlang, "slopbgp_ffi", "now_seconds")
pub fn now() -> Int

@external(erlang, "slopbgp_ffi", "tcp_listen")
pub fn listen(port: Int, bind_ip: String) -> Result(Socket, String)

@external(erlang, "slopbgp_ffi", "tcp_accept")
pub fn accept(listen_socket: Socket, timeout: Int) -> Result(Socket, String)

@external(erlang, "slopbgp_ffi", "tcp_connect")
pub fn connect(host: String, port: Int, timeout: Int) -> Result(Socket, String)

@external(erlang, "slopbgp_ffi", "tcp_send")
pub fn send(socket: Socket, data: BitArray) -> Result(Nil, String)

@external(erlang, "slopbgp_ffi", "tcp_recv")
pub fn recv(
  socket: Socket,
  length: Int,
  timeout: Int,
) -> Result(BitArray, String)

@external(erlang, "slopbgp_ffi", "tcp_close")
pub fn close(socket: Socket) -> Nil

@external(erlang, "slopbgp_ffi", "tcp_peername")
pub fn peername(socket: Socket) -> Result(#(String, Int), String)

pub fn read_full_bgp_message(
  socket: Socket,
  buffer: BitArray,
  has_add_path: Bool,
  timeout: Int,
) -> Result(#(BgpMessage, BitArray), String) {
  // First try decoding from existing buffer
  case decode_message(buffer, has_add_path) {
    Ok(#(msg, rem)) -> Ok(#(msg, rem))
    Error(_) -> {
      // Need more data from socket
      use chunk <- result.try(recv(socket, 0, timeout))
      let new_buffer = <<buffer:bits, chunk:bits>>
      case decode_message(new_buffer, has_add_path) {
        Ok(#(msg, rem)) -> Ok(#(msg, rem))
        Error(_) ->
          read_full_bgp_message(socket, new_buffer, has_add_path, timeout)
      }
    }
  }
}
