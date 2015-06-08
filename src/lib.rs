#![feature(libc)]

#![allow(dead_code)]
#![allow(non_camel_case_types)]

extern crate libc;
use libc::c_int;

/**
 * Abstraction of libnl core functionality
 */
#[link(name="nl-3")]
extern "C" {
	// Exposed socket functions
	fn nl_socket_alloc() -> *const nl_sock;
	fn nl_socket_free(socket: *const nl_sock);
	fn nl_socket_get_fd(socket: *const nl_sock) -> i32;
	fn nl_socket_set_buffer_size(socket: *const nl_sock, rxbuf: c_int, txbuf: c_int) -> i32;
	
	fn nl_socket_set_local_port(socket: *const nl_sock, port: u32);
	fn nl_socket_get_local_port(socket: *const nl_sock) -> u32;

	fn nl_connect(socket: *const nl_sock, protocol: u32) -> i32;
	fn nl_close(socket: *const nl_sock);

	fn nl_socket_set_cb(socket: *const nl_sock, cb: *const nl_cb);
	fn nl_socket_get_cb(socket: *const nl_sock) -> nl_cb;

	// Exposed socket transceiver
	fn nl_send_simple(socket: *const nl_sock, msg_type: c_int, flags: c_int, buf: *const u8, size: c_int) -> i32;
	// Exposed msg functions
	fn nlmsg_alloc() -> *const nl_msg;
	fn nlmsg_free(msg: *const nl_msg);

	pub fn nlmsg_hdr(msg: *const nl_msg) -> *const nlmsghdr;
	pub fn nlmsg_attrdata(hdr: *const nlmsghdr, header_length: c_int) -> *const nl_attr;

	pub fn nla_type(attr: *const nl_attr) -> c_int;
	pub fn nla_get_u8(msg: *const nl_attr) -> u8;

	fn nla_put_u8(msg: *const nl_msg, name: c_int, value: u8) -> c_int;
}

// exposed structures - these are wrapped
#[repr(C)]
struct nl_sock;
#[repr(C)]
pub struct nl_msg;
#[repr(C)]
struct nl_cb;
#[repr(C)]
pub struct nl_attr;
#[repr(C)]
pub struct nlmsghdr;

// RSNL datatypes wrapping the libnl data structures
pub struct socket {
	ptr: *const nl_sock
}


/* library version of nlmsghdr
 * the name is altered to differentiate
 * between the native libnl and rsnl
 */
pub struct rsnl_msghdr {
	nlmsg_len: u32,
	nlmsg_type: u16,
	nlmsg_flags: u16,
	nlmsg_seq: u32,
	nlmsg_pid: u32
}

pub struct msg {
	ptr: *const nl_msg
}

pub enum NetlinkProtocol {
	route,
	unused,
	usersock,
	firewall,
	sock_diag,
	nflog,
	xfrm,
	selinux,
	iscsi,
	audit,
	fib_lookup,
	connector,
	netfilter,
	ip6_fw,
	dnrtmsg,
	kobject_uevent,
	DMEVENTS,
	scsitransport,
	ecryptfs,
	rdma,
	crypto,
	zu= 30
}


impl socket {
	pub fn new() -> socket {
		unsafe {
			let nlptr = nl_socket_alloc();
			socket {
				ptr: nlptr
			}
		}
	}

	pub fn set_buffer_size(&self, rxbuf: c_int, txbuf: c_int) -> i32 {
		unsafe {
			nl_socket_set_buffer_size(self.ptr, rxbuf, txbuf)
		}
	}

	pub fn connect(&self, protocol: NetlinkProtocol) -> i32 {
		unsafe { nl_connect(self.ptr, protocol as u32) }
	}

	pub fn close(&self) {
		unsafe{ nl_close(self.ptr) }
	}

	pub fn get_fd(&self) -> i32 {
		unsafe { nl_socket_get_fd(self.ptr) }
	}

	pub fn get_local_port(&self) -> u32 {
		unsafe { nl_socket_get_local_port(self.ptr) }
	}

	pub fn set_local_port(&self, port: u32) {
		unsafe { nl_socket_set_local_port(self.ptr, port) }
	}

	pub fn send_simple(&self, msg_type: c_int, flags: c_int, buf: *const u8, size: c_int) -> c_int {
		unsafe { nl_send_simple(self.ptr, msg_type, flags, buf, size) }
	}
}

impl Drop for socket {
	fn drop(&mut self) {
		unsafe {
			nl_socket_free(self.ptr);
		}
	}
}

pub enum AttrPayload {
	U8(u8),
}

pub struct Attribute {
	name : i32,
	payload : AttrPayload,
}

impl msg {
	pub fn new() -> msg {
	unsafe {
		let nlmsg = nlmsg_alloc();
		msg { 
			ptr: nlmsg
		}
	}
	}

	pub fn put(&mut self, attribute: &Attribute) {
		unsafe {
			match attribute.payload {
				AttrPayload::U8(value) => nla_put_u8(self.ptr, attribute.name, value)
			};
		}
	}
}

impl Drop for msg {
	fn drop(&mut self) {
		unsafe {
			nlmsg_free(self.ptr);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn emit_and_parse_u8_attribute() {
		let attr_name = 3;
		let attr_value = 5;
		let attr_payload = AttrPayload::U8(attr_value);

		let mut message = msg::new();
		message.put(&Attribute { name: attr_name, payload: attr_payload});

		let parsed_name = unsafe {
			let header = nlmsg_hdr(message.ptr);
			let raw_attr = nlmsg_attrdata(header, 0);
			nla_type(raw_attr)
		};

		assert_eq!(attr_name, parsed_name);

		let parsed_payload = unsafe {
			let header = nlmsg_hdr(message.ptr);
			let raw_attr = nlmsg_attrdata(header, 0);
			nla_get_u8(raw_attr)
		};

		assert_eq!(attr_value, parsed_payload);
	}
}
