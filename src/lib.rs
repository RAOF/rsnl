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
	fn nlmsg_alloc_simple(msg_type : c_int, flags : c_int) -> *const nl_msg;
	fn nlmsg_free(msg: *const nl_msg);

	pub fn nlmsg_hdr(msg: *const nl_msg) -> *const nlmsghdr;
	pub fn nlmsg_attrdata(hdr: *const nlmsghdr, header_length: c_int) -> *const nl_attr;
	pub fn nlmsg_attrlen(hdr: *const nlmsghdr, header_length: c_int) -> i32;

	pub fn nla_type(attr: *const nl_attr) -> c_int;
	pub fn nla_get_u8(msg: *const nl_attr) -> u8;

	fn nla_next(cur : *const nl_attr, remaining : &mut i32) -> *const nl_attr;
	fn nla_ok(cur : *const nl_attr, remaining: i32) -> bool;

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

#[derive(Debug)]
pub enum AttributeValue {
	U8(u8),
}

pub struct Attribute {
	attr : *const nl_attr
}

impl Attribute {
	unsafe fn from_ptr(wrappee : *const nl_attr) -> Attribute {
		Attribute { attr : wrappee }
	}

	pub unsafe fn as_uint8(&self) -> u8 {
		nla_get_u8(self.attr)
	}

	pub fn name(&self) -> i32 {
		unsafe { nla_type(self.attr) }
	}
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

	pub fn put(&mut self, name : i32, value : &AttributeValue) {
		unsafe {
			match *value {
				AttributeValue::U8(data) => nla_put_u8(self.ptr, name, data)
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

impl IntoIterator for msg {
	type Item = Attribute;
	type IntoIter = MsgIterator;

	fn into_iter(self) -> Self::IntoIter {
		unsafe {
		MsgIterator { current: nlmsg_attrdata(nlmsg_hdr(self.ptr), 0),
		              remaining : nlmsg_attrlen(nlmsg_hdr(self.ptr), 0) }
		          }
	}
}

pub struct MsgIterator {
	current : *const nl_attr,
	remaining : i32
}

impl Iterator for MsgIterator {
	type Item = Attribute;
	fn next(&mut self) -> Option<Attribute> {
		if self.remaining > 0 {
			unsafe {
				if nla_ok(self.current, self.remaining) {
					let cur = Attribute::from_ptr(self.current);
					self.current = nla_next(self.current, &mut self.remaining);
					Some(cur)
				}
				else {
					None
				}
			}
		}
		else {
			None
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
		let attr_payload = AttributeValue::U8(attr_value);

		let mut message = msg::new();
		message.put(attr_name, &attr_payload);

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

	#[test]
	fn iterates_over_message_attributes() {
		let names = [1, 5, 27];
		let data : [u8; 3] = [8, 9, 22];
		let mut attr_payload : [AttributeValue; 3] = [AttributeValue::U8(1), AttributeValue::U8(3) , AttributeValue::U8(5)];

		for (index, value) in data.iter().enumerate() {
			attr_payload[index] = AttributeValue::U8(*value);
		}

		let mut message = msg::new();

		for (name, payload) in names.iter().zip(attr_payload.iter()) {
			message.put(*name, payload);
		}

		for (index, attr) in message.into_iter().enumerate() {
			unsafe {
				assert_eq!(names[index], attr.name());
				assert_eq!(data[index], attr.as_uint8());
			}
		}
	}
}
