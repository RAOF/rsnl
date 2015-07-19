#![feature(negate_unsigned)]
#![feature(plugin)]
#![plugin(bindgen_plugin)]

extern crate libc;

mod bindings {
	#![allow(dead_code)]
	#![allow(non_camel_case_types)]
	#![allow(non_snake_case)]
	#![allow(non_upper_case_globals)]

	use libc::size_t;
	use libc::ssize_t;
	use libc::uint32_t;
	use libc::uint64_t;
	use libc::uint16_t;
	use libc::uint8_t;

	pub type __u16 = u16;
	pub type __u32 = u32;
	pub type __u8 = u8;
	pub type __u64 = u64;
	pub type __s32 = i32;
	pub type __be16 = u16;

	pub type __socklen_t = i32;
	pub type sa_family_t = u16;

	#[repr(C)]
	pub struct FILE;

	#[repr(C)]
	pub struct Struct_iovec;

	#[repr(C)]
	pub struct Struct_addrinfo;

	bindgen!("/usr/include/libnl3/netlink/msg.h", link="nl-3", match="msg.h", match="netlink", match="socket.h", clang_args="-I", clang_args="/usr/include/libnl3");
}


// RSNL datatypes wrapping the libnl data structures
pub struct Socket {
	ptr: *mut bindings::Struct_nl_sock
}

impl Socket {
	pub fn new() -> Socket {
		unsafe {
			let nlptr = bindings::nl_socket_alloc();
			Socket {
				ptr: nlptr
			}
		}
	}

	pub fn set_buffer_size(&self, rxbuf: ::libc::c_int, txbuf: ::libc::c_int) -> i32 {
		unsafe {
			bindings::nl_socket_set_buffer_size(self.ptr, rxbuf, txbuf)
		}
	}

	pub fn connect(&self, protocol: NetlinkProtocol) -> i32 {
		unsafe { bindings::nl_connect(self.ptr, protocol as i32) }
	}

	pub fn close(&self) {
		unsafe{ bindings::nl_close(self.ptr) }
	}

	pub fn get_fd(&self) -> i32 {
		unsafe { bindings::nl_socket_get_fd(self.ptr) }
	}

	pub fn get_local_port(&self) -> u32 {
		unsafe { bindings::nl_socket_get_local_port(self.ptr) }
	}

	pub fn set_local_port(&self, port: u32) {
		unsafe { bindings::nl_socket_set_local_port(self.ptr, port) }
	}

	pub fn send_simple(&self, msg_type: ::libc::c_int, flags: ::libc::c_int, buf: *const u8, size: ::libc::size_t) -> ::libc::c_int {
		unsafe { bindings::nl_send_simple(self.ptr, msg_type, flags, buf as *mut ::libc::c_void, size) }
	}
}

impl Default for Socket {
	fn default() -> Socket {
		Socket::new()
	}
}

impl Drop for Socket {
	fn drop(&mut self) {
		unsafe {
			bindings::nl_socket_free(self.ptr);
		}
	}
}

pub struct Message {
	ptr: *mut bindings::Struct_nl_msg
}

use std::ffi::CString;

impl Message {
	pub fn new() -> Message {
	    unsafe {
			let nlmsg = bindings::nlmsg_alloc();
			Message {
				ptr: nlmsg
			}
		}
	}

	pub fn put(&mut self, name : i32, value : &AttributeValue) {
		unsafe {
			match *value {
				AttributeValue::Raw(data) => bindings::nla_put(self.ptr, name, data.len() as i32, data as *const _ as *const ::libc::c_void),
				AttributeValue::U8(data) => bindings::nla_put_u8(self.ptr, name, data),
				AttributeValue::U16(data) => bindings::nla_put_u16(self.ptr, name, data),
				AttributeValue::U32(data) => bindings::nla_put_u32(self.ptr, name, data),
				AttributeValue::U64(data) => bindings::nla_put_u64(self.ptr, name, data),
				AttributeValue::String(data) => bindings::nla_put_string(self.ptr, name, CString::new(data).unwrap().as_ptr()),
				AttributeValue::Flag(true) => bindings::nla_put_flag(self.ptr, name),
				AttributeValue::Flag(false) => 1,
				AttributeValue::Msec(data) => bindings::nla_put_msecs(self.ptr, name, data),
				AttributeValue::Nested(_) => unimplemented!()
			};
		}
	}
}

impl Default for Message {
	fn default() -> Message {
		Message::new()
	}
}

impl Drop for Message {
	fn drop(&mut self) {
		unsafe {
			bindings::nlmsg_free(self.ptr);
		}
	}
}

impl IntoIterator for Message {
	type Item = Attribute;
	type IntoIter = MessageIterator;

	fn into_iter(self) -> Self::IntoIter {
		unsafe {
		MessageIterator { current: bindings::nlmsg_attrdata(bindings::nlmsg_hdr(self.ptr), 0),
		              remaining : bindings::nlmsg_attrlen(bindings::nlmsg_hdr(self.ptr), 0) }
		          }
	}
}

pub struct MessageIterator {
	current : *const bindings::Struct_nlattr,
	remaining : i32
}

impl Iterator for MessageIterator {
	type Item = Attribute;
	fn next(&mut self) -> Option<Attribute> {
		if self.remaining > 0 {
			unsafe {
				if bindings::nla_ok(self.current, self.remaining) != 0 {
					let cur = Attribute::from_ptr(self.current);
					self.current = bindings::nla_next(self.current, &mut self.remaining);
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

pub enum NetlinkProtocol {
	Route,
	Unused,
	Usersock,
	Firewall,
	SockDiag,
	NfLog,
	Xfrm,
	Selinux,
	Iscsi,
	Audit,
	FibLookup,
	Connector,
	Netfilter,
	Ip6Fw,
	Dnrtmsg,
	KobjectUevent,
	DMEVENTS,
	Scsitransport,
	Ecryptfs,
	Rdma,
	Crypto,
	Zu= 30
}

#[derive(Debug)]
pub enum AttributeValue<'a> {
	Raw(&'a [u8]),
	U8(u8),
	U16(u16),
	U32(u32),
	U64(u64),
	String(&'a str),
	Flag(bool),
	Msec(u64),
	Nested(&'a [AttributeValue<'a>])
}

pub struct Attribute {
	attr : *const bindings::Struct_nlattr
}

impl Attribute {
	unsafe fn from_ptr(wrappee : *const bindings::Struct_nlattr) -> Attribute {
		Attribute { attr : wrappee }
	}

	pub unsafe fn as_uint8(&self) -> u8 {
		bindings::nla_get_u8(self.attr)
	}

	pub fn name(&self) -> i32 {
		unsafe { bindings::nla_type(self.attr) }
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn iterates_over_message_attributes() {
		let names = [1, 5, 27];
		let data : [u8; 3] = [8, 9, 22];
		let attr_payload : Vec<_> = data.iter().map(|val| AttributeValue::U8(*val)).collect();

		let mut message = Message::new();

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
