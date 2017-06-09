//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use std::fmt;
use std::net::Ipv4Addr;
use byteorder::{ReadBytesExt, BigEndian};

use error::*;
use size;
use packet::Packet as P;
use ip::Protocol;
use ip::v4::Flags;
use ip::v4::option;
use ip::v4::checksum;

#[derive(Clone)]
pub struct Packet<B> {
	buffer: B,
}

sized!(Packet,
	header {
		min:  0,
		max:  0,
		size: 0,
	}

	payload {
		min:  0,
		max:  0,
		size: 0,
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("ip::v6::Packet")
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	pub fn new(buffer: B) -> Result<Packet<B>> {
		let packet = Packet {
			buffer: buffer,
		};

		if packet.buffer.as_ref().len() < <Self as size::header::Min>::min() {
			return Err(ErrorKind::InvalidPacket.into());
		}

		if packet.buffer.as_ref()[0] >> 4 != 6 {
			return Err(ErrorKind::InvalidPacket.into());
		}

		Err(ErrorKind::InvalidPacket.into())
	}
}

