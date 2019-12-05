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


use std::io::Cursor;
use std::net::Ipv6Addr;
use byteorder::{WriteBytesExt, BigEndian};

use crate::error::*;
use crate::buffer::{self, Buffer};
use crate::builder::{Builder as Build, Finalization};
use crate::ip::Protocol;
use crate::ip::v6::Packet;

/// IPv6 packet builder.
pub struct Builder<B: Buffer = buffer::Dynamic> {
	buffer:    B,
	finalizer: Finalization,

	payload: bool,
}

impl<B: Buffer> Build<B> for Builder<B> {
	fn with(mut buffer: B) -> Result<Self> {
		use crate::size::header::Min;
		buffer.next(Packet::<()>::min())?;

		buffer.data_mut()[0] = (6 << 4) as u8;

		Ok(Builder {
			buffer:    buffer,
			finalizer: Default::default(),

			payload: false,
		})
	}

	fn finalizer(&mut self) -> &mut Finalization {
		&mut self.finalizer
	}

	fn build(mut self) -> Result<B::Inner> {
		self.prepare();

		let mut buffer = self.buffer.into_inner();
		self.finalizer.finalize(buffer.as_mut())?;
		Ok(buffer)
	}
}

impl Default for Builder<buffer::Dynamic> {
	fn default() -> Self {
		Builder::with(buffer::Dynamic::default()).unwrap()
	}
}

macro_rules! protocol {
	($(#[$attr:meta])* fn $module:ident($protocol:ident)) => (
		$(#[$attr])*
		pub fn $module(mut self) -> Result<crate::$module::Builder<B>> {
			if self.payload {
				return Err(ErrorKind::AlreadyDefined.into());
			}

			self = self.next_header(Protocol::$protocol)?;
			self.prepare();

			let mut builder = crate::$module::Builder::with(self.buffer)?;
			builder.finalizer().extend(self.finalizer);

			Ok(builder)
		}
	)
}

impl<B: Buffer> Builder<B> {
	/// Hop Limit
	pub fn hop_limit(mut self, value: u8) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_hop_limit(value)?;
		Ok(self)
	}

	/// Source address.
	pub fn source(mut self, value: Ipv6Addr) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_source(value)?;
		Ok(self)
	}

	/// Destination address.
	pub fn destination(mut self, value: Ipv6Addr) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_destination(value)?;
		Ok(self)
	}

	/// Inner protocol.
	pub fn next_header(mut self, value: Protocol) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_next_header(value)?;
		Ok(self)
	}

	/// Payload for the packet.
	pub fn payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
		if self.payload {
			return Err(ErrorKind::AlreadyDefined.into());
		}
		
		self.payload = true;

		for byte in value {
			self.buffer.more(1)?;
			*self.buffer.data_mut().last_mut().unwrap() = *byte;
		}

		Ok(self)
	}

	fn prepare(&mut self) {
		let offset = self.buffer.offset();
		let length = self.buffer.length();

		self.finalizer.add(move |out| {
			// Set the version to 6
			out[offset] |= (6 << 4) as u8;

			// Calculate and write the payload length
			let length = out.len() - length;
			Cursor::new(&mut out[offset + 4 ..])
				.write_u16::<BigEndian>(length as u16)?;

			Ok(())
		});
	}

	protocol!(/// Build a UDP packet.
		fn udp(Udp));
}


#[cfg(test)]
mod test {
	use std::net::Ipv6Addr;
	use crate::builder::Builder;
	use crate::ip;

	#[test]
	fn udp6() {
		let packet = ip::v6::Builder::default()
			.hop_limit(64).unwrap()
			.source("2001:db8::1".parse().unwrap()).unwrap()
			.destination("2001:db8:1::1".parse().unwrap()).unwrap()
			.udp().unwrap()
				.source(1234).unwrap()
				.destination(5678).unwrap()
				.payload(b"test").unwrap()
				.build().unwrap();

		let packet = ip::v6::Packet::new(packet).unwrap();

		assert_eq!(packet.hop_limit(), 64);
		assert_eq!(packet.next_header(), ip::Protocol::Udp);
		assert_eq!(packet.payload_length(), 12);
		assert_eq!(packet.source(), "2001:db8::1".parse::<Ipv6Addr>().unwrap());
		assert_eq!(packet.destination(), "2001:db8:1::1".parse::<Ipv6Addr>().unwrap());
	}
}
