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
use std::net::Ipv6Addr;
use byteorder::{ReadBytesExt, BigEndian};

use crate::error::*;
use crate::ip::Protocol;
use crate::packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};

/// IPv6 packet parser.
#[derive(Clone)]
pub struct Packet<B> {
	buffer: B,
}

sized!(Packet,
	header {
		min:  40,
		max:  40,
		size: p => p.header_length(),
	}

	payload {
		min:  0,
		max:  u16::max_value() as usize,
		size: p => p.payload_length() as usize,
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("ip::v6::Packet")
			.field("version", &self.version())
			.field("payload_length", &self.payload_length())
			.field("next_header", &self.next_header())
			.field("hop_limit", &self.hop_limit())
			.field("source", &self.source())
			.field("destination", &self.destination())
			.field("payload", &self.payload())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Create an IPv6 packet without checking the buffer.
	pub fn unchecked(buffer: B) -> Packet<B> {
		Packet { buffer }
	}

	/// Parse an IPv6 packet without checking the payload.
	pub fn no_payload(buffer: B) -> Result<Packet<B>> {
		use crate::size::header::Min;

		let packet = Packet::unchecked(buffer);

		if packet.buffer.as_ref().len() < Self::min() {
			return Err(ErrorKind::SmallBuffer.into());
		}

		if packet.buffer.as_ref()[0] >> 4 != 6 {
			return Err(ErrorKind::InvalidPacket.into());
		}

		Ok(packet)
	}

	/// Parse an IPv6 packet, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		let packet = Packet::no_payload(buffer)?;

		if packet.buffer.as_ref().len() < packet.length() as usize {
			return Err(ErrorKind::SmallBuffer.into());
		}

		Ok(packet)
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Convert the packet to its owned version.
	///
	/// # Notes
	///
	/// It would be nice if `ToOwned` could be implemented, but `Packet` already
	/// implements `Clone` and the impl would conflict.
	pub fn to_owned(&self) -> Packet<Vec<u8>> {
		Packet::unchecked(self.buffer.as_ref().to_vec())
	}
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
	fn as_ref(&self) -> &[u8] {
		use crate::size::Size;

		&self.buffer.as_ref()[.. self.size()]
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Packet<B> {
	fn as_mut(&mut self) -> &mut [u8] {
		use crate::size::Size;

		let size = self.size();
		&mut self.buffer.as_mut()[.. size]
	}
}

impl<'a, B: AsRef<[u8]>> AsPacket<'a, Packet<&'a [u8]>> for B {
	fn as_packet(&self) -> Result<Packet<&[u8]>> {
		Packet::new(self.as_ref())
	}
}

impl<'a, B: AsRef<[u8]> + AsMut<[u8]>> AsPacketMut<'a, Packet<&'a mut [u8]>> for B {
	fn as_packet_mut(&mut self) -> Result<Packet<&mut [u8]>> {
		Packet::new(self.as_mut())
	}
}

impl<B: AsRef<[u8]>> P for Packet<B> {
	fn split(&self) -> (&[u8], &[u8]) {
		use crate::size::payload::Size;

		let header  = self.header_length();
		let payload = self.size();

		let buffer = self.buffer.as_ref();
		let buffer = if buffer.len() < header + payload {
			buffer
		}
		else {
			&buffer[.. header + payload]
		};

		buffer.split_at(header)
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
	fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
		use crate::size::payload::Size;

		let header  = self.header_length();
		let payload = self.size();

		let buffer = self.buffer.as_mut();
		let buffer = if buffer.len() < header + payload {
			buffer
		}
		else {
			&mut buffer[.. header + payload]
		};

		buffer.split_at_mut(header)
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Total length of the packet in octets.
	pub fn length(&self) -> usize {
		self.header_length() + self.payload_length() as usize
	}

	/// Total length of the header in octets, will always be 40.
	pub fn header_length(&self) -> usize {
		40
	}

	/// IP protocol version, will always be 6.
	pub fn version(&self) -> u8 {
		self.buffer.as_ref()[0] >> 4
	}

	/// Total length of the payload in octets.
	pub fn payload_length(&self) -> u16 {
		(&self.buffer.as_ref()[4 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// Hop Limit
	pub fn hop_limit(&self) -> u8 {
		self.buffer.as_ref()[7]
	}

	/// Source address.
	pub fn source(&self) -> Ipv6Addr {
		Ipv6Addr::new(
			(&self.buffer.as_ref()[8 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[10 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[12 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[14 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[16 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[18 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[20 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[22 ..]).read_u16::<BigEndian>().unwrap())
	}

	/// Destination address.
	pub fn destination(&self) -> Ipv6Addr {
		Ipv6Addr::new(
			(&self.buffer.as_ref()[24 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[26 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[28 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[30 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[32 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[34 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[36 ..]).read_u16::<BigEndian>().unwrap(),
			(&self.buffer.as_ref()[38 ..]).read_u16::<BigEndian>().unwrap())
	}

	/// Inner protocol.
	pub fn next_header(&self) -> Protocol {
		self.buffer.as_ref()[6].into()
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {
	/// Hop Limit
	pub fn set_hop_limit(&mut  self, value: u8) -> Result<&mut Self> {
		self.buffer.as_mut()[7] = value;
		Ok(self)
	}

	/// Source address.
	pub fn set_source(&mut  self, value: Ipv6Addr) -> Result<&mut Self> {
		self.header_mut()[8 .. 24].copy_from_slice(&value.octets());
		Ok(self)
	}

	/// Destination address.
	pub fn set_destination(&mut  self, value: Ipv6Addr) -> Result<&mut Self> {
		self.header_mut()[24 .. 40].copy_from_slice(&value.octets());
		Ok(self)
	}

	/// Inner protocol.
	pub fn set_next_header(&mut  self, value: Protocol) -> Result<&mut Self> {
		self.buffer.as_mut()[6] = value.into();
		Ok(self)
	}
}
