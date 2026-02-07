// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Noise Protocol Transport               ║
// ║         End-to-end encrypted P2P communication                   ║
// ╚══════════════════════════════════════════════════════════════════╝

use snow::{Builder, TransportState};
use std::io::{self, Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Noise protocol pattern (XX for mutual authentication)
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum message size
const MAX_MSG_SIZE: usize = 65535;

/// A Noise-encrypted transport channel
pub struct NoiseTransport {
    transport: TransportState,
}

impl NoiseTransport {
    /// Initiate a connection to a peer (client/initiator role)
    pub async fn connect(
        addr: &str,
        local_key: &[u8],
    ) -> Result<(Self, TcpStream), Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(addr).await?;

        let builder = Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(local_key);

        let mut handshake = builder.build_initiator()?;
        let mut buf = vec![0u8; MAX_MSG_SIZE];

        // -> e
        let len = handshake.write_message(&[], &mut buf)?;
        send_frame(&stream, &buf[..len]).await?;

        // <- e, ee, s, es
        let msg = recv_frame(&stream).await?;
        handshake.read_message(&msg, &mut buf)?;

        // -> s, se
        let len = handshake.write_message(&[], &mut buf)?;
        send_frame(&stream, &buf[..len]).await?;

        let transport = handshake.into_transport_mode()?;

        Ok((Self { transport }, stream))
    }

    /// Listen for a connection (server/responder role)
    pub async fn listen(
        addr: &str,
        local_key: &[u8],
    ) -> Result<(Self, TcpStream), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(addr).await?;
        let (stream, _peer_addr) = listener.accept().await?;

        let builder = Builder::new(NOISE_PATTERN.parse()?)
            .local_private_key(local_key);

        let mut handshake = builder.build_responder()?;
        let mut buf = vec![0u8; MAX_MSG_SIZE];

        // <- e
        let msg = recv_frame(&stream).await?;
        handshake.read_message(&msg, &mut buf)?;

        // -> e, ee, s, es
        let len = handshake.write_message(&[], &mut buf)?;
        send_frame(&stream, &buf[..len]).await?;

        // <- s, se
        let msg = recv_frame(&stream).await?;
        handshake.read_message(&msg, &mut buf)?;

        let transport = handshake.into_transport_mode()?;

        Ok((Self { transport }, stream))
    }

    /// Send an encrypted message
    pub async fn send(
        &mut self,
        stream: &TcpStream,
        plaintext: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = vec![0u8; plaintext.len() + 16]; // + Poly1305 tag
        let len = self.transport.write_message(plaintext, &mut buf)?;
        send_frame(stream, &buf[..len]).await?;
        Ok(())
    }

    /// Receive and decrypt a message
    pub async fn recv(
        &mut self,
        stream: &TcpStream,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let ciphertext = recv_frame(stream).await?;
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self.transport.read_message(&ciphertext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Get the remote peer's static public key (if available)
    pub fn remote_public_key(&self) -> Option<Vec<u8>> {
        self.transport
            .get_remote_static()
            .map(|k| k.to_vec())
    }
}

/// Send a length-prefixed frame
async fn send_frame(
    stream: &TcpStream,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let len = (data.len() as u32).to_be_bytes();
    stream.writable().await?;

    // Write length prefix + data
    let mut frame = Vec::with_capacity(4 + data.len());
    frame.extend_from_slice(&len);
    frame.extend_from_slice(data);

    let mut written = 0;
    while written < frame.len() {
        stream.writable().await?;
        match stream.try_write(&frame[written..]) {
            Ok(n) => written += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

/// Receive a length-prefixed frame
async fn recv_frame(
    stream: &TcpStream,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    let mut read = 0;
    while read < 4 {
        stream.readable().await?;
        match stream.try_read(&mut len_buf[read..]) {
            Ok(0) => return Err("Connection closed".into()),
            Ok(n) => read += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_SIZE {
        return Err("Message too large".into());
    }

    // Read data
    let mut data = vec![0u8; len];
    let mut read = 0;
    while read < len {
        stream.readable().await?;
        match stream.try_read(&mut data[read..]) {
            Ok(0) => return Err("Connection closed".into()),
            Ok(n) => read += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(data)
}

/// Generate a new Noise keypair
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
    let keypair = builder.generate_keypair().unwrap();
    (keypair.private, keypair.public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (private, public) = generate_keypair();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
    }
}
