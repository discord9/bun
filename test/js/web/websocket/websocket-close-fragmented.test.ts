import { TCPSocketListener } from "bun";
import { describe, expect, test } from "bun:test";

const hostname = "127.0.0.1";
const port = 0;
const MAX_HEADER_SIZE = 16 * 1024; // 16KB max for handshake headers

describe("WebSocket", () => {
  test("fragmented close frame", async () => {
    let server: TCPSocketListener | undefined;
    let client: WebSocket | undefined;
    let handshakeBuffer = new Uint8Array(0);
    let handshakeComplete = false;

    try {
      server = Bun.listen({
        socket: {
          data(socket, data) {
            if (handshakeComplete) {
              // Client's close response - end the connection
              socket.end();
              return;
            }

            // Accumulate handshake data
            const newBuffer = new Uint8Array(handshakeBuffer.length + data.length);
            newBuffer.set(handshakeBuffer);
            newBuffer.set(data, handshakeBuffer.length);
            handshakeBuffer = newBuffer;

            // Prevent unbounded growth
            if (handshakeBuffer.length > MAX_HEADER_SIZE) {
              socket.end();
              throw new Error("Handshake headers too large");
            }

            // Check for end of HTTP headers
            const dataStr = new TextDecoder("utf-8").decode(handshakeBuffer);
            const endOfHeaders = dataStr.indexOf("\r\n\r\n");
            if (endOfHeaders === -1) {
              // Need more data
              return;
            }

            if (!dataStr.startsWith("GET")) {
              throw new Error("Invalid handshake");
            }

            const magic = /Sec-WebSocket-Key:\s*(.*)\r\n/i.exec(dataStr);
            if (!magic) {
              throw new Error("Missing Sec-WebSocket-Key");
            }

            const hasher = new Bun.CryptoHasher("sha1");
            hasher.update(magic[1].trim());
            hasher.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            const accept = hasher.digest("base64");

            // Respond with a websocket handshake
            socket.write(
              "HTTP/1.1 101 Switching Protocols\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                `Sec-WebSocket-Accept: ${accept}\r\n` +
                "\r\n",
            );
            socket.flush();

            handshakeComplete = true;

            // Send a close frame split across two writes to simulate TCP fragmentation.
            // Close frame: FIN=1, opcode=8 (close), payload = 2 byte code + 21 byte reason
            const closeCode = 1000;
            const closeReason = "fragmented close test";
            const reasonBytes = new TextEncoder().encode(closeReason);
            const payloadLength = 2 + reasonBytes.length; // 23 bytes total

            // Ensure payload fits in single-byte length field
            if (payloadLength >= 126) {
              throw new Error("Payload too large for this test");
            }

            // Part 1: Frame header (2 bytes) + close code (2 bytes) + first 10 bytes of reason = 14 bytes
            const part1 = new Uint8Array(2 + 2 + 10);
            part1[0] = 0x88; // FIN + Close opcode
            part1[1] = payloadLength; // Single-byte payload length
            part1[2] = (closeCode >> 8) & 0xff;
            part1[3] = closeCode & 0xff;
            part1.set(reasonBytes.slice(0, 10), 4);

            socket.write(part1);
            socket.flush();

            // Part 2: Remaining 11 bytes of the close reason
            setTimeout(() => {
              socket.write(reasonBytes.slice(10));
              socket.flush();
            }, 10);
          },
        },
        hostname,
        port,
      });

      const { promise, resolve, reject } = Promise.withResolvers<void>();

      client = new WebSocket(`ws://${server.hostname}:${server.port}`);
      client.addEventListener("error", () => {
        reject(new Error("WebSocket error"));
      });
      client.addEventListener("close", event => {
        try {
          expect(event.code).toBe(1000);
          expect(event.reason).toBe("fragmented close test");
          resolve();
        } catch (err) {
          reject(err);
        }
      });

      await promise;
    } finally {
      client?.close();
      server?.stop(true);
    }
  });

  // Regression: the close() reason was transcoded into a fixed 128-byte
  // stack buffer and then pointer-cast to `&mut [u8; 125]` before being
  // passed on with `body_len = cursor.position()`. A UTF-16 reason of
  // 42 code units of U+0800 passes the C++ 123-char limit but transcodes
  // to 126 UTF-8 bytes — overrunning the 125-byte reference in the next
  // frame. Fix: cap the transcode buffer at 125 and bail to the no-reason
  // path on overflow. Expectation: calling close() with this reason does
  // not crash the process; the close handshake completes.
  test("close() with reason that transcodes beyond 125 UTF-8 bytes does not crash", async () => {
    let server: TCPSocketListener | undefined;
    let client: WebSocket | undefined;
    let handshakeBuffer = new Uint8Array(0);
    let handshakeComplete = false;
    let receivedCloseFrame = false;

    try {
      server = Bun.listen({
        socket: {
          data(socket, data) {
            if (handshakeComplete) {
              // First byte of a client frame: 0x88 = FIN | Close.
              if (!receivedCloseFrame && data.length > 0 && data[0] === 0x88) {
                receivedCloseFrame = true;
                // Echo a normal close frame back so the client completes its close handshake.
                // Server→client frames are NOT masked. Empty payload.
                socket.write(new Uint8Array([0x88, 0x00]));
                socket.flush();
                socket.end();
              }
              return;
            }

            const merged = new Uint8Array(handshakeBuffer.length + data.length);
            merged.set(handshakeBuffer);
            merged.set(data, handshakeBuffer.length);
            handshakeBuffer = merged;
            if (handshakeBuffer.length > MAX_HEADER_SIZE) {
              socket.end();
              throw new Error("Handshake headers too large");
            }
            const dataStr = new TextDecoder("utf-8").decode(handshakeBuffer);
            if (dataStr.indexOf("\r\n\r\n") === -1) return;
            const magic = /Sec-WebSocket-Key:\s*(.*)\r\n/i.exec(dataStr);
            if (!magic) throw new Error("Missing Sec-WebSocket-Key");
            const hasher = new Bun.CryptoHasher("sha1");
            hasher.update(magic[1].trim());
            hasher.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            const accept = hasher.digest("base64");
            socket.write(
              "HTTP/1.1 101 Switching Protocols\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                `Sec-WebSocket-Accept: ${accept}\r\n` +
                "\r\n",
            );
            socket.flush();
            handshakeComplete = true;
          },
        },
        hostname,
        port,
      });

      const { promise, resolve, reject } = Promise.withResolvers<CloseEvent>();

      client = new WebSocket(`ws://${server.hostname}:${server.port}`);
      client.addEventListener("error", () => {
        reject(new Error("WebSocket error"));
      });
      client.addEventListener("close", event => resolve(event));
      client.addEventListener("open", () => {
        // 42 code units × 3 UTF-8 bytes = 126 bytes — one byte past the
        // 125-byte close-frame payload cap. C++ spec check bounds on
        // UTF-16 code-unit count (42 < 123), so this reaches the native
        // close path.
        const reason = "\u0800".repeat(42);
        // Does not throw: length() === 42 ≤ 123.
        client!.close(1000, reason);
      });

      // Succeed if the client emits 'close' without the process crashing.
      // The exact code/reason depends on whether the server got to respond
      // before the client's close timer expired; the important assertion
      // is that we got here at all.
      const event = await promise;
      expect(typeof event.code).toBe("number");
    } finally {
      client?.close();
      server?.stop(true);
    }
  });
});
