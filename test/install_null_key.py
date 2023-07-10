import kore
import socket

class Negotiate:
    def configure(self, args):
        kore.config.workers = 1
        kore.config.deployment = "dev"

        kore.task_create(self.negotiate())

    async def negotiate(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.setblocking(False)

        sock = kore.socket_wrap(s)

        await sock.sendto("/tmp/signsky.key", b"\x00" * 32)
        kore.shutdown()

koreapp = Negotiate()
