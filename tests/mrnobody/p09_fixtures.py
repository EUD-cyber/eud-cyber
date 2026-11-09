"""Adapt existing P09 state fixtures to the real protocol command boundary."""
import base64
import hashlib
from unittest.mock import Mock


def decode_input(frame):
    header, payload = frame.split(b'\n', 1)
    length, digest = header.split(b':')
    assert len(payload) == int(length)
    source = base64.b64decode(payload, validate=True)
    assert hashlib.sha256(source).hexdigest().encode() == digest
    return source.decode('utf-8')


def p09_factory():
    factory = Mock()
    session = factory.return_value

    def command(shell, executable, arguments, **kwargs):
        assert executable == 'powershell.exe'
        assert kwargs == {'console_mode_stdin': False, 'skip_cmd_shell': True}
        session.frame = b''
        session.ended = False
        return 'command'

    def send(shell, command_id, chunk, end=False):
        assert not session.ended
        session.frame += chunk
        session.ended = end
        if end:
            session.source = decode_input(session.frame)

    def output(*args):
        assert session.ended
        response = session.run_ps(session.source)
        return response.std_out, response.std_err, response.status_code

    session.protocol.run_command.side_effect = command
    session.protocol.send_command_input.side_effect = send
    session.protocol.get_command_output.side_effect = output
    return factory
