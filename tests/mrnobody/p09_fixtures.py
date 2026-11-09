"""Adapt existing P09 state fixtures to the real protocol command boundary."""
import base64
import gzip
import re
from unittest.mock import Mock


def decode_command(arguments):
    wrapper = base64.b64decode(arguments[-1]).decode('utf-16-le')
    payload = re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", wrapper).group(1)
    return gzip.decompress(base64.b64decode(payload)).decode('utf-8')


def p09_factory():
    factory = Mock()
    session = factory.return_value

    def command(shell, executable, arguments, **kwargs):
        assert executable == 'powershell.exe'
        assert kwargs == {'skip_cmd_shell': True}
        session.source = decode_command(arguments)
        return 'command'

    def output(*args):
        response = session.run_ps(session.source)
        return response.std_out, response.std_err, response.status_code

    session.protocol.run_command.side_effect = command
    session.protocol.get_command_output.side_effect = output
    return factory
