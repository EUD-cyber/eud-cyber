"""Parse fixed P11 scripts and compile the Windows service without installing it."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'TESTFILES/ATTACKER-V2/web'))
from persistence_actions import METHODS, script


class StaticChecks(unittest.TestCase):
    def test_generated_scripts_parse(self):
        for method, (platform, _, _) in METHODS.items():
            for action in ('create', 'cleanup'):
                source = script({'MRNOBODY_METHOD': method, 'MRNOBODY_ACTION': action}, platform)
                if platform == 'linux':
                    if os.name == 'nt': continue
                    argv = ['bash', '-n']
                else:
                    shell = shutil.which('pwsh') or shutil.which('powershell')
                    if not shell: continue
                    argv = [shell, '-NoProfile', '-NonInteractive', '-Command',
                            '$s=[Console]::In.ReadToEnd(); $t=$null; $e=$null; [System.Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e)|Out-Null; if($e.Count){$e|ForEach-Object {$_.Message};exit 1}']
                result = subprocess.run(argv, input=source, text=True, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(os.name == 'nt', 'Compile against Windows PowerShell .NET Framework')
    def test_service_binary_compiles_without_installing_or_executing(self):
        source = script({'MRNOBODY_METHOD': 'service'}, 'windows')
        code = re.search(r"\$source = @'\n(.*?)\n'@", source, re.S)[1]
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            output = Path(tmp) / 'mrnobody-p11-telemetry.exe'
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                                     "$ErrorActionPreference='Stop'; Add-Type -TypeDefinition ([Console]::In.ReadToEnd()) -ReferencedAssemblies 'System.ServiceProcess.dll' -OutputAssembly $env:MRN_COMPILE_OUTPUT -OutputType ConsoleApplication"],
                                    env=dict(os.environ, MRN_COMPILE_OUTPUT=str(output)), input=code,
                                    text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(output.is_file())


if __name__ == '__main__':
    unittest.main()
