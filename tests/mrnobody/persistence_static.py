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
    @unittest.skipUnless(os.name == 'nt', 'PowerShell fixture with in-process fake task/service providers')
    def test_windows_create_rerun_cleanup_and_ownership_with_fake_providers(self):
        # These functions shadow every task/service operation. Only owned files
        # below the isolated temporary ProgramData directory can be modified.
        providers = r'''
$ErrorActionPreference = 'Stop'
$script:task = $null
$script:service = $null
function Get-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction) if($TaskPath -ne '\'){throw 'wrong_task_path'}; $script:task }
function New-ScheduledTaskAction { param($Execute,$Argument) @{Execute=$Execute;Argument=$Argument} }
function New-ScheduledTaskTrigger { param([switch]$Daily,$At) @{At=$At} }
function Register-ScheduledTask { param($TaskName,$TaskPath,$Description,$Action,$Trigger,[switch]$Force) if($TaskPath -ne '\'){throw 'wrong_task_path'}; $script:task = [pscustomobject]@{Description=$Description} }
function Unregister-ScheduledTask { param($TaskName,$TaskPath,$Confirm) if($TaskPath -ne '\'){throw 'wrong_task_path'}; $script:task=$null }
function Get-CimInstance { param($ClassName,$Filter) $script:service }
function Add-Type { param($TypeDefinition,$ReferencedAssemblies,$OutputAssembly,$OutputType) [IO.File]::WriteAllBytes($OutputAssembly,[byte[]]@(1,2,3)) }
function New-Service { param($Name,$BinaryPathName,$DisplayName,$Description,$StartupType) $script:service=[pscustomobject]@{Description=$Description;PathName=$BinaryPathName;State='Stopped';Status='Stopped'} }
function Start-Service { param($Name) $script:service.State='Running';$script:service.Status='Running' }
function Stop-Service { param($Name,$ErrorAction) $script:service.State='Stopped';$script:service.Status='Stopped' }
function Get-Service { param($Name) $script:service }
function Invoke-CimMethod { param($InputObject,$MethodName) if($MethodName -ne 'Delete'){throw 'wrong_method'}; $script:service=$null; [pscustomobject]@{ReturnValue=0} }
'''
        for method in ('scheduled-task', 'service'):
            create = script({'MRNOBODY_METHOD': method}, 'windows')
            cleanup = script({'MRNOBODY_METHOD': method, 'MRNOBODY_ACTION': 'cleanup'}, 'windows')
            member = 'task' if method == 'scheduled-task' else 'service'
            fixture = providers
            fixture += '\n& {\n' + create + '\n}\n'
            fixture += f"if ($null -eq $script:{member}) {{ throw 'missing_artifact' }}\n"
            fixture += '\n& {\n' + create + '\n}\n'
            fixture += f"$script:{member}.Description = 'unrelated artifact'\n"
            fixture += "$blocked=$false; try { & {\n" + cleanup + "\n} } catch { $blocked=$true }; if(-not $blocked){throw 'ownership_not_enforced'}\n"
            fixture += f"$script:{member}.Description = 'MrNobody controlled lab P11'\n"
            fixture += '\n& {\n' + cleanup + '\n}\n& {\n' + cleanup + '\n}\n'
            fixture += f"if ($null -ne $script:{member}) {{ throw 'artifact_not_removed' }}\n"
            with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
                result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                                         '& ([scriptblock]::Create([Console]::In.ReadToEnd()))'],
                                        input=fixture, env=dict(os.environ, ProgramData=tmp), capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(list(Path(tmp).rglob('owner.txt')))

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
