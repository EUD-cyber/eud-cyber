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
$script:compilations = 0
function Set-Acl { param($LiteralPath,$AclObject) if (-not $AclObject.AreAccessRulesProtected) { throw 'unprotected_acl' } }
function Get-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction) if($TaskPath -ne '\'){throw 'wrong_task_path'}; $script:task }
function New-ScheduledTaskAction { param($Execute,$Argument) @{Execute=$Execute;Arguments=$Argument} }
function New-ScheduledTaskTrigger { param([switch]$Daily,[switch]$Once,$At,$RepetitionInterval,$RepetitionDuration) @{At=$At;RepetitionInterval=$RepetitionInterval} }
function Stop-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction) }
function Register-ScheduledTask { param($TaskName,$TaskPath,$Description,$Action,$Trigger,$User,$RunLevel,[switch]$Force) if($TaskPath -ne '\'){throw 'wrong_task_path'}; $script:task = [pscustomobject]@{Description=$Description;Actions=$Action;Triggers=$Trigger} }
function Unregister-ScheduledTask { param($TaskName,$TaskPath,$Confirm) if($TaskPath -ne '\'){throw 'wrong_task_path'}; $script:task=$null }
function Get-CimInstance { param($ClassName,$Filter) $script:service }
function Add-Type { param($TypeDefinition,$ReferencedAssemblies,$OutputAssembly,$OutputType) $script:compilations++; [IO.File]::WriteAllBytes($OutputAssembly,[byte[]]@(1,2,3)) }
function New-Service { param($Name,$BinaryPathName,$DisplayName,$Description,$StartupType) $script:service=[pscustomobject]@{Description=$Description;PathName=$BinaryPathName;State='Stopped';Status='Stopped'} }
function Start-Service { param($Name) $script:service.State='Running';$script:service.Status='Running'; $dir=Join-Path $env:ProgramData ('MrNobody\P11\'+$Name); if(Test-Path (Join-Path $dir 'config.txt')){[IO.File]::WriteAllText((Join-Path $dir 'status.txt'),'0,0,0,-1')} }
function Stop-Service { param($Name,$ErrorAction) $script:service.State='Stopped';$script:service.Status='Stopped' }
function Get-Service { param($Name) $script:service }
function Invoke-CimMethod { param($InputObject,$MethodName) if($MethodName -ne 'Delete'){throw 'wrong_method'}; $script:service=$null; [pscustomobject]@{ReturnValue=0} }
'''
        for method in ('scheduled-task', 'service', 'task-service'):
            create = script({'MRNOBODY_METHOD': method}, 'windows')
            cleanup = script({'MRNOBODY_METHOD': method, 'MRNOBODY_ACTION': 'cleanup'}, 'windows')
            member = 'task' if method == 'scheduled-task' else 'service'
            fixture = providers
            fixture += "$dir=Join-Path $env:ProgramData 'MrNobody\\P11\\mrnobody-p11-telemetry'; $exe=Join-Path $dir 'mrnobody-p11-telemetry.exe'; $owner=Join-Path $dir 'owner.txt'; $config=Join-Path $dir 'config.txt'\n"
            fixture += '\n& {\n' + create + '\n}\n'
            if method != 'scheduled-task':
                fixture += "if ($script:compilations -ne 1) { throw 'rerun_recompiled_live_service' }\n"
                # Unknown files and altered binary paths must block BOTH create
                # and cleanup before stopping or overwriting owned artifacts.
                fixture += "$foreign=Join-Path $dir 'unrelated.txt'; [IO.File]::WriteAllText($foreign,'keep')\n"
                for source in (create, cleanup):
                    fixture += "$blocked=$false; try { & {\n" + source + "\n} } catch { $blocked=$_.Exception.Message -eq 'artifact_ownership_conflict' }; if(-not $blocked){throw 'foreign_file_not_protected'}\n"
                fixture += "if(-not $script:service -or [IO.File]::ReadAllText($foreign) -ne 'keep'){throw 'conflict_mutated_state'}; Remove-Item -LiteralPath $foreign\n"
                fixture += "$savedPath=$script:service.PathName; $script:service.PathName='unrelated.exe'\n"
                fixture += "$blocked=$false; try { & {\n" + cleanup + "\n} } catch { $blocked=$_.Exception.Message -eq 'artifact_ownership_conflict' }; if(-not $blocked){throw 'binary_path_not_protected'}\n"
                fixture += "$script:service.PathName=$savedPath\n"
            if method == 'task-service':
                fixture += "$before=[IO.File]::ReadAllText($config)\n"
                # Expired activity must not receive a fresh deadline on retry.
                fixture += "[IO.File]::WriteAllLines($config,[string[]]@($before.Split([char]10)[0].TrimEnd([char]13),'0'))\n"
                fixture += "$blocked=$false; try { & {\n" + create + "\n} } catch { $blocked=$_.Exception.Message -eq 'exercise_expired_cleanup_before_recreate' }; if(-not $blocked){throw 'expired_retry_renewed_activity'}\n"
                fixture += "[IO.File]::WriteAllText($config,$before)\n"
            fixture += f"if ($null -eq $script:{member}) {{ throw 'missing_artifact' }}\n"
            fixture += '\n& {\n' + create + '\n}\n'
            fixture += f"$script:{member}.Description = 'unrelated artifact'\n"
            fixture += "$blocked=$false; try { & {\n" + cleanup + "\n} } catch { $blocked=$true }; if(-not $blocked){throw 'ownership_not_enforced'}\n"
            fixture += f"$script:{member}.Description = 'MrNobody controlled lab P11'\n"
            fixture += '\n& {\n' + cleanup + '\n}\n& {\n' + cleanup + '\n}\n'
            fixture += f"if ($null -ne $script:{member}) {{ throw 'artifact_not_removed' }}\n"
            if method != 'scheduled-task':
                # Recover an owned orphan from an interrupted compile. There is
                # no registered service/task; this must rebuild, never run junk.
                fixture += "New-Item -ItemType Directory -Path $dir -Force|Out-Null; [IO.File]::WriteAllText($owner,'MrNobody controlled lab P11'); [IO.File]::WriteAllText($exe,'incomplete')\n"
                fixture += '\n& {\n' + create + '\n}\n'
                fixture += "if($script:compilations -ne 2 -or [IO.File]::ReadAllBytes($exe).Length -ne 3){throw 'stale_binary_not_rebuilt'}\n"
                if method == 'task-service':
                    # Missing config is uncertain: create must not renew the
                    # deadline, but same-method cleanup must still recover it.
                    fixture += "Remove-Item -LiteralPath $config\n"
                    fixture += "$blocked=$false; try { & {\n" + create + "\n} } catch { $blocked=$_.Exception.Message -eq 'legacy_service_cleanup_before_paired_create' }; if(-not $blocked){throw 'missing_config_recreated'}\n"
                fixture += '\n& {\n' + cleanup + '\n}\n'
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
        source = script({'MRNOBODY_METHOD': 'task-service', 'MRNOBODY_PERSISTENCE_DNS': 'enabled', 'MRNOBODY_PERSISTENCE_RESOLVER': '192.168.1.53'}, 'windows')
        code = re.search(r"\$source = @'\n(.*?)\n'@", source, re.S)[1]
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            output = Path(tmp) / 'mrnobody-p11-telemetry.exe'
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                                     "$ErrorActionPreference='Stop'; Add-Type -TypeDefinition ([Console]::In.ReadToEnd()) -ReferencedAssemblies 'System.ServiceProcess.dll' -OutputAssembly $env:MRN_COMPILE_OUTPUT -OutputType ConsoleApplication"],
                                    env=dict(os.environ, MRN_COMPILE_OUTPUT=str(output)), input=code,
                                    text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(output.is_file())
            # Execute only the expired maintenance branch: it must return before
            # ServiceController, SCM registration or any DNS socket is touched.
            (Path(tmp) / 'config.txt').write_text('enabled|evilcorp.test|192.168.1.53|60|3600\n0\n')
            expired = subprocess.run([str(output), '--maintain'], capture_output=True, timeout=10)
            self.assertEqual(expired.returncode, 0)
            self.assertFalse((Path(tmp) / 'status.txt').exists())
            invalid = subprocess.run([str(output), '--unknown'], capture_output=True, timeout=10)
            self.assertNotEqual(invalid.returncode, 0)


if __name__ == '__main__':
    unittest.main()
