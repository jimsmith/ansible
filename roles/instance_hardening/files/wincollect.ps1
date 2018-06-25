$batchFileContent = @"
wincollect-7.2.5-27.x64.exe /s /v"/qn INSTALLDIR=\"C:\Program Files\IBM\WinCollect\" HEARTBEAT_INTERVAL=6000 LOG_SOURCE_AUTO_CREATION_ENABLED=True LOG_SOURCE_AUTO_CREATION_PARAMETERS=""Component1.AgentDevice=DeviceWindowsLog&Component1.Action=create&Component1.LogSourceName=%COMPUTERNAME%&Component1.LogSourceIdentifier=%COMPUTERNAME%&Component1.Dest.Name=10.79.208.11&Component1.Dest.Hostname=10.79.208.11&Component1.Dest.Port=514&Component1.Dest.Protocol=TCP&Component1.Log.Security=true&Component1.Log.System=true&Component1.Log.Application=true&Component1.Log.DNS+Server=true&Component1.Log.File+Replication+Service=true&Component1.Log.Directory+Service=true&Component1.RemoteMachinePollInterval=3000&Component1.EventRateTuningProfile=High+Event+Rate+Server&Component1.MinLogsToProcessPerPass=1250&Component1.MaxLogsToProcessPerPass=1875"""
"@
$batchFileContent | Out-File -FilePath:"C:\wincollect.cmd" -Encoding ASCII -Force
Start-Sleep -s 2
& C:\wincollect.cmd
Start-Sleep -s 10
iex C:\wincollect.cmd
Start-Sleep -s 10
#Remove-Item -LiteralPath:"C:\wincollect.cmd" -Force
