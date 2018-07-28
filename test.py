import time, calendar, subprocess

timeAtRequest = 1532804300

print(calendar.timegm(time.gmtime()))

timeDiff = calendar.timegm(time.gmtime()) - timeAtRequest

print(timeDiff)

subprocess.call("powershell Get-NetAdapter")

subprocess.call("powershell Disable-NetAdapter -Name \"Wi-Fi\" -Confirm:$false") 
