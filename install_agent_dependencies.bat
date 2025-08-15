@echo off
echo Installing Cisco AI Agent dependencies...
echo.
echo Installing required packages...
py -m pip install pyasn1==0.4.8
py -m pip install pysnmp==4.4.12
py -m pip install paramiko==3.5.1
py -m pip install requests==2.32.3
py -m pip install websocket-client==1.0.0
py -m pip install psutil==5.8.0
echo.
echo Installation complete!
echo You can now run: python cisco_ai_agent.py
pause 