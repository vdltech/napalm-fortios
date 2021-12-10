Value Speed (\d+)
Value Enabled (up|down)
Value Status (up|down)
Value MAC (.*)

Start
 ^Current_HWaddr\s+${MAC}
 ^Admin\s+:${Enabled}
 ^netdev status\s+:${Status}
 ^Speed\s+:${Speed} -> Record
