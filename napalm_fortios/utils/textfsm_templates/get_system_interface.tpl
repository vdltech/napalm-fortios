Value Name (.*?)
Value IP (\S+)
Value Netmask (\S+)
Value Status (up|down)
Value Type (\S+)

Start
 ^name: ${Name}\s+(mode: \S+\s*)?ip: ${IP} ${Netmask}\s+status: ${Status}.*type: ${Type} -> Record
