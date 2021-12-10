Value Name (.*?)
Value IP (\S+)
Value Netmask (\S+)
Value Description (.*)
Value Alias (.*)
Value Vlan (\d+)

Start
 ^\s+edit "${Name}"
 ^\s+set ip ${IP} ${Netmask}
 ^\s+set alias "${Alias}"
 ^\s+set description "${Description}"
 ^\s+set vlanid ${Vlan}
 ^\s+next -> Record

