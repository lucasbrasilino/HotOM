from pox.lib.addresses import *
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from HotOMCompDB import HotOMVM

engine = create_engine('sqlite:///dc.db')
DBSession = sessionmaker(bind=engine)
session = DBSession()

vm = HotOMVM(net_id=0xaabbcc, ip_addr="192.168.1.1",hw_addr="aa:bb:cc:00:00:01")
print vm
session.add(vm)

vm = HotOMVM()
vm.ip_addr = IPAddr("192.168.1.2")
vm.hw_addr = EthAddr("aa:bb:cc:00:00:02")


session.add(vm)
session.commit()
