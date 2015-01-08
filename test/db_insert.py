from pox.lib.addresses import *
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from HotOMCompDB import HotOMVM

engine = create_engine('sqlite:///dc.db')
DBSession = sessionmaker(bind=engine)
session = DBSession()

vm = HotOMVM(ip_addr="192.168.1.1",hw_addr="aa:bb:cc:00:00:01")
#vm.ip_addr = IPAddr("192.168.1.1")
#vm.hw_addr = EthAddr("aa:bb:cc:00:00:01")

session.add(vm)
session.commit()
