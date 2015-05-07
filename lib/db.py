import sqlite3 as sql
import sys

class dbCache (object):
    def __init__(self,dbcache):
        try:
            self.dbcache = dbcache
            self.con = sql.connect(self.dbcache)
        except sql.Error, e:
            print "dbOpenCache exception: %s " % e.args[0]
            sys.exit(1)
        self.con.close()

    def getNetIDFromVM(self,vstag,port_name):
        self.con = sql.connect(self.dbcache)
        self.cur = self.con.cursor()
        self.cur.execute("select vn.net_id from vn,vm,vs where " + \
                         "vm.net_id=vn.net_id and vm.vstag=vs.vstag " + \
                         "and vs.vstag = ? and vm.port_name = ?",
                         [vstag,port_name])
        self.con.commit()
        (net_id,) = self.cur.fetchone()
        self.con.close()
        return net_id

    def getDstVMFromIngressPort(self,vstag,port_name,ip_addr_dst):
        self.con = sql.connect(self.dbcache)
        self.cur = self.con.cursor()
        self.cur.execute("select vn.net_id from vn,vm,vs where " + \
                         "vm.net_id=vn.net_id and vm.vstag=vs.vstag " + \
                         "and vs.vstag = ? and vm.port_name = ?",
                         [vstag,port_name])
        self.con.commit()
        (net_id,) = self.cur.fetchone()
        self.cur.execute("select vs.vstag,vm.hotom_addr,vm.port_name from " + \
                         "vn,vm,vs where " + \
                         "vm.net_id=vn.net_id and vm.vstag=vs.vstag " + \
                         "and vn.net_id = ? and vm.ip_addr = ?",
                         [net_id, ip_addr_dst])
        self.con.commit()
        (vstag,hw_addr,port_name) = self.cur.fetchone()
        self.con.close()
        return (net_id,vstag,hw_addr,port_name)

