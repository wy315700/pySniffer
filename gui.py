#coding=utf-8  
__author__ = 'wangyang'
import wx
import pcap
import dpkt
import Queue
import binascii
import socket
import win_inet_pton
import string, threading, time
import sys, glob, random
import multiprocessing, pickle

def time2stamp(timestr, format_type='%Y-%m-%d %H:%M:%S'):
    return time.mktime(time.strptime(timestr, format_type))

def stamp2time(stamp, format_type='%Y-%m-%d %H:%M:%S'):
    return time.strftime(format_type, time.localtime(stamp))
# class ListBoxFrame(wx.Frame):
#     def __init__(self):
#         wx.Frame.__init__(self, None, -1, 'List Box Example', 
#                 size=(250, 200))
#         self.Centre()
        
#         self.panel = wx.Panel(self, -1)
#         vbox = wx.BoxSizer(wx.VERTICAL)

#         self.getAllDev()
#         self.drawListBox()
#         self.drawButton()
#         vbox.Add(self.listBox, 1, wx.EXPAND | wx.ALL | wx.ALIGN_TOP, 20)
#         vbox.Add(self.button,  0, wx.ALIGN_CENTER | wx.ALL ^wx.TOP | wx.ALIGN_BOTTOM, 20)
#         self.panel.SetSizer(vbox)

#     def getAllDev(self):
#         self.devlist = pcap.findalldevs()

#     def drawListBox(self):
#         self.listBox = wx.ListBox(self.panel, -1, (20, 20), (160, 120), self.devlist, 
#                 wx.LB_SINGLE)
#         self.listBox.SetSelection(3)

#     def drawButton(self):
#         self.button = wx.Button(self.panel, -1, u"选择", pos=(50, 20))
#         self.Bind(wx.EVT_BUTTON, self.OnClick, self.button)
#         self.button.SetDefault()

#     def OnClick(self, event):
#         dlg = wx.MessageDialog(None, u"您选择的网卡是："+ self.devlist[self.listBox.GetSelection()],
#                           'A Message Box',
#                           wx.YES_NO | wx.ICON_QUESTION)
#         retCode = dlg.ShowModal()
#         if (retCode == wx.ID_YES):
#             print "yes"
#         else:
#             print "no"


class DemoFrame(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, None, -1,
                          u"pySniffer powerd by 天外之音",
                          size=(1000,400))

        
        self.rootPanel = wx.Panel(self)
        self.drawList(self.rootPanel);
        self.tree = wx.TreeCtrl(self.rootPanel)
        self.drawTextCtrl(self.rootPanel)
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.Add(self.list, 1, wx.EXPAND | wx.ALL | wx.ALIGN_TOP, 20)
        vbox.Add(self.tree, 1, wx.EXPAND | wx.ALL ^wx.TOP | wx.ALIGN_TOP, 20)

        self.rootPanel.SetSizer(vbox)
        self.num = 0
    def drawTextCtrl(self,panel):
        pass
    def drawTreeCtrl(self,panel):
        root = self.tree.AddRoot(u"第xx个数据包")
        childId1 = self.tree.AppendItem(root, u"链路层数据")
        childId2 = self.tree.AppendItem(root, u"网络层数据")
        childId3 = self.tree.AppendItem(root, u"应用层数据")
        pass
    def drawList(self,panel): #创建主监视列表
        self.list = wx.ListCtrl(panel, -1, style=wx.LC_REPORT | wx.LC_HRULES)#创建列表

        columns = [u"编号", u"时间" ,u"源网卡地址", u"目的网卡地址", u"协议", u"源IP", u"目的IP", u"源端口", u"目的端口"]

        # Add some columns
        for col in range(len(columns)):#增加列
            self.list.InsertColumn(col,columns[col])
                
        # set the width of the columns in various ways
        self.list.SetColumnWidth(0, wx.LIST_AUTOSIZE_USEHEADER)#设置列的宽度
        self.list.SetColumnWidth(1, 140)
        self.list.SetColumnWidth(2, 120)
        self.list.SetColumnWidth(3, 120)
        self.list.SetColumnWidth(4, 40)
        self.list.SetColumnWidth(5, 100)
        self.list.SetColumnWidth(6, 100)
    def addItem(self, itemList):
        self.num += 1
        index = self.list.InsertStringItem(sys.maxint, `self.num`)
        for col in range(0,len(itemList)):
            self.list.SetStringItem(index, col + 1, itemList[col])

        self.list.ScrollList(0, index)

def eth_addr_to_str(mac_addr):
    mac_addr = binascii.hexlify(mac_addr)
    s = list()
    for i in range(12/2) :
        s.append( mac_addr[i*2:i*2+2] )
    r = ":".join(s)
    return r


def thread_print():
    global global_queue, mutex, isStop
    # 获得线程名
    threadname = threading.currentThread().getName()
    try:
        while not isStop:


            ptime,pdata = global_queue.get()

            if isStop == True:
                return

            # tem= dpkt.ethernet.Ethernet(pdata)
            tem = pdata #pdata不能被序列化 暂时在读取时处理

            global frame

            

            itemList = []

            itemList.append(stamp2time(ptime))

            itemList.append(eth_addr_to_str(tem.src))
            itemList.append(eth_addr_to_str(tem.dst))

            itemList.append(tem.data.__class__.__name__)
            if tem.data.__class__.__name__=='IP':
                itemList.append('%d.%d.%d.%d'%tuple(map(ord,list(tem.data.src)))) #source IP
                itemList.append('%d.%d.%d.%d'%tuple(map(ord,list(tem.data.dst)))) #dist IP
                try:
                    itemList[3] = tem.data.data.__class__.__name__;
                # if tem.data.data.__class__.__name__ == 'TCP' or tem.data.data.__class__.__name__ == 'UDP':
                    itemList.append(`tem.data.data.sport`)
                    itemList.append(`tem.data.data.dport`)
                except Exception,e:
                    print str(e)
            else:
                if tem.data.__class__.__name__=='IP6':
                    try:
                        itemList.append(socket.inet_ntop(socket.AF_INET6, tem.data.src)) #source IP
                        itemList.append(socket.inet_ntop(socket.AF_INET6, tem.data.dst)) #dist IP
                    except:
                        itemList.append(win_inet_pton.inet_ntop(socket.AF_INET6, tem.data.src)) #source IP
                        itemList.append(win_inet_pton.inet_ntop(socket.AF_INET6, tem.data.dst)) #dist IP
                try:
                    print tem.data.data.__class__.__name__
                except Exception,e:
                    print str(e)



            frame.addItem(itemList)

    except KeyboardInterrupt:
        return


def readFromPcap(global_queue):
    # global global_queue, mutex, isStop
    pc=pcap.pcap(immediate = True)
    # pc.setfilter()
    for ptime,pdata in pc:
        # if isStop:
        #     return
        tem= dpkt.ethernet.Ethernet(pdata)#pdata不能被序列化 暂时在读取时处理
        global_queue.put((ptime,tem))

        # print ptime
        # 释放锁
        # break
if __name__ == '__main__':

    isStop = False


    global_queue = multiprocessing.Queue(maxsize = 0)

    readThread = multiprocessing.Process(target=readFromPcap, args=(global_queue,))
    # readThread = threading.Thread(target=readFromPcap, args=())
    readThread.start()

    app = wx.PySimpleApp()
    frame = DemoFrame()
    frame.Show()

    printThread = threading.Thread(target=thread_print, args=())
    printThread.start()


    app.MainLoop()

    isStop = True

    print 'Exit!!'
    

    readThread.terminate()
    print 'TERMINATED:', readThread, readThread.is_alive()

    readThread.join()
    printThread.join()