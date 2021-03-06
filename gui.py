#coding=utf-8  
__author__ = 'wangyang'
import wx,wx.richtext
import pcap
import dpkt
import Queue
import binascii
import socket
import win_inet_pton
import string, threading, time
import sys, glob, random
import multiprocessing, pickle
import re
import struct

def time2stamp(timestr, format_type='%Y-%m-%d %H:%M:%S'):
    return time.mktime(time.strptime(timestr, format_type))

def stamp2time(stamp, format_type='%Y-%m-%d %H:%M:%S'):
    return time.strftime(format_type, time.localtime(stamp))

def hexPrint(data):
    if data < 16:
        return "0%X "%data
        pass
    else:
        return "%X "%data

def charPrint(data):
    length = len(data)

    data = re.sub("[\x00-\x1f|\x7f-\xff]",".",data)

    return data 


def openFrameForDevChoise():
    frame = ListBoxFrame()
    frame.Show()
    

def openFrameForSniffer(name = None , filter = None):
    global_queue = multiprocessing.Queue(maxsize = 0)
    readThread = multiprocessing.Process(target=readFromPcap, args=(global_queue,name, filter))
    readThread.start()
    frame = DemoFrame()
    frame.Show()
    printThread = threading.Thread(target=thread_print, args=(global_queue,frame))
    printThread.start()

class ListBoxFrame(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, None, -1, u'网卡选择', 
                size=(600, 300))
        self.Centre()
        
        self.panel = wx.Panel(self, -1)
        vbox = wx.BoxSizer(wx.VERTICAL)

        self.getAllDev()
        self.drawListBox()
        self.drawButton()
        self.drawStaticText()
        self.drawTextCtrl()
        vbox.Add(self.label, 0, wx.EXPAND | wx.ALL ^wx.BOTTOM | wx.ALIGN_TOP, 10)
        vbox.Add(self.listBox, 1, wx.EXPAND | wx.ALL | wx.ALIGN_TOP, 10)
        vbox.Add(self.textCtrl,0, wx.EXPAND | wx.ALL | wx.ALIGN_TOP, 10)
        vbox.Add(self.button,  0, wx.ALIGN_CENTER | wx.ALL ^wx.TOP | wx.ALIGN_BOTTOM, 10)
        self.panel.SetSizer(vbox)

    def getAllDev(self):
        self.devlist = [] #用于显示
        self.devnamelist = [] #由于网卡数据

        maxlength = 0;
        for dev in pcap.findalldevs():
            length = len(dev.description)
            maxlength = maxlength if maxlength > length else length
        for dev in pcap.findalldevs():
            devname = dev.description
            self.devnamelist.append(dev.name)
            devname += ' '*(maxlength - len(devname))
            devname += dev.name
            self.devlist.append(devname)

    def drawStaticText(self):
        self.label = wx.StaticText(self.panel, -1, u"请选择网卡", 
                (100, 10))

    def drawListBox(self):
        self.listBox = wx.ListBox(self.panel, -1, (20, 20), (160, 120), self.devlist, 
                wx.LB_SINGLE)
        self.listBox.SetSelection(3)
        self.listBox.Bind(wx.EVT_LISTBOX_DCLICK,self.OnClick)
    def drawTextCtrl(self):
        self.textCtrl = wx.richtext.RichTextCtrl(self.panel, -1, "" ,size=(-1, 40))
        self.textCtrl.SetHint(u"请输入过滤条件")
        self.isTextCtrlEmpty = True
        self.textCtrl.Bind(wx.EVT_LEFT_DOWN, self.OnType)
    def drawButton(self):
        self.button = wx.Button(self.panel, -1, u"选择", pos=(50, 20))
        self.Bind(wx.EVT_BUTTON, self.OnClick, self.button)
        self.button.SetDefault()
    def OnType(self, evt):
        if self.isTextCtrlEmpty == True:
            self.isTextCtrlEmpty = False
            self.textCtrl.Clear()
    def OnClick(self, event):
        dlg = wx.MessageDialog(None, u"您选择的网卡是："+ self.devlist[self.listBox.GetSelection()],
                          'A Message Box',
                          wx.YES_NO | wx.ICON_QUESTION)
        retCode = dlg.ShowModal()
        if (retCode == wx.ID_YES):
            print "yes"
        else:
            print "no"
        value = None
        if self.isTextCtrlEmpty != True:
            value = self.textCtrl.GetValue()
        openFrameForSniffer(self.devnamelist[self.listBox.GetSelection()], value)
        self.Destroy()  

class VirtualListCtrl(wx.ListCtrl):#1 声明虚列表
    """
    A generic virtual listctrl that fetches data from a DataSource.
    """
    def __init__(self, parent, dataSource):
        wx.ListCtrl.__init__(self, parent,
            style=wx.LC_REPORT|wx.LC_SINGLE_SEL|wx.LC_VIRTUAL)#使用wx.LC_VIRTUAL标记创建虚列表
        self.dataSource = dataSource
        self.Bind(wx.EVT_LIST_CACHE_HINT, self.DoCacheItems)
        self.SetItemCount(len(dataSource) )#设置列表的大小
        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnItemSelected, self)

        columns = [u"编号", u"时间" ,u"源网卡地址", u"目的网卡地址", u"协议", u"源IP", u"目的IP", u"源端口", u"目的端口"]

        # Add some columns
        for col in range(len(columns)):#增加列
            self.InsertColumn(col,columns[col])
                
        # set the width of the columns in various ways
        self.SetColumnWidth(0, wx.LIST_AUTOSIZE_USEHEADER)#设置列的宽度
        self.SetColumnWidth(1, 140)
        self.SetColumnWidth(2, 120)
        self.SetColumnWidth(3, 120)
        self.SetColumnWidth(4, 60)
        self.SetColumnWidth(5, 100)
        self.SetColumnWidth(6, 100)
    
    def OnItemSelected(self, evt):
        item = evt.GetItem()
        print "Item selected:", item.GetText()
        self.getParentFrame().drawTreeCtrl(item.GetText())


    def getParentFrame(self):
        parent = self.GetParent()
        while not isinstance(parent , DemoFrame):
            parent = parent.GetParent()

        return parent

    def DoCacheItems(self, evt):
        # self.dataSource.UpdateCache(
        #     evt.GetCacheFrom(), evt.GetCacheTo())
        pass

    def OnGetItemText(self, item, col):#得到需求时的文本
        data = self.dataSource[item]
        try:
            return data[col]
        except:
            return ''

    def OnGetItemAttr(self, item):  return None
    def OnGetItemImage(self, item): return -1

    def refresh(self):
        length = len(self.dataSource)
        self.SetItemCount(length)#设置列表的大小
        self.ScrollList(0, length - 1)

class DemoFrame(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, None, -1,
                          u"pySniffer powerd by 天外之音",
                          size=(900,600))
        self.num = 0
        self.listData = []
        self.temList  = []
        
        self.rootPanel = wx.Panel(self)
        self.drawList(self.rootPanel);
        self.tree = wx.TreeCtrl(self.rootPanel , size = (-1,100))
        
        
        self.scroll = wx.ScrolledWindow(self.rootPanel, id=-1, pos=wx.DefaultPosition,
                        size=(-1, 100), style=wx.VSCROLL,
                            name="scrolledWindow")
        self.scroll.SetScrollRate(1, 1)
        self.scroll.SetVirtualSize((-1,4000) )
        self.scroll.SetAutoLayout(False)

        self.drawTextCtrl(self.scroll)

        vbox = wx.BoxSizer(wx.VERTICAL)

        self.drawButton(self.rootPanel)

        hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        hbox2.Add(self.button, 0, wx.EXPAND | wx.RIGHT | wx.ALIGN_LEFT, 10)

        vbox.Add(hbox2, 0, wx.EXPAND | wx.ALL | wx.ALIGN_TOP, 10)

        vbox.Add(self.list, 1, wx.EXPAND | wx.ALL | wx.ALIGN_TOP, 10)
        vbox.Add(self.tree, 0, wx.EXPAND | wx.ALL ^wx.TOP | wx.ALIGN_TOP, 10)

        hbox1 = wx.BoxSizer(wx.HORIZONTAL)

        hbox1.Add(self.textCtrlForRawData, 2, wx.EXPAND | wx.ALL ^wx.RIGHT | wx.ALIGN_LEFT, 0)

        hbox1.Add(self.textCtrlForCharData, 1, wx.EXPAND | wx.ALL ^wx.LEFT | wx.ALIGN_LEFT, 0)

        self.scroll.SetSizer(hbox1)
        
        vbox.Add(self.scroll, 0, wx.EXPAND | wx.ALL ^wx.TOP | wx.ALIGN_TOP, 10)
        self.rootPanel.SetSizer(vbox)
    
    def onSelect(self,evt):
        if evt.GetEventObject() == self.textCtrlForRawData:
            if evt.GetEventType() == wx.EVT_LEFT_DOWN.typeId:
                self.leftclicked = 1
                self.textCtrlForCharData.SetSelection(0,0)
                print 'clicked'
                evt.Skip()
            if evt.GetEventType() == wx.EVT_LEFT_UP.typeId:
                self.leftclicked = 0
                print 'unclicked'
            if evt.GetEventType() == wx.EVT_MOTION.typeId:
                if self.leftclicked == 1:
                    start,end = self.textCtrlForRawData.GetSelection()
                    nlinesbeforestart = start / 61
                    nlinesbeforeend   = end / 61
                    nlines = nlinesbeforeend - nlinesbeforestart #中间经过几个换行符
                    rsatrt = (start + 1 - nlinesbeforestart)/3 + nlinesbeforestart
                    rend = (end -1 - nlinesbeforeend)/ 3 + 1 + nlinesbeforeend
                    self.textCtrlForCharData.SetSelection(rsatrt,rend)
                evt.Skip()
        if evt.GetEventObject() == self.textCtrlForCharData:
            if evt.GetEventType() == wx.EVT_LEFT_DOWN.typeId:
                self.rightclicked = 1
                self.textCtrlForRawData.SetSelection(0,0)
                print 'clicked'
                evt.Skip()
            if evt.GetEventType() == wx.EVT_LEFT_UP.typeId:
                self.rightclicked = 0
                print 'unclicked'
            if evt.GetEventType() == wx.EVT_MOTION.typeId:
                if self.rightclicked == 1:
                    start,end = self.textCtrlForCharData.GetSelection()
                    
                    nlinesbeforestart = start / 21
                    nlinesbeforeend   = end / 21
                    nlines = nlinesbeforeend - nlinesbeforestart
                    rsatrt = ( start - nlinesbeforestart) * 3 + nlinesbeforestart
                    rend = (end - nlinesbeforeend) * 3 - 1 + nlinesbeforeend
                    self.textCtrlForRawData.SetSelection(rsatrt,rend)
                evt.Skip()
    def OnClick(self,evt):
        if evt.GetEventObject() == self.button:
            if evt.GetEventType() == wx.EVT_BUTTON.typeId:
                if self.isPause == False:
                    self.button.SetLabel("start")
                    self.isPause = True
                else:
                    self.button.SetLabel("pause")
                    self.isPause = False
        pass
    def drawButton(self,panel):
        self.button = wx.Button(panel, -1, "pause")
        self.Bind(wx.EVT_BUTTON, self.OnClick, self.button)
        self.isPause = False
    def drawTextCtrl(self,panel):
        self.textCtrlForRawData = wx.richtext.RichTextCtrl(panel, -1, "I've entered some text!",size=(-1, 100),style =  wx.TE_READONLY | wx.TE_MULTILINE)
        self.textCtrlForCharData = wx.richtext.RichTextCtrl(panel, -1, "I've entered some text else!",size=(-1, 100),style = wx.TE_READONLY | wx.TE_MULTILINE)
        self.textCtrlForRawData.Bind(wx.EVT_LEFT_DOWN,self.onSelect)
        self.textCtrlForRawData.Bind(wx.EVT_LEFT_UP,self.onSelect)
        self.textCtrlForRawData.Bind(wx.EVT_MOTION,self.onSelect)

        self.textCtrlForCharData.Bind(wx.EVT_LEFT_DOWN,self.onSelect)
        self.textCtrlForCharData.Bind(wx.EVT_LEFT_UP,self.onSelect)
        self.textCtrlForCharData.Bind(wx.EVT_MOTION,self.onSelect)

        self.leftclicked = 0
        self.rightclicked = 0

        # font = self.textCtrlForRawData.GetFont()
        # print font.GetFaceName()
        font1 = wx.Font(9, wx.MODERN, wx.NORMAL, wx.NORMAL, False, u'Consolas')
        self.textCtrlForRawData.SetFont(font1) #使用等宽字体
        self.textCtrlForCharData.SetFont(font1) #使用等宽字体

    
    def writeCharData(self,data):
        self.textCtrlForCharData.Clear()
        length = len(data)
        current = 0 
        colunm  = 0
        row     = 0  
        charsinline = 20
        dataToWrite = ''
        while current < length:
            remain = length - current
            charsThisLine = charsinline if remain >= charsinline else remain
            
            chars = charPrint(struct.unpack(`charsThisLine`+'s', data[current:current + charsThisLine])[0])
            dataToWrite += chars
            
            current = current + charsinline
            if current < length:
                dataToWrite += '\n'
        self.textCtrlForCharData.AppendText(dataToWrite)

    def writeRawData(self,data):
        self.textCtrlForRawData.Clear()
        # self.textCtrl.AppendText(charPrint(data).decode('utf-8') )

        lenth = len(data)
        current = 0 
        colunm  = 0
        row     = 0  
        dataToWrite = ''
        while current < lenth:
            dataToWrite += hexPrint(struct.unpack('B', data[current])[0] ).decode('utf-8')
            current = current+1
            colunm = colunm+1
            if colunm == 20:
                dataToWrite += '\n'
                colunm = 0
                row = row + 1
        self.textCtrlForRawData.AppendText(dataToWrite)
        
    def resizeTextCtrl(self):
        LineSpace = self.textCtrlForRawData.GetBasicStyle().GetLineSpacing()
        font = self.textCtrlForRawData.GetFont()
        heightInOneLine = font.GetPointSize() * 96 / 72 + LineSpace #计算行高

        size = (-1, self.textCtrlForRawData.GetNumberOfLines() * heightInOneLine + LineSpace)
        self.scroll.SetVirtualSize(size)

        self.textCtrlForRawData.SetSize(size)
        self.textCtrlForCharData.SetSize(size)

        self.scroll.SetAutoLayout(False)

        self.scroll.Refresh()
        # print size,self.textCtrlForRawData.GetSize(),self.scroll.GetVirtualSize()
    def drawTreeCtrl(self,index):
        index = int(index)

        self.tree.DeleteAllItems()
        self.root = self.tree.AddRoot(u"第"+`index`+u"个数据包")
        tem = self.temList[index]

        self.writeRawData(tem.pack())
        self.writeCharData(tem.pack())
        self.resizeTextCtrl()

        childId1 = self.tree.AppendItem(self.root, u"链路层数据")
        self.tree.AppendItem(childId1, u"源MAC地址： " + self.listData[index][2])
        self.tree.AppendItem(childId1, u"目标MAC地址： " + self.listData[index][3])
        self.tree.AppendItem(childId1, u"数据类型： " + tem.data.__class__.__name__)
        childId2 = self.tree.AppendItem(self.root, u"网络层数据")

        if tem.data.__class__.__name__=='IP':
            src_ip  = '%d.%d.%d.%d'%tuple(map(ord,list(tem.data.src)))
            dist_ip = '%d.%d.%d.%d'%tuple(map(ord,list(tem.data.dst)))
            self.tree.AppendItem(childId2, u"源IP地址: " + src_ip)
            self.tree.AppendItem(childId2, u"目的IP地址: " + dist_ip)
                
        childId3 = self.tree.AppendItem(self.root, u"传输层数据")
        if tem.data.data.__class__.__name__ == 'TCP' or tem.data.data.__class__.__name__ == 'UDP':
            self.tree.AppendItem(childId3, u"源端口" + `tem.data.data.sport`)
            self.tree.AppendItem(childId3, u"目的端口" + `tem.data.data.dport`)
        pass
    def drawList(self,panel): #创建主监视列表

        self.list = VirtualListCtrl(panel,self.listData)
    def addItem(self, itemList, tem):
        # index = self.list.InsertStringItem(sys.maxint, `self.num`)
        # for col in range(0,len(itemList)):
        #     self.list.SetStringItem(index, col + 1, itemList[col])

        # self.list.ScrollList(0, index)
        if self.isPause == True:
            return
        itemList.insert(0, `self.num`)
        self.num += 1
        self.listData.append(itemList)
        self.temList.append(tem)
        self.list.refresh() 

def eth_addr_to_str(mac_addr):
    mac_addr = binascii.hexlify(mac_addr)
    s = list()
    for i in range(12/2) :
        s.append( mac_addr[i*2:i*2+2] )
    r = ":".join(s)
    return r.upper()


def thread_print(global_queue, frame):
    global  mutex, isStop
    # 获得线程名
    threadname = threading.currentThread().getName()
    try:
        while not isStop:
            ptime,pdata = global_queue.get()

            if isStop == True:
                return

            # tem= dpkt.ethernet.Ethernet(pdata)
            tem = pdata #pdata不能被序列化 暂时在读取时处理

            # global frame

            

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
                        itemList[3] = tem.data.data.__class__.__name__;
                        itemList.append(socket.inet_ntop(socket.AF_INET6, tem.data.src)) #source IP
                        itemList.append(socket.inet_ntop(socket.AF_INET6, tem.data.dst)) #dist IP
                    except:
                        itemList.append(win_inet_pton.inet_ntop(socket.AF_INET6, tem.data.src)) #source IP
                        itemList.append(win_inet_pton.inet_ntop(socket.AF_INET6, tem.data.dst)) #dist IP
                try:
                    print tem.data.data.__class__.__name__
                except Exception,e:
                    print str(e)



            frame.addItem(itemList,tem)

    except KeyboardInterrupt:
        return


def readFromPcap(global_queue, name = None, filter = None):
    # global global_queue, mutex, isStop
    pc=pcap.pcap(name = name, immediate = True)
    if filter != None:
        pc.setfilter(filter)
    for ptime,pdata in pc:
        # if isStop:
        #     return
        
        try:
            tem= dpkt.ethernet.Ethernet(pdata)#pdata不能被序列化 暂时在读取时处理
            global_queue.put((ptime,tem))
        except Exception,e:
            print str(e)

        # print ptime
        # 释放锁
        # break

class App(wx.App):

    def OnInit(self):
        self.frame = ListBoxFrame()   #4
        self.frame.Show()
        self.SetTopWindow(self.frame)   #5
        return True

if __name__ == '__main__':
    multiprocessing.freeze_support()
    isStop = False

    app = wx.PySimpleApp()

    openFrameForDevChoise()
    
    app.MainLoop()
    isStop = True

    print 'Exit!!'
    

    readThread.terminate()
    print 'TERMINATED:', readThread, readThread.is_alive()

    readThread.join()
    printThread.join()
