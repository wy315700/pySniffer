# -*- coding: utf-8 -*-  
__author__ = 'wangyang'
import wx
import pcap

class ListBoxFrame(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, None, -1, 'List Box Example', 
                size=(250, 200))
        self.panel = wx.Panel(self, -1)
        vbox = wx.BoxSizer(wx.VERTICAL)

        self.getAllDev()
        self.drawListBox()
        self.drawButton()
        vbox.Add(self.listBox, 1, wx.EXPAND | wx.ALL | wx.ALIGN_TOP, 20)
        vbox.Add(self.button,  0, wx.ALIGN_CENTER | wx.ALL ^wx.TOP | wx.ALIGN_BOTTOM, 20)
        self.panel.SetSizer(vbox)

    def getAllDev(self):
        self.devlist = pcap.findalldevs()

    def drawListBox(self):
        self.listBox = wx.ListBox(self.panel, -1, (20, 20), (160, 120), self.devlist, 
                wx.LB_SINGLE)
        self.listBox.SetSelection(3)

    def drawButton(self):
        self.button = wx.Button(self.panel, -1, u"选择", pos=(50, 20))
        self.Bind(wx.EVT_BUTTON, self.OnClick, self.button)
        self.button.SetDefault()

    def OnClick(self, event):
        dlg = wx.MessageDialog(None, u"您选择的网卡是："+ self.devlist[self.listBox.GetSelection()],
                          'A Message Box',
                          wx.YES_NO | wx.ICON_QUESTION)
        retCode = dlg.ShowModal()
        if (retCode == wx.ID_YES):
            print "yes"
        else:
            print "no"

                
if __name__ == '__main__':
    app = wx.PySimpleApp()
    ListBoxFrame().Show()
    app.MainLoop()  