# encoding: utf8
#
# pyshaper - a dynamic traffic-shaper for Linux 2.4-2.6 based systems.
#
# Written in March 2004 by David McNab <david@freenet.org.nz>
# Copyright (c) 2004 by David McNab
#
# Released under the terms of the GNU General Public License.
#
# You should have received a file named 'COPYING' with this
# program. If not, you can review a copy of the GPL at the
# GNU website, at http://gnu.org
#

import os
import thread
import threading
import time
import traceback

import Pmw

import pyshaper

from Tkinter import *

from pyshaper.config import ShaperConfig
from pyshaper.conn import TCPConns
from pyshaper.ipmon import IPmon, MatchedConnectionException
from pyshaper.util import takeKey


class TShaperGui:
    """
    Displays a GUI to allow users to visualise and edit shaping config

    GUI can:
        - launch/stop shaper
        - display/edit shaper config
        - send a SIGHUP to running shaper to make it reload config
    """
    
    
    def __init__(self):
        self.startTime = time.time()

        # load initial config
        self.config = ShaperConfig(os.environ.get("PYSHAPERCONFIG", None))
        self.config.dontSave = True
        self.shaperPeriod = self.config.shaperPeriod

        # set up connection monitoring
        self.lockConns = threading.Lock()
        self.conns = TCPConns()
        thread.start_new_thread(self.thrdConns, ())

        # cache of packet details
        # each key is a list [src,sport,dst,dport] of packet details
        # each value is a shaper class which matches the packet
        self.pktCache = {}

        self.savingWindowSize = False

        self.buildWindow()
        self.centerWindow()

        ipmon = self.ipmon = IPmon(handler=self.on_packet)
        thread.start_new_thread(ipmon.run, ())

    
    
    def buildWindow(self):

        root = self.root = Tk()
        root.title("pyshaper - Bandwidth Manager")
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        # set change flag
        self.hasChanged = False

        # gui sizing attributes
        self.clsNameWidth = 16

        # tooltip object
        self.toolTip = Pmw.Balloon(self.root)

        frmMain = self.frmMain = myFrame(root)
        frmMain.pack(side=LEFT, fill=BOTH, expand=1)

        self.buildMenu()

        # create the panes
        paneMain = self.paneMain = myPanedWidget(self.frmMain,
                                                 orient='vertical',
                                                 hull_borderwidth=3,
                                                 separatorrelief='raised',
                                                 command=self.on_paneMainResize,
                                                 )
        paneMain.pack(fill=BOTH, expand=1)

        # overall control pane
        paneCtrl = paneMain.add('ctrl')
        frmCtrl = self.frmCtrl = myFrame(paneCtrl)
        frmCtrl.pack(side=TOP, fill=X, expand=1)

        # checkbutton to turn shaping on and off
        isRunning = self.isRunning()
        varRunning = self.varRunning = IntVar(frmCtrl)
        varRunning.set(isRunning)
        self.chkRunning = myCheckbutton(
            frmCtrl,
            text="Shaping Is Active",
            variable=varRunning,
            command=self.on_chkRunning,
            )
        self.chkRunning.pack(side=LEFT)

        # traffic indicator
        self.labTraffic = myLabel(
            frmCtrl,
            text="Traffic",
            )
        self.labTraffic.pack(side=LEFT)

        # counter for setting shaper interval
        frmPeriod = self.frmCtrl = myFrame(paneCtrl)
        frmPeriod.pack(side=TOP, fill=X, expand=1)

        myLabel(frmPeriod, text="Shape current connections every").pack(side=LEFT)
        s = self.cntShaperPeriod = myCounter(
            frmPeriod,
            #datatype='numeric',
            entry_width=3,
            entryfield_value=int(self.config.shaperPeriod),
            entryfield_validate = { 'validator':'integer', 'min':4, 'max':300},
            command=self.on_changeValue,
            )
        s.pack(side=LEFT)
        myLabel(frmPeriod, text="seconds").pack(side=LEFT)


        # button to restart the shaper
        #if isRunning:
        #    state = NORMAL
        #else:
        #    state = DISABLED

        if self.isRunning():
            txt = "Apply Changes"
        else:
            txt = "Save Changes"
        state = DISABLED
        self.butApplyChanges = myButton(
            frmCtrl,
            text=txt,
            command=self.on_butApplyChanges,
            state=state,
            )
        self.butApplyChanges.pack(side=RIGHT)

        # classes display pane
        paneClasses = paneMain.add('classes')
        #frmClasses = self.frmClasses = myFrame(paneClasses)
        #frmClasses.pack(side=TOP, fill=X, expand=1)

        # big list widget for displaying connection classes and traffic
        classWidgets = self.classWidgets = {}
        classWidgetsList = self.classWidgetsList = []
        lstClasses = self.lstClasses = ClsListBox(paneClasses, self)
        lstClasses.pack(side=TOP, fill=BOTH, expand=1)
        for iface in self.config.interfaces:
            #print iface
            classes = iface.classes[:]
            #print "\n".join([str(c) for c in classes])
            if not classes:
                continue
            #classes.sort()

            # add all traffic classes
            for cls in classes:
                lstItem = ClsListBoxItem(lstClasses, iface, cls,
                                         clsNameWidth=self.clsNameWidth,
                                         gui=self)
                classWidgets[iface.name, cls.name] = lstItem
                classWidgetsList.append(lstItem)
                lstClasses.append(lstItem)

            # add the default class for this interface
            lstItem = ClsListBoxItem(lstClasses, iface, iface.default,
                                     clsNameWidth=self.clsNameWidth,
                                     gui=self)
            classWidgets[iface.name, 'default'] = lstItem
            classWidgetsList.append(lstItem)
            lstClasses.append(lstItem)

        return

        # stuff here is just for reference

        menuEdit = myMenu(menuTop, "Edit")
        menuEdit.addCmd("Configuration...", self.on_menuEditConfig,
                        "Control-C", "Shift-^C")

        menuView = myMenu(menuTop, "View")
        menuView.addCmd("Show Router Console", self.on_menuViewConsole)

        menuTools = myMenu(menuTop, "Tools")
        menuTools.addCmd("Re-Seed Peers Database", self.on_menuToolsReseed)

        menuHelp = myMenu(menuTop, "Help")
        menuHelp.addCmd("User Manual", self.on_menuHelpManual)
        menuHelp.addCmd("I2P Project Website", self.on_menuHelpWebsite)
        menuHelp.addCmd("Frequently Asked Questions", self.on_menuHelpFAQ)
        menuHelp.addCmd("Mailing List", self.on_menuHelpMailList)
        menuHelp.addCmd("Wiki Pages", self.on_menuHelpWiki)
        menuHelp.addCmd("About", self.on_menuHelpAbout)

        if 0:
            menuEdit = myMenu(menuTop, "Edit")
            menuEdit.addCmd("New Task", self.on_menuEditNewTask,
                            "Control-n", "^N")
            menuEdit.addCmd("Edit Task", self.on_menuEditEditTask,
                            "Control-e", "^E")
            menuEdit.addCmd("Delete Task", self.on_menuEditDeleteTask,
                            "Control-d", "^D")
            menuEdit.addCmd("Projects", self.on_menuEditProjects,
                            "Control-p", "^P")
            menuEdit.addCmd("Settings", self.on_menuEditSettings,
                            "Control-S", "Shift-^S")

            menuDebug = myMenu(menuTop, "Debug")
            menuDebug.addCmd("Calendar", self.on_menuDebugCalendar, "Control-C", "S^C")

            menuHelp = myMenu(menuTop, "Help")
            menuHelp.addCmd("About", self.on_menuHelpAbout, None, None)

        return

        # create router status pane
        paneRouter = self.paneRouter = paneMain.add('router')

        frmRouter = myFrame(paneRouter)
        frmRouter.pack(side=TOP, fill=X, expand=1)

        myLabel(frmRouter,
                text="Router Status",
                font=theme.myFontHeading).pack(side=LEFT, anchor=W)
        self.butRouter = myButton(frmRouter, text=rtrButTxt, command=self.on_butRouter)
        self.butRouter.pack(side=RIGHT, anchor=E)
        self.labRouterStatus = myLabel(frmRouter, text=rtrTxt)
        self.labRouterStatus.pack(side=RIGHT, anchor=W)

        if 0:
            # TunnelMgr status and button pane
            if self.i2pmgr.tunnelMgrIsRunning():
                tmgrTxt = "Running"
                tmgrButTxt = "Stop"
            else:
                tmgrTxt = "Not Running"
                tmgrButTxt = "Start"
            frmTunnelMgr = myFrame(paneRouter)
            frmTunnelMgr.pack(side=TOP, fill=X, expand=1)
            myLabel(frmTunnelMgr,
                    text="Tunnel Manager Status",
                    font=theme.myFontHeading).pack(side=LEFT, anchor=W)
            self.butTunnelMgr = myButton(frmTunnelMgr, text=tmgrButTxt, command=self.on_butTunnelMgr)
            self.butTunnelMgr.pack(side=RIGHT, anchor=E)
            self.labTunnelMgrStatus = myLabel(frmTunnelMgr, text=tmgrTxt)
            self.labTunnelMgrStatus.pack(side=RIGHT, anchor=W)

        # eepproxy status and button pane
        if self.i2pmgr.webProxyIsRunning():
            eepTxt = "Running"
            eepButTxt = "Stop"
        else:
            eepTxt = "Not Running"
            eepButTxt = "Start"

        frmEepProxy = myFrame(paneRouter)
        frmEepProxy.pack(side=TOP, fill=X, expand=1)
        myLabel(frmEepProxy,
                text="Web Proxy Status",
                font=theme.myFontHeading).pack(side=LEFT, anchor=W)
        self.butEepProxy = myButton(frmEepProxy, text=eepButTxt, command=self.on_butEepProxy)
        self.butEepProxy.pack(side=RIGHT, anchor=E)
        self.labEepProxyStatus = myLabel(frmEepProxy, text=eepTxt)
        self.labEepProxyStatus.pack(side=RIGHT, anchor=W)
        self.toolTip.bind(
            self.butEepProxy,
            "Set your browser's HTTP proxy to localhost:%s to use" % self.i2pmgr.i2pMgrCfg['webProxyPort'],
            )


        # services display pane
        paneServices = self.paneServices = paneMain.add('services')

        labServices = myLabel(paneServices, text="Your Services", justify=LEFT)
        labServices.pack(side=TOP, anchor=W)

        frmSvcs = myPanedWidget(paneServices, orient='horizontal')
        frmSvcs.pack(side=LEFT, fill=Y, expand=1)

        # *********************************************
        # CREATE/POPULATE SERVICESLIST MEGAWIDGET

        paneSvcsList = frmSvcs.add('serviceslist')
        lstServices = self.lstServices = SvcListBox(paneSvcsList)
        lstServices.pack(side=LEFT, fill=BOTH, expand=1)
        svcs = self.i2pmgr.services.keys()
        svcs.sort()
        for svc in svcs:
            lstServices.append(SvcListBoxItem(lstServices, name=svc, gui=self))
        if len(svcs) > 0:
            lstServices.selectItem(0)

        frmSvcButs = frmSvcs.add('svcsbuts', min=48, max=80)

        frmSvcButs1 = myFrame(frmSvcButs, bg="green")
        frmSvcButs1.pack(side=TOP)

        butStartAll = self.butStartAll = myButton(frmSvcButs1,
                                                  text="Start All",
                                                  command=self.on_butStartAll,
                                                  )
        butStartAll.pack(side=TOP, fill=X, expand=1, anchor=N)
        self.toolTip.bind(butStartAll, "Starts all I2P services which\nare not already running")

        butStopAll = self.butStopAll = myButton(frmSvcButs1,
                                                text="Stop All",
                                                command=self.on_butStopAll,
                                                )
        butStopAll.pack(side=TOP, fill=X, expand=1, anchor=N)
        self.toolTip.bind(butStopAll, "Stops all I2P services which\nare presently running")

        butStartService = self.butStartService = myButton(frmSvcButs1,
                                                          text="Start",
                                                          command=self.on_butStartService,
                                                          )
        butStartService.pack(side=TOP, fill=X, expand=1, anchor=N)
        self.toolTip.bind(butStartService, "Starts the selected I2P service")

        butStopService = self.butStopService = myButton(frmSvcButs1,
                                                          text="Stop",
                                                          command=self.on_butStopService,
                                                          )
        butStopService.pack(side=TOP, fill=X, expand=1, anchor=N)
        self.toolTip.bind(butStopService, "Stops the selected I2P service")

        butAddService = self.butAddService = myButton(frmSvcButs1,
                                                          text="Add",
                                                          command=self.on_butAddService,
                                                          )
        butAddService.pack(side=TOP, fill=X, expand=1, anchor=N)
        self.toolTip.bind(butAddService, "Creates a whole new I2P service")

        butEditService = self.butEditService = myButton(frmSvcButs1,
                                                          text="Edit",
                                                          command=self.on_butEditService,
                                                          )
        butEditService.pack(side=TOP, fill=X, expand=1, anchor=N)
        self.toolTip.bind(
            butEditService,
            "Allows you to change the configuration\n"
            "of the selected I2P service\n"
            "You may not make changes if the service is"
            "presently running")

        butDeleteService = self.butDeleteService = myButton(frmSvcButs1,
                                                          text="Delete",
                                                          command=self.on_butDeleteService,
                                                          )
        butDeleteService.pack(side=TOP, fill=X, expand=1, anchor=N)
        self.toolTip.bind(
            butDeleteService,
            "Destroys the selected service, and\n"
            "deletes all its files.\n"
            "Currently running services may not be deleted")

        # add a title pane with random slogan
        self.paneTitle = paneMain.add('title', min=24, max=80)
        random.seed(time.asctime())
        try:
            slogan = random.choice(g.newlines.split(file("slogans.txt").read().strip()))
        except:
            traceback.print_exc()
            slogan = "(slogans.txt file not found)"
        labTitleText = "I2P: " + slogan
        labTitle = myLabel(self.paneTitle,
                           text=labTitleText,
                           wraplength=400,
                           font=theme.myFont,
                           )
        labTitle.pack(anchor='n')


        # status pane and text widget
        if 0:
            paneLog = self.paneLog = paneMain.add('log', min=60)

            labLog = myLabel(paneLog, text="Status Log", justify=LEFT)
            labLog.pack(side=TOP, anchor=NW)

            txtLog = myText(paneLog, usehullsize=1)
            txtLog.pack(side=TOP, fill=BOTH, expand=1)
            self.txtLog = txtLog.interior()
            self.txtLog.configure(height=12)
            txtLog.component('hull').configure(height=80)
            txtLog.component('hull').pack(fill=BOTH)














    
    
    def buildMenu(self):

        # -------------------------------------------------
        # Construct the menu
        menuTop = self.menuTop = myMenu(self.frmMain)
        self.root.config(menu=menuTop)

        menuFile = myMenu(menuTop, "File")
        menuFile.addCmd("Quit", self.on_menuFileQuit,
                        "Control-q", "^Q")

        menuHelp = myMenu(menuTop, "Help")
        menuHelp.addCmd("About", self.on_menuHelpAbout,
                        "Shift-Alt-Control-h", "")
    
    
    def centerWindow(self):

        root = self.root

        root.update_idletasks()

        scrW = root.winfo_screenwidth()
        scrH = root.winfo_screenheight()

        w = root.winfo_width()
        h = root.winfo_height()

        #print w, h

        root.geometry("+%s+%s" % ((scrW - w)/2, (scrH - h)/2))
    
    
    def run(self):

        #print "gui not implemented yet"

        self.lastPktTime = time.time()
        self.frmMain.after(100, self.on_startup)
        self.root.mainloop()
    
    
    def isRunning(self):
        """
        Determines whether the daemon is running, returns True/False
        """
        return os.path.isfile(pyshaper.pidfile)

    
    
    def startDaemon(self):
        """
        Launches the daemon
        """
        os.system("pyshaper -V 3 start")
    
    
    def stopDaemon(self):
        """
        Terminates the daemon
        """
        os.system("pyshaper stop")
    
    
    def restartDaemon(self):
        """
        Terminates the daemon
        """
        os.system("pyshaper reload")
    
    
    def on_startup(self):

        """
        Callback which gets hit as soon as the gui mainloop is entered
        """
        self.root.geometry("%sx%s" % (self.config.guiWidth, self.config.guiHeight))
        #print "w=%s, h=%s" % (self.config.guiWidth, self.config.guiHeight)
        self.labTraffic.after(1000, self.on_refresh)
    
    
    def on_close(self, ev=None):

        print "pyshaper gui window closed"
        self.root.destroy()
        sys.exit(0)
    
    
    def on_paneMainResize(self, wh):

        #print "pane main resize: %s" % repr(wh)
        #print self.root.geometry()

        if time.time() - self.startTime < 3:
            return

        if self.savingWindowSize:
            #print "saving config with new window size"
            g = self.root.geometry()
            wS, hS = g.split("+",1)[0].split("x")
            self.config.guiWidth, self.config.guiHeight = int(wS), int(hS)
            self.config.save(True)
        else:
            self.config.dontSave = False
            self.savingWindowSize = True
    
    
    def on_menuFileQuit(self, ev=None):

        self.on_close()
    
    
    def on_menuHelpAbout(self, ev=None):
        myMessageBox(
            self.root,
            "About pyshaper",
            "\n".join(["This is pyshaper version %s" % pyshaper.__version__,
                       "",
                       "pyshaper is a bandwidth management program written",
                       "by David McNab <david@freenet.org.nz>",
                       "",
                       "Copyright (c) 2004, all rights reserved",
                       "Released under the GNU General Public License",
                       "",
                       "pyshaper homepage:",
                       "http://www.freenet.org.nz/python/pyshaper",
                       "",
                     ]),
                    )
    
    
    def on_chkRunning(self, event=None):
        """
        Starts/stops the daemon
        """
        if self.varRunning.get():
            # button is ON, start the daemon
            self.butApplyChanges.configure(text="Apply Changes")
            self.startDaemon()
        else:
            # button is OFF, stop daemon
            self.butApplyChanges.configure(text="Save Changes")
            self.stopDaemon()
    
    
    def on_butApplyChanges(self, ev=None):

        classWidgets = self.classWidgets
        config = self.config

        # transfer period val into config
        config.shaperPeriod = int(self.cntShaperPeriod.get())

        # transfer the class counter values into config
        for iface in self.config.interfaces:
            #print iface
            ifaceName = iface.name

            # get config object for this interface
            cfgIface = config.interfacesdict[ifaceName]

            # get counter values from each class
            for cls in iface.classes[:]:

                # uplift widget values
                clsName = cls.name
                clsItem = classWidgets[ifaceName, clsName]
                bwIn = int(clsItem.cntIn.getvalue())
                bwOutRate = int(clsItem.cntOutMin.getvalue())
                bwOutCeil = int(clsItem.cntOutMax.getvalue())

                # get config object for this class
                cfgClass = cfgIface.classesdict[clsName]

                # and update config object
                cfgClass.bwIn = bwIn
                cfgClass.bwOutRate = bwOutRate
                cfgClass.bwOutCeil = bwOutCeil

            # ditto for interface default class
            clsItem = classWidgets[ifaceName, 'default']
            bwIn = int(clsItem.cntIn.getvalue())
            bwOutRate = int(clsItem.cntOutMin.getvalue())
            bwOutCeil = int(clsItem.cntOutMax.getvalue())

            # get config object for this class
            cfgClass = cfgIface.default

            # and update config object
            cfgClass.bwIn = bwIn
            cfgClass.bwOutRate = bwOutRate
            cfgClass.bwOutCeil = bwOutCeil

        # write out config
        print "trying to save updated config"
        config.dontSave = False
        config.save(True)

        self.butApplyChanges.config(state=DISABLED)

        # and tell daemon to reload the new config
        if self.isRunning():
            self.restartDaemon()

    
    
    def on_changeValue(self, wid, newval):

        print "value changed"
        self.hasChanged = True
        self.butApplyChanges.configure(state=NORMAL)
    
    
    def on_packet(self, pkt):
        """
        Receives a packet I/O notification from the IPmon thread
        """
        #print pkt

        # turn on traffic 'LED' and mark time of receiving last pkt
        self.labTraffic.config(bg='green', fg=theme.labBgColor)
        self.lastPktTime = time.time()

        # is this pkt info cached?
        src = pkt['src']
        sport = pkt['sport']
        dst = pkt['dst']
        dport = pkt['dport']
        plen = pkt['len']

        cls = self.pktCache.get((src, sport, dst, dport), None)

        cls = None # disable caching for now

        if cls:
            #print "on_packet: found in cache as class %s" % cls.name
            cls.on_packet(src, sport, dst, dport, plen)
            return
        else:
            # classify packet
            for mode in [True, False]:
                for iface in self.config.interfaces:
                    # try the classes
                    for cls in iface.classes:
                        if cls.name == 'default':
                            continue
                        #print "gui.on_packet: awaiting lock"
                        self.lockConns.acquire()
                        #print "gui.on_packet: got lock"
                        try:
                            res = cls.matchesPacket(src, sport, dst, dport, mode)
                        except:
                            traceback.print_exc()
                            res = None
                        self.lockConns.release()
                        #print "gui.on_packet: released lock"
                        if res:
                            #print "cls %s matches %s,%s,%s,%s" % (cls.name, src,sport,dst,dport)
                            self.pktCache[src, sport, dst, dport] = cls
                            cls.on_packet(src, sport, dst, dport, plen)
                            return

                    # is either src or dest matching iface's ip?
                    #print "ipaddr=%s src=%s dst=%s" % (repr(iface.ipaddr),repr(src),repr(dst))
                    if iface.ipaddr in (src, dst):
                        # yes, handle as default
                        #self.pktCache[src, sport, dst, dport] = iface.default
                        iface.default.on_packet(src, sport, dst, dport, plen)
                        return

        print "unmatched packet %s:%s->%s:%s %s" % (src, sport, dst, dport, plen)






    
    
    def on_refresh(self, ev=None):
        """
        Thread which updates the gui periodically
        """
        try:
            # turn off 'traffic' light if no recent traffic
            if time.time() - self.lastPktTime > 0.1:
                # timeout - turn off traffic indicator label
                self.labTraffic.config(bg=theme.labBgColor, fg=theme.labFgColor)

            # update rate totals on all classes
            for clswid in self.classWidgetsList:
                clswid.refreshRate()

            # update the 'router is running' checkbutton
            self.varRunning.set(self.isRunning())

            # set up repeat callback
            self.labTraffic.after(500, self.on_refresh)

        except KeyboardInterrupt:
            print "on_refresh: terminated by user"
            sys.exit(0)

        except:
            traceback.print_exc()
            return
    
    
    def thrdConns(self):
        """
        Periodically monitor/update connections
        """
        while 1:
            time.sleep(1)

            try:
                conns = TCPConns()

                #print "thrdConns: awaiting lock"
                self.lockConns.acquire()
                #print "thrdConns: got lock"

                try:
                    # forget previous connections for all classes
                    for iface in self.config.interfaces:
                        for cls in iface.classes:
                            cls.conns = []
                        iface.default.conns = []

                    # sort current connections into classes
                    #print "---- thrdConns ----"
                    for conn in conns:
                        #print "thrdConns: %s:%s %s:%s" % (conn.raddr, conn.rport, conn.laddr, conn.lport)
                        try:
                            localip = conn.laddr

                            # match against each rule
                            for iface in self.config.interfaces:
                                # ditch connections that aren't on this interface
                                if iface.ipaddr != localip:
                                    continue

                                # try to match against all classes
                                for cls in iface.classes:
                                    if cls.matches(conn):
                                        #print "%s matched %s:%s %s:%s" % (
                                        #    cls.name, conn.laddr, conn.lport, conn.raddr, conn.rport)
                                        cls.conns.append(conn)
                                        raise MatchedConnectionException() # bail out to uppermost loop

                                # no rule found for conn, add to default
                                iface.default.conns.append(conn)
                                break # quicker than raising exception

                        except MatchedConnectionException:
                            pass

                    self.conns = conns
                except:
                    traceback.print_exc()

                self.lockConns.release()
                #print "thrdConns: released lock"

            except:
                traceback.print_exc()


    
    


class myMenu(Menu):
    
    
    def __init__(self, parent, label=None, tearoff=0, **args):

        Menu.__init__(self, parent,
                      font="helvetica 10",
                      tearoff=tearoff,
                      **args)
        if label != None:
            parent.add_cascade(label=label, menu=self)

        self['bg'] = theme.menuBgColor
        self['fg'] = theme.menuFgColor
        self['font'] = theme.menuFont
        self['activebackground'] = theme.menuActiveBgColor
        self['activeforeground'] = theme.menuActiveFgColor
    
    
    def add_cascade(self, underline=0, **args):
        Menu.add_cascade(self, underline=0, **args)
    
    
    def add_command(self, underline=0, **args):
        Menu.add_command(self, underline=0, **args)
    
    
    def addCmd(self, label, action, shortcut=None, abbrev='', **args):
        self.add_command(label=label,
                         accelerator=abbrev,
                         command=action,
                         **args)
        if shortcut != None:
            self.bind_all("<%s>" % shortcut, action)

    
    


class myPanedWidget(Pmw.PanedWidget):

    def __init__(self, parent, **kwds):

        handlesize = takeKey(kwds, 'handlesize', 0)

        Pmw.PanedWidget.__init__(self,
                                 parent,
                                 handlesize=handlesize,
                                 **kwds)

        self.component('hull').config(
            bg=theme.frmBgColor,
            highlightcolor=theme.frmBgColor,
            highlightbackground=theme.frmBgColor,
            )
        #self.component('Handle').configure(bg=theme.frmBgColor)

    def add(self, name, **kw):
        pane = Pmw.PanedWidget.add(self, name, **kw)
        pane.config(
            bg=theme.frmBgColor,
            highlightcolor=theme.frmBgColor,
            highlightbackground=theme.frmBgColor,
            )
        return pane



class myFrame(Frame):
    def __init__(self, parent, **kw):
        bg = takeKey(kw, 'bg', theme.frmBgColor)
        Frame.__init__(self,
                       parent,
                       bg=bg,
                       highlightbackground=theme.frmBgColor,
                       highlightcolor=theme.frmBgColor,
                       borderwidth=0,
                       highlightthickness=0,
                       **kw
                       )



class myLabel(Label):
    
    
    def __init__(self, parent, **kw):

        bg = takeKey(kw, 'bg', theme.labBgColor)
        fg = takeKey(kw, 'fg', theme.labFgColor)
        height = takeKey(kw, 'height', 1)
        font = takeKey(kw, 'font', theme.myFont)

        #print "theme.myFont = %s" % theme.myFont

        Label.__init__(self, parent,
                       #font=font,
                       bg=bg,
                       fg=fg,
                       font=font,
                       #height=height,
                       **kw)


    
    



class myButton(Button):
    
    
    def __init__(self, parent, **kw):

        bg = takeKey(kw, 'bg', theme.butBgColor)
        fg = takeKey(kw, 'fg', theme.butFgColor)
        font = takeKey(kw, 'font', theme.butFont)
        padx = takeKey(kw, 'padx', theme.butPadx)
        pady = takeKey(kw, 'pady', theme.butPady)

        Button.__init__(self, parent,
                        font=font,
                        bg=bg,
                        fg=fg,
                        padx=padx,
                        pady=pady,
                        **kw)
        self.config(
            #background=theme.butBgColor,
            foreground=theme.butFgColor,
            #selectColor=theme.butSelColor,
            activeforeground=theme.butActiveFgColor,
            activebackground=theme.butActiveBgColor,
            highlightbackground=theme.butHighlightColor,
            #selectBackground=theme.butActiveBgColor,
            #highlightColor=theme.butActiveFgColor,
            #selectForeground=theme.butSelColor,
            #disabledForeground=theme.tkDisabledFgColor,
            #insertBackground=theme.tkInsBgColor,
            #troughColor=theme.tkTroughColor
            )
    
    



class myCheckbutton(Checkbutton):
    def __init__(self, parent, **args):
        bg = takeKey(args, 'bg', theme.chkBgColor)
        fg = takeKey(args, 'fg', theme.chkFgColor)
        font = takeKey(args, 'font', theme.chkFont)

        if sys.platform == 'win32':
            theme.chkSelColor = theme.chkBgColor

        Checkbutton.__init__(self, parent,
                             onvalue=1, offvalue=0,
                             bg=bg,
                             fg=fg,
                             font=font,
                             justify=LEFT,
                             anchor=W,
                             selectcolor=theme.chkSelColor,
                             highlightcolor=theme.chkSelColor,
                             highlightbackground=theme.frmBgColor,
                             activeforeground=theme.chkActiveFgColor,
                             activebackground=theme.chkActiveBgColor,
                             **args)



    
    



class myEntry(Pmw.EntryField):
    
    
    def __init__(self, parent, **args):

        font = takeKey(args, 'font', theme.entryFont)
        bg = takeKey(args, 'bg', theme.entryBgColor)
        fg = takeKey(args, 'fg', theme.entryFgColor)
        width = takeKey(args, 'width', 8)

        Pmw.EntryField.__init__(
            self, parent,
            **args)

        try:
            self.component('entry').config(
                bg=bg,
                fg=fg,
                font=font,
                width=width,
                selectforeground=fg,
                selectbackground=theme.entrySelColor,
                #activebackground=bg,
                disabledbackground=theme.entryBgColor,
                #disabledforeground=theme.entryDisabledFgColor,
                disabledforeground='white',
                highlightcolor=theme.labBgColor,
                highlightbackground=theme.labBgColor,
                insertbackground=fg,
                )
        except:
            #print "BLAH!!!"
            self.component('entry').config(
                bg=bg,
                fg=fg,
                font=font,
                width=width,
                selectforeground=fg,
                selectbackground=theme.entrySelColor,
                #activebackground=bg,
                highlightcolor=theme.labBgColor,
                highlightbackground=theme.labBgColor,
                insertbackground=fg,
                )

        self.component('hull').config(
            bg=bg,
            highlightcolor=fg,
            highlightbackground=bg,
            )

        try:
            lab = self.component('label')
        except:
            return

        #print "configuring label for field"
        if lab:
            try:
                self.component('label').config(
                    #borderwidth=0,
                    bg=theme.labBgColor,
                    fg=theme.labFgColor,
                    font=theme.labFont,
                    #disabledbackground=theme.entryBgColor,
                    disabledforeground=theme.entryDisabledFgColor,
                    highlightcolor=theme.labBgColor,
                    highlightbackground=theme.labBgColor,
                    )
            except:
                self.component('label').config(
                    #borderwidth=0,
                    bg=theme.labBgColor,
                    fg=theme.labFgColor,
                    font=theme.labFont,
                    #disabledbackground=theme.entryBgColor,
                    highlightcolor=theme.labBgColor,
                    highlightbackground=theme.labBgColor,
                    )


    
    


class myComboBox(Pmw.ComboBox):
    
    
    def __init__(self, parent, **args):

        Pmw.ComboBox.__init__(self, parent, **args)

        self.component('entryfield').component('entry').config(
            background=theme.cmbBgColor,
            foreground=theme.cmbFgColor,
            highlightbackground=theme.frmBgColor,
            )
        l = self.component('scrolledlist').component('listbox')
        #print l.keys()
        l.config(
            background=theme.cmbBgColor,
            foreground=theme.cmbFgColor,
            highlightbackground=theme.frmBgColor,
            selectbackground=theme.cmbSelBgColor,
            selectforeground=theme.cmbSelFgColor,
            )
        self.component('arrowbutton').config(
            bg=theme.cmbBgColor,
            highlightbackground=theme.frmBgColor,
            )
    
    


"""
This code is based on a sample from the book:
"Python and Tkinter programming" by John Grayson.
Many many thanks to the author for saving me a couple
of boring hours.
"""

from Tkinter import *

class myProgressBar:
    def __init__(self, master=None, orientation="horizontal",
                 min=0, max=100, width=100, height=18,
                 doLabel=1, appearance="flat",
                 fillColor=None, background="gray",
                 labelColor="yellow", labelFont="Verdana",
                 labelText="", labelFormat="%d%%",
                 value=50, bd=2):

        # preserve various values
        self.master = master
        self.orientation = orientation
        self.min = min
        self.max = max
        self.width = width
        self.height = height
        self.doLabel = doLabel
        if fillColor is None:
            fillColor = theme.progbarFgColor
        self.fillColor = fillColor

        self.labelFont = labelFont
        self.labelColor = labelColor
        self.background = theme.progbarBgColor

        self.labelText=labelText
        self.labelFormat=labelFormat
        self.value=value
        self.frame=Frame(master, relief=appearance, bd=bd,
                         borderwidth=0,
                         highlightbackground=theme.frmBgColor,
                         highlightcolor=theme.frmBgColor,
                         )
        self.canvas=Canvas(self.frame, height=height, width=width, bd=0,
                           highlightthickness=0, background=self.background,
                           borderwidth=0,
                           highlightbackground=theme.frmBgColor,
                           highlightcolor=theme.frmBgColor,
                           )
        #print self.canvas.keys()
        self.scale=self.canvas.create_rectangle(0, 0, width, height,
                                                fill=fillColor)
        self.label=self.canvas.create_text(self.canvas.winfo_reqwidth()
/ 2,
                                           height / 2, text=labelText,
                                           anchor="c", fill=labelColor,
                                           font=self.labelFont)

        self.span = self.max - self.min

        self.update()
        self.canvas.pack(side='top', fill='x', expand='no')


    def updateProgress(self, newValue, newMax=None):

        if newMax:
            self.max = newMax
        self.value = newValue
        self.update()

    def update(self):

        # Trim the values to be between min and max
        value=self.value
        if value > self.max:
            value = self.max
        if value < self.min:
            value = self.min

        span = self.span
        red = min(255, (value-self.min)*510/span)
        green = min(255, (self.max - value)*510/span)
        #print "level=%d, red=%d, green=%d" % (value, red, green)

        # Adjust the rectangle
        if self.orientation == "horizontal":
            self.canvas.coords(self.scale, 0, 0,
              float(value) / self.max * self.width, self.height)
        else:
            self.canvas.coords(self.scale, 0,
                               self.height - (float(value) /
                                              self.max*self.height),
                               self.width, self.height)
        # Now update the colors
        self.canvas.itemconfig(self.scale, fill=self.fillColor)
        # And update the label
        if self.doLabel:
            self.canvas.itemconfig(self.label, fill=self.labelColor)
            if value:
                if value >= 0:
                    pvalue = int((float(value) / float(self.max)) *
                                   100.0)
                else:
                    pvalue = 0
                self.canvas.itemconfig(self.label, text=self.labelFormat
                                         % pvalue)
            else:
                self.canvas.itemconfig(self.label, text='')
        else:
            pass
            #self.canvas.itemconfig(self.label, text=self.labelFormat %
            #                       self.labelText)
        self.canvas.update_idletasks()




class myCounter(Pmw.Counter):
    """
    A customised 'counter' or 'spinner' widget
    """
    
    
    def __init__(self, parent, **kwds):

        self.callback = takeKey(kwds, 'command', None)
        self.datatype1 = takeKey(kwds, 'datatype', self.on_change)

        self.min = kwds.get('entryfield_validate').get('min', 0)
        self.max = kwds.get('entryfield_validate').get('max', 100)

        Pmw.Counter.__init__(self, parent, datatype=self.datatype1, **kwds)

        #if self.callback:
        #    kw = {'command':self.on_change}
        #else:
        #    kw = {}

        self.component('uparrow').config(
            bg = theme.cntBgColor,
            borderwidth=0,
            #fg = theme.entryFgColor,
            highlightcolor=theme.cntBgColor,
            highlightbackground=theme.cntBgColor,
            )
        self.component('downarrow').config(
            bg = theme.cntBgColor,
            borderwidth=0,
            #fg = theme.entryFgColor,
            highlightcolor=theme.cntBgColor,
            highlightbackground=theme.cntBgColor,
            )

        if self.on_change:
            #self.component('downarrow').bind("<Button-1>", self.on_change)
            #self.component('uparrow').bind("<Button-1>", self.on_change)
            pass


        self.component('hull').config(
            bg = theme.cntFgColor,
            borderwidth=0,
            highlightcolor=theme.cntBgColor,
            highlightbackground=theme.cntBgColor,
            )
        ef = self.component('entryfield').component('entry')
        #print ef.keys()
        ef.config(
            borderwidth=0,
            fg=theme.cntFgColor,
            bg=theme.cntBgColor,
            highlightcolor=theme.cntBgColor,
            highlightbackground=theme.cntBgColor,
            )

    def on_change(self, text, factor, increment, *args):
        #print "on_change"
        val = int(text)
        newval = val + (factor * increment)
        if newval >= self.min and newval <= self.max:
            if self.callback:
                self.callback(self, newval)
            return newval
        else:
            return val

    
    



class myScale(Scale):
    
    
    def __init__(self, parent, orient='horizontal', **args):
        Scale.__init__(self, parent,
                       #bg="red",
                       orient=orient,
                       **args)
    
    


def myMessageBox(parent, title, message, icontype='warning', buttonlist=['OK'], defbutton=0):
    """
    myMessageBox - create and display a modal message dialog on the fly.

    Arguments:
     - parent - parent window
     - title - text to put into window title bar
     - message - text to display inside dialog
     - icontype - 'information', 'warning' or 'error'
     - buttonlist - a list of button labels
     - defbutton - index of default button in list
    """
    if 0 and parent:
        try:
            parent.deiconify()
        except:
            pass

    dialog = Pmw.MessageDialog(
        parent,
        title=title,
        defaultbutton=0,
        buttons=buttonlist,
        buttonboxpos='s',
        iconpos='w',
        icon_bitmap=icontype,
        message_text=message)

    #dialog.deiconify()
    #dialog.show()

    dialog.interior().configure(bg=theme.winBgColor)
    dialog.component('message').config(fg=theme.myFgColor, bg=theme.winBgColor)
    dialog.component('icon').config(bg=theme.winBgColor)
    bb = dialog.component('buttonbox')
    bb.component('hull').config(bg=theme.winBgColor)
    buttons = [bb.button(i) for i in range(bb.numbuttons())]
    for but in buttons:
        but.config(bg=theme.butBgColor,
                   fg=theme.butFgColor,
                   font=theme.butFont,
                   #butSelColor = "#c9c9c9"
                   activeforeground=theme.butActiveFgColor,
                   activebackground=theme.butActiveBgColor,
                   highlightbackground=theme.butBgColor,
                   )

    dialog.bind("<Escape>", dialog.deactivate)
    dialog.bind("<space>", dialog.deactivate)

    result = dialog.activate(geometry = 'centerscreenalways')
    if type(result) != type(""):
        result = buttonlist[defbutton]

    #print "myMessageBox: result=%s" % repr(result)
    return result





class WidgetListBoxItem(Frame):
    """
    Base class for creating multi-widget items which can be displayed
    in WidgetListBox objects

    Note that when you subclass this, you need to support the following
    methods:
        - setcolor - shades the item with a colour to indicate selection/deselection
        - on_select, on_deselect (optional)

    When inserting your own widgets into a WidgetListBoxItem, you must instantiate
    them with this WidgetListBoxItem object as parent, then call L{self.addwidget}

    Attributes you might be interested in:
        - widgets - a list of component widgets
        - parent - the WidgetListBox object into which this item has been inserted
    """
    
    
    def __init__(self, parent, *args, **kw):
        """
        Base constructor.

        You should override this to populate the item with usable widgets, and
        make sure in your constructor to call this constructor.

        Args:
            - parent - the WidgetListBox object on which this item will be displayed
        """

        # sanity check
        if not isinstance(parent, WidgetListBox):
            raise Exception("parent must be an instance of WidgetListBox or subclass")

        # grab style info
        self.bg = takeKey(kw, 'bg', getattr(parent, 'bg', '#ffffff'))
        self.fg = takeKey(kw, 'fg', getattr(parent, 'fg', '#000000'))
        self.bgsel = takeKey(kw, 'bgsel', getattr(parent, 'bgsel', '#8080ff'))
        self.fgsel = takeKey(kw, 'fgsel', getattr(parent, 'fgsel', '#000000'))

        Frame.__init__(self, parent.frame, width=300, bg=self.bg)
        self.parent = parent
        self.widgets = []
        self.pack(side=LEFT, fill=X, expand=0)
    
    
    def setselected(self, isSelected, ignore=0):

        if isSelected:
            # deselect prev selection
            prev = self.parent.selected
            if prev:
                prev.setselected(0)

            # set selected style, invoke callback
            self.parent.selected = self
            self.setcolor('select')
            self.focus_set()
            if not ignore:
                try:
                    self.on_select()
                except:
                    traceback.print_exc()
                self.parent.on_select(self)
        else:
            # set deselected style, invoke callback
            self.parent.selected = None
            self.setcolor('deselect')
            if not ignore:
                self.on_deselect()
                self.parent.on_deselect(self)
    
    
    def setcolor(self, state):
        """
        Sets the background of all items on this widget to color

        Override this in your subclass
        """
        if state == 'select':
            fgcolor = self.fgsel
            bgcolor = self.bgsel
            #print "setting color to %s" % color
        elif state == 'deselect':
            fgcolor = self.fg
            bgcolor = self.bg
        else:
            #print "color=%s" % color
            fgcolor = "#00ff00"
            bgcolor = "#ffe040"
        self.configure(bg=bgcolor)
        for wid in self.widgets:
            wid.configure(background=bgcolor)
            try:
                wid.configure(color=fgcolor)
            except:
                traceback.print_exc()



    
    
    def addwidget(self, wid, **kw):
        """
        Add a newly-created widget to your list item.

        This will chain the widget in to the listbox item, so that it will
        receive appropriate bindings, and be appropriately styled when selected
        and deselected.

        Arguments:
            - wid - widget to add (must have been created with this WidgetListBoxItem object
              as parent

        Keywords:
            - nobind - a list of binding names NOT to apply to this widget. One or more of:
                - '<Button-1>'
                - '<Down>'
                - '<Up>'
                - '<Button-4>'
                - '<Button-5>'
                - '<Next>'
                - '<Prior>'
            - bg - the default background colour of the widget
        """
        wid.noBind = kw.get('nobind', [])
        self.widgets.append(wid)
        wid.setselected = self.setselected
        bg = kw.get('bg', self.parent.bg)
        #print "bg=%s" % bg
        wid.configure(bg=bg)
        wid.parent = self

    
    
    def refresh(self):
        """
        Call this if you update the data cell.
        This propagates the change to the item's widgets
        """
        #print "WARNING: WidgetListItem.refresh() - you should subclass this"

    
    
    def on_select(self):
        """
        Called whenever this widget is selected, whether through
        mouse or keyboard actions

        Override as desired
        """
        #print "item selected"

    
    
    def on_deselect(self):
        """
        Called whenever this widget is deselected, whether through
        mouse or keyboard actions

        Override as desired
        """
        #print "item deselected"


    
    


class WidgetListBox(Pmw.ScrolledFrame):
    """
    Base bits of the WidgetListBox* classes
    """
    
    
    def __init__(self, parent, *args, **kw):

        self.bg = takeKey(kw, 'bg', '#ffffff')
        self.bgsel = takeKey(kw, 'bgsel', '#c0c0ff')
        self.fgsel = takeKey(kw, 'fgsel', '#c0c0c0')

        Pmw.ScrolledFrame.__init__(self, parent, *args, **kw)

        items = takeKey(kw, 'items', ())

        self.config(
            bg=self.bg,
            highlightbackground=self.bgsel,
            )

        if items:
            self.setlist(items)

        self.config(
            bg=self.bg,
            highlightbackground=self.bgsel,
            )

        self.frame = self.interior()
        self.view = self.component('clipper')
        self.view.configure(bg=self.bg)
        self.items = []
        self.selected = None



    
    
    def clear(self):
        self.setlist(())
        self.refresh()
    
    
    def get(self, first=None, last=None):
        """
        Similar to Pmw.ScrolledListBox.get()

        Retrieves one, some or all the items in the list.
        Note that the items returned are widget refs

        Arguments:
            - first - index of first item to get. Omit to get all items
            - last - index of last item to get. Omit to get just one item
        """
        nitems = len(self.items)
        if first == None:
            return self.items[:]
        if first < 0 or first >= nitems:
            raise Exception("Range error - first=%s, nitems=%s" % (first, nitems))
        if last == None:
            return self.items[first]
        elif last == END:
            return self.items[first:]
        else:
            return self.items[first:last]
    
    
    
    def getcurselection(self):
        """
        See getvalue()
        """
        return self.getvalue()
    
    
    def getvalue(self):
        """
        Returns a list of the currently selected items
        """
        if self.selected:
            return [self.selected]
        else:
            return []
    
    
    def setlist(self, lst, **kw):
        """
        Toss all the items in the list, and replace them
        with a whole new list of items.

        Each element of lst must be an instance of WidgetListBoxItem (or subclass)
        """
        # grab new items
        self.items = lst[:]

        # redisplay
        self.refresh()
    
    
    def setvalue(self, itemOrItems):
        """
        Sets the current selection for the WidgetListBox to itemOrItems

        Argument:
            - itemOrItems - either a single item (instance of WidgetListBoxItem or subclass),
              or a sequence of such
        """
        if type(itemOrItems) in [type(()), type([])]:
            nitems = len(itemOrItems)
            if nitems == 0:
                self.selectItem(-1)
            elif nitems > 1:
                raise("Multiple item selections not implemented yet")
        elif not isinstance(itemOrItems, WidgetListBoxItem) or itemOrItems not in self.items:
            raise("Nonexistent item")
        else:
            itemOrItems = [itemOrItems]

        for item in itemOrItems:
            self.selectItem(item)
    
    
    def size(self):
        """
        Returns the number of items in the list
        """
        return len(self.items)
    
    
    def on_select(self, item):
        """
        Callback which gets hit whenever an item gets selected

        Override as desired
        """
        #print "WidgetListBox.on_select: item=%s, idx=%s" % (item, self.getItemIndex(item))

    
    
    def on_deselect(self, item):
        """
        Callback which gets hit whenever an item gets deselected

        Override as desired
        """
        try:
            idx = self.getItemIndex(item)
        except:
            idx = -1
        #print "WidgetListBox.on_deselect: item=%s, idx=%s" % (item, idx)

    
    
    def append(self, item):
        """
        Append an item to the end of the list

        Arguments:
            - item - the item to append - must be instance of WidgetListBoxItem or subclass

        Returns:
            - the item appended, for your convenience, to let you use this method 'on the fly'
        """
        if not isinstance(item, WidgetListBoxItem):
            raise Exception("Item must be an instance of WidgetListBoxItem or subclass")

        self.items.append(item)
        self.refresh()
        return item

    
    
    def delete(self, idxOrItem):
        """
        Deletes an item from the end of the list

        Arguments:
            - idxOrItem - either a ref to an item currently on the list, or the
              'index' of the item within the list
        """
        nitems = len(self.items)

        # convert arg to an index, if needed
        if type(idxOrItem) == type(0):
            idx = item
        else:
            # attempt to find item
            try:
                idx = self.items.index(idxOrItem)
            except:
                raise Exception("Tried to delete item not present in list")

        # range check
        if idx >= nitems:
            raise Exception("out of range err: idx=%s, nitems=%s" % (idx, nelems))

        # ditch the item
        self.items.pop(idx).pack_forget()

        # update display
        self.refresh()

        # try to select neighbouring item
        nitems -= 1
        if idx == nitems:
            if idx > 0:
                self.selectItem(idx-1)
        else:
            self.selectItem(idx)
    
    
    def insert(self, idx, item):
        """
        Inserts an item at an arbitrary position within the list

        Arguments:
            - idx - index at which to insert the item, or -1 to append to end
            - item - the item to insert - must be instance of WidgetListBoxItem or subclass

        Returns:
            - the item appended, for your convenience, to let you use this method 'on the fly'
        """
        nelems = len(self.items)
        if idx == -1:
            idx = nelems
        if idx > nelems or idx < 0:
            raise Exception("out of range err: idx=%s, nitems=%s" % (idx, len(self.widgets)))

        if not isinstance(item, WidgetListBoxItem):
            raise Exception("Item must be an instance of WidgetListBoxItem or subclass")

        #self.setItemBindings(item)

        if idx == nelems:
            # trivial - just append
            self.items.append(item)
            self.itemPackAndBind(item)
        else:
            # Stick this item in the list
            self.items.insert(idx, item)

        # update display
        # no need for refresh() to unpack everything - we've already done it
        self.refresh(clear=0)

        return item

    
    
    def selectItem(self, item):
        """
        Selects one item

        Arguments:
            - item - either an index on the list, or a ref to one of the items on the list.
              Set to -1 to deselect all
        """
        nitems = len(self.items)
        if type(item) == type(0):
            if item < 0:
                if self.selected:
                    self.selected.setselected(0)
                    return
            elif item >= nitems:
                raise Exception("range error: item=%s, nitems=%s" % (item, nitems))
            else:
                item = self.items[item]

        if not isinstance(item, WidgetListBoxItem):
            raise Exception("Expected index or WidgetListBoxItem object, got a %s" % item.__class__)

        item.setselected(1)
    
    
    def getItemIndex(self, item):
        """
        Returns the 'index' with which the item is
        internally stored, or -1 if the item isn't known
        """
        try:
            return self.items.index(item)
        except:
            raise Exception("Item not present on list")
    
    
    def refresh(self, clear=1):

        """
        Remove all items from display, sort the display, add items
        back to display.

        Setting the arg 'clear' to 0 means don't do a pack_forget() on each
        of the items - this is only done from setlist()
        """
        if clear:
            # ditch existing items
            i = 0
            nitems = len(self.items)
            while i < nitems:
                self.items[i].pack_forget()
                i += 1

        # sort items if needed
        self.items.sort(self.compare)

        # and filter to the ones we need to show
        self.showItems = filter(self.filter, self.items)

        # pack and bind new items
        for item in self.showItems:
            self.itemPackAndBind(item)

        #print "trying to refresh WidgetListBox"
        self.reposition()
    
    
    
    def on_click(self, ev):
        """
        Callback for mouse click events.
        You likely won't need to override this.
        """
        #print "got click on widget: %s" % ev.widget.__class__
        wid = ev.widget
        wid.setselected(1)

    
    
    def on_down(self, ev):
        """
        Callback for 'Down' key events.
        You likely won't need to override this.
        """
        # sanity check - can't move past bottom
        if not self.selected:
            return

        wid = ev.widget
        try:
            idx = self.showItems.index(wid)
        except:
            try:
                idx = self.items.index(wid)
            except:
                idx = 0
        #except:
        #    idx = self.showItems.index(wid.parent)
        if idx < len(self.showItems) - 1:
            self.showItems[idx+1].setselected(1)

        self.scrollTo(idx)
    
    
    def on_up(self, ev):
        """
        Callback for 'Up' key events.
        You likely won't need to override this.
        """
        # sanity check - can't move past top
        if not self.selected:
            return

        wid = ev.widget
        try:
            idx = self.showItems.index(wid)
        except:
            try:
                idx = self.items.index(wid)
            except:
                idx = 0
        #except:
        #    idx = self.showItems.index(wid.parent)
        if idx > 0:
            self.showItems[idx-1].setselected(1)

        self.scrollTo(idx)


    
    
    def scrollTo(self, idx):
        #print "scrollTo"
        self.yview('moveto', float(idx-3)/len(self.items))


    
    
    def scrollUp(self, ev=None):
        #print "scrollUp"
        self.yview('scroll', -0.33, 'pages')

    
    
    def scrollUpPage(self, ev=None):
        #print "scrollUpPage"
        self.yview('scroll', -0.8, 'pages')

    
    
    def scrollDown(self, ev=None):
        #print "scrollDown"
        self.yview('scroll', 0.33, 'pages')

    
    
    def scrollLeft(self, ev=None):
        #print "scrollLeft"
        self.xview('scroll', -0.33, 'pages')

    
    
    def scrollRight(self, ev=None):
        #print "scrollRight"
        self.xview('scroll', 0.33, 'pages')

    
    
    def scrollDownPage(self, ev=None):
        #print "scrollDownPage"
        self.yview('scroll', 0.8, 'pages')

    
    
    def itemPackAndBind(self, item):
        """
        Pack the item and set its bindings
        """
        #print "itemPackAndBind: item=%s" % item.__class__
        #print "isinstance=%s" % isinstance(item, WidgetListBoxItem)

        if isinstance(item, WidgetListBoxItem):
            for wid in item.widgets:
                #print "packing item: %s" % wid.__class__
                self.itemPackAndBind(wid)
            item.pack(side=TOP, fill='x', expand=1, anchor='w')
        else:
            pass
            item.pack(side=LEFT, anchor=NE)

        noBind = getattr(item, "noBind", [])

        #print "noBind = %s" % noBind

        for evtype, action in {'<Button-1>' : self.on_click,
                               '<Down>'     : self.on_down,
                               '<Up>'       : self.on_up,
                               '<Button-4>' : self.scrollUp,
                               '<Button-5>' : self.scrollDown,
                               '<Next>'     : self.scrollDownPage,
                               '<Prior>'    : self.scrollUpPage,
                               '<Right>'    : self.scrollRight,
                               '<Left>'     : self.scrollLeft,
                               }.items():
            if evtype not in noBind:
                item.bind(evtype, action)


    
    
    def compare(self, item1, item2):
        """
        You should override this method so that you can have
        your listbox presenting its items in desired order
        """
        if item1 < item2:
            return -1
        elif item1 > item2:
            return 1
        else:
            return 0
    
    
    def filter(self, item):
        """
        Used when filtering the view

        You should override this if you want filtering, with your method returning
        1 if a given item should appear on the display
        """
        return 1
    
    



class ClsListBoxItem(WidgetListBoxItem):

    
    
    def __init__(self, parent, iface, cls, **kw):

        WidgetListBoxItem.__init__(self, parent,
                                   bg=theme.listBgColor,
                                   fg=theme.listFgColor,
                                   bgsel=theme.listSelBgColor,
                                   fgsel=theme.listSelFgColor,
                                   border=1,
                                   )
        self.config(
            borderwidth=1,
            highlightthickness=1,
            highlightcolor=theme.listFgColor,
            highlightbackground=theme.listFgColor,
            )

        gui = kw['gui']

        # flag turns guages on/off
        showGuages = False

        self.iface = iface
        self.cls = cls
        clsNameWidth = takeKey(kw, 'clsNameWidth', 6)

        # add cls name label
        self.labName = myLabel(
            self,
            text=self.iface.name+"."+self.cls.name,
            #bg='green',
            activebackground=theme.myFgColor,
            activeforeground=theme.myBgColor,
            justify=LEFT,
            anchor=W,
            width=clsNameWidth,
            )

        #self.addwidget(self.labName, nobind=[])
        #self.labSvcName.config(justify=LEFT)
        self.labName.pack(side=LEFT, anchor=NW, fill=Y, expand=1)

        # frame for ingress and egress widgets
        frmInOut = self.frmInOut = myFrame(self)
        frmInOut.pack(side=LEFT, fill=X, expand=1)
        #self.addwidget(frmInOut)

        # ingress frame
        frmIn = self.frmIn = myFrame(frmInOut)
        frmIn.pack(side=TOP, fill=X, expand=1)

        labIn = myLabel(frmIn, text="RX(max): ", width=8, justify=LEFT)
        labIn.pack(side=LEFT, anchor=W)

        # add counter for incoming
        s = self.cntIn = myCounter(
            frmIn,
            entry_width=4,
            entryfield_value=int(cls.bwIn),
            entryfield_validate = { 'validator':'integer', 'min':1, 'max':int(iface.bwIn)},
            command=gui.on_changeValue,
            )
        s.pack(side=LEFT)
        #self.addwidget(s)

        if showGuages:
            # add guages for incoming - moving average 5 and 25
            frmInGuages = myFrame(frmIn)
            frmInGuages.pack(side=LEFT, anchor=SW)
            self.guaInMA25 = myProgressBar(
                frmInGuages,
                width=60,
                height=8,
                doLabel=0,
                value=60,
                fillColor='green',
                )
            self.guaInMA25.frame.pack(side=BOTTOM)
            self.guaInMA5 = myProgressBar(
                frmInGuages,
                width=60,
                height=8,
                doLabel=0,
                value=50,
                fillColor='green',
                )
            self.guaInMA5.frame.pack(side=BOTTOM)
        else:
            self.labRateIn = myLabel(frmIn, text='')
            self.labRateIn.pack(side=LEFT, anchor=W, fill=X, expand=1)
            #self.labRateIn.pack(side=RIGHT, anchor=SE)

        # egress frame
        frmOut = self.frmOut = myFrame(frmInOut)
        frmOut.pack(side=TOP, fill=X, expand=1)

        frmOutG = myFrame(frmOut)
        frmOutG.pack(side=LEFT, fill=X, expand=1)

        labOutMin = myLabel(frmOutG, text="TX(min):", width=8, justify=LEFT)
        labOutMin.grid(row=0, column=0)
        labOutMax = myLabel(frmOutG, text="TX(max):", width=8, justify=LEFT)
        labOutMax.grid(row=1, column=0)

        # add counters for outgoing min/max
        s = self.cntOutMin = myCounter(
            frmOutG,
            entry_width=4,
            entryfield_value=int(cls.bwOutRate),
            entryfield_validate = { 'validator':'integer', 'min':1, 'max':int(iface.bwOut)},
            command=gui.on_changeValue,
            )
        s.grid(row=0, column=1)

        s = self.cntOutMax = myCounter(
            frmOutG,
            entry_width=4,
            entryfield_value=int(cls.bwOutCeil),
            entryfield_validate = { 'validator':'integer', 'min':1, 'max':int(iface.bwOut)},
            command=gui.on_changeValue,
            )
        s.grid(row=1, column=1)

        # add guages for outgoing - moving average 5 and 25
        if showGuages:
            frmOutGuages = myFrame(frmOut)
            frmOutGuages.pack(side=LEFT, anchor=NW)
            self.guaOutMA5 = myProgressBar(
                frmOutGuages,
                width=60,
                height=8,
                doLabel=0,
                value=50,
                fillColor='red',
                )
            self.guaOutMA5.frame.pack(side=TOP)
            self.guaOutMA25 = myProgressBar(
                frmOutGuages,
                width=60,
                height=8,
                doLabel=0,
                value=60,
                fillColor='red',
                )
            self.guaOutMA25.frame.pack(side=TOP)
        else:
            self.labRateOut = myLabel(frmOut, text='')
            self.labRateOut.pack(side=LEFT, anchor=W, fill=X, expand=1)
            #self.labRateOut.configure(bg='blue')




    
    
    def setcolor(self, state):
        """
        Sets the background of all items on this widget to color

        Override this in your subclass
        """
        if state == 'select':
            #fgcolor = self.fg
            #bgcolor = self.bg
            fgcolor = self.fgsel
            bgcolor = self.bgsel
            #print "setting color to %s" % color
        elif state == 'deselect':
            fgcolor = self.fg
            bgcolor = self.bg
        else:
            #print "color=%s" % color
            fgcolor = "#00ff00"
            bgcolor = "#ffe040"
        self.configure(bg=bgcolor)

        if 0:
            for wid in self.widgets:
                wid.configure(background=bgcolor)
                try:
                    wid.configure(fg=fgcolor)
                except:
                    traceback.print_exc()

        if state == 'select':
            color = self.bgsel
            #print "setting color to %s" % color
        elif state == 'deselect':
            color = self.bg
        else:
            #print "color=%s" % color
            #color = "#ffe040"
            color = "black"
        self.configure(bg=color)
        for wid in self.widgets:
            #if wid == self.labSvcName:
            wid.configure(background=color)
            #else:
            #    wid.configure(background='green')
    
    
    def refresh(self):
        """
        Call this if you update the data cell.
        This propagates the change to the item's widgets
        """
        #print "WARNING: WidgetListItem.refresh() - you should subclass this"

    
    
    def refreshRate(self):

        #print "refreshRate: %s" % self.iface.name+"."+self.cls.name
        #return

        cls = self.cls

        # mad-assed kludge - feed in some 'null' packets to cls to flush out the
        # class' history
        cls.on_packet(0, 0, 0, 0, 0)

        #if cls.name == 'httpout' and cls.silly != 'xxx':
        #    print "%s.%s: rate = %s b/s in, %s b/s out, %s" % (
        #        cls.parent.name, cls.name, cls.rateIn, cls.rateOut, cls.silly)

        self.labRateIn.config(text="%16.2f" % (cls.rateIn / 128))
        self.labRateOut.config(text="%16.2f" % (cls.rateOut / 128))




    
    
    def on_select(self):
        """
        Called whenever this widget is selected, whether through
        mouse or keyboard actions

        Override as desired
        """
        #print "item selected"

    
    
    def on_deselect(self):
        """
        Called whenever this widget is deselected, whether through
        mouse or keyboard actions

        Override as desired
        """
        #print "item deselected"


    
    



class ClsListBox(WidgetListBox):

    
    
    def __init__(self, parent, gui, **kw):

        kw['bg'] = theme.myListBgColor
        WidgetListBox.__init__(self, parent, **kw)
        self.gui = gui
        #self.services = {}
    
    
    def on_select(self, item):
        """
        Callback which gets hit whenever an item gets selected
        """
        #print "SvcListBox.on_select: item=%s, idx=%s" % (item, self.getItemIndex(item))
        #print "SvcListBox.on_select: item=%s" % item.svcName

    
    
    def on_deselect(self, item):
        """
        Callback which gets hit whenever an item gets deselected
        """
        try:
            idx = self.getItemIndex(item)
        except:
            idx = -1
        #print "WidgetListBox.on_deselect: item=%s, idx=%s" % (item, idx)
        #print "SvcListBox.on_deselect: item=%s, idx=%s" % (item, self.getItemIndex(item))

        #print "SvcListBox.on_deselect: item=%s, index=%s" % (item.svcName, idx)


    
    



class theme:

    
    
    myBgColor = "#404040"
    myBgColor1 = "#404040"
    myFgColor = "#ffcc00"
    myListFgColor = myFgColor
    myListBgColor = myBgColor
    mySelColor = "#a000a0"
    myListSelBgColor = "#ffcc00"
    myListSelFgColor = "#000000"
    myFgColorActive = "#ffffff"
    myBgColorActive = "#0000ff"
    myDisabledColor = "#c0c0c0"

    myFont = "helvetica 11"
    myFontHeading = "helvetica 11 bold"

    myFontWindows = "helvetica 8"
    myFontHeadingWindows = "helvetica 10 bold"

    # widget-specific settings

    grpRingColor = myFgColor

    winBgColor = myBgColor
    winFgColor = myFgColor

    menuBgColor = myBgColor
    menuFgColor = myFgColor
    menuFont = myFont
    menuFontWindows = myFontWindows
    menuActiveBgColor = myBgColorActive
    menuActiveFgColor = myFgColorActive

    frmBgColor = myBgColor

    butFont = myFont
    butFontWindows = myFontWindows
    butBgColor = myBgColor
    butFgColor = myFgColor
    butSelColor = mySelColor
    butActiveFgColor = myFgColorActive
    butActiveBgColor = myBgColorActive
    butHighlightColor = myBgColor
    butBoxHighlightColor = myBgColorActive
    butHighlightBgColor = myBgColorActive
    butPadx = 4
    butPady = 2

    tkDisabledFgColor = myDisabledColor
    tkInsBgColor = "#808080"
    tkTroughColor = "#9999ff"

    listBgColor = myBgColor
    listFgColor = myListFgColor
    listSelBgColor = myListSelBgColor
    listSelFgColor = myListSelFgColor
    listFont = myFont
    listFontWindows = myFontWindows

    labBgColor = myBgColor
    labFgColor = myFgColor
    labFont = myFont
    labFontWindows = myFontWindows

    scrlBgColor = myBgColor
    scrlBgActiveColor = myBgColorActive

    chkBgColor = myBgColor
    chkFgColor = myFgColor
    chkFont = myFont
    chkFontWindows = myFontWindows
    #chkSelColor = mySelColor
    chkSelColor = "green"

    chkActiveFgColor = myFgColorActive
    chkActiveBgColor = myBgColorActive

    entrySelColor = mySelColor
    entryBgColor = myBgColor1
    entryFgColor = myFgColor
    entryDisabledFgColor = "#000000"
    entryFont = myFont
    entryFontWindows = myFontWindows

    textBgColor = myBgColor1
    textFgColor = myFgColor
    textFont = myFont
    textFontWindows = myFontWindows
    textFgColor = myFgColor
    textSelBgColor = mySelColor
    textSelFgColor = myFgColor

    cmbBgColor = myBgColor
    cmbFgColor = myFgColor
    cmbSelBgColor = mySelColor
    cmbSelFgColor = myFgColor
    cmbFont = myFont
    cmbFontWindows = myFontWindows

    cntBgColor = myBgColor
    cntFgColor = myFgColor

    radBgColor = myBgColor
    radFgColor = myFgColor
    radFont = myFont
    radFontWindows = myFontWindows
    radSelColor = mySelColor
    radActiveBgColor = myFgColor
    radActiveFgColor = myBgColor

    progbarMyTypingColor = "black"
    progbarPeerTypingColor = "#d0d0d0"
    progbarErrorColor = "red"
    progbarMsgColor = "#C0C000"
    progbarOKColor = "#00C000"
    progbarBgColor = "#d0d0d0"
    progbarFgColor = "#0000ff"
    #progbarVoxSendFgColor = "black"
    #progbarVoxSendBgColor = "#808080"
