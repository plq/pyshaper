#!/usr/bin/env python
#@+leo-ver=4
#@+node:@file pyshaper.py
#@@first
"""
pyshaper - a dynamic traffic-shaper for Linux 2.4-2.6 based systems.

Run epydoc on this file to get reasonably readable API doco

Run this file with the argument 'help' for usage info.

Written in March 2004 by David McNab <david@freenet.org.nz>
Copyright (c) 2004 by David McNab

Released under the terms of the GNU General Public License.

You should have received a file named 'COPYING' with this
program. If not, you can review a copy of the GPL at the
GNU website, at http://gnu.org
"""
#@+others
#@+node:imports
import sys, os, commands, re, traceback, signal, time, stat, StringIO, popen2, sha
import getopt
import thread, threading

# imports for ip2cc
from urllib import urlopen
from socket import inet_aton, inet_ntoa, gethostbyname, gaierror
import struct
#import re
#import sys, os
#from ip2cc import cc2name


# grab GeoIP if available
try:
    import GeoIP
    #GeoIP = None
except:
    GeoIP = None

# import gui stuff, if we can
try:
    from Tkinter import *
    import Pmw
    import tkMessageBox
    from tkFileDialog import askopenfilename, asksaveasfilename
except:
    pass
#@-node:imports
#@+node:globals
# ---------------------------------------------
# Edit these constants if your situation requires it

configDir = "/etc/pyshaper"
configPath = "/etc/pyshaper/pyshaper.conf"

# how long between shaping runs, in seconds
shaperPeriod = 30

# where pyshaper sticks its pidfile
pidfile = "/var/run/pyshaper.pid"

# command we use to discover existing TCP connections
netstatCmd = "netstat -e -e -e -v --inet -p --numeric-ports"

# default verbosity of output messages
verbosity = 2

# -----------------------------------------------------------

version = "0.1.3"

reDelim = re.compile("[ ,:]")
reSpaces = re.compile("\\s+")

# try to create pyshaper dir if nonexistent
if not os.path.isdir(configDir):
    try:
        os.makedirs(configDir)
    except:
        pass
#@-node:globals
#@+node:exceptions
class MatchedConnectionException(Exception): pass
#@-node:exceptions
#@+node:GUI
try:
    #@    @+others
    #@+node:class TShaperGui
    class TShaperGui:
        """
        Displays a GUI to allow users to visualise and edit shaping config
        
        GUI can:
            - launch/stop shaper
            - display/edit shaper config
            - send a SIGHUP to running shaper to make it reload config
        """
        #@    @+others
        #@+node:__init__
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
        
        #@-node:__init__
        #@+node:buildWindow
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
            
        
        
        
        
        
        
        
        
        
        
        
        
        
        #@-node:buildWindow
        #@+node:buildMenu
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
        #@-node:buildMenu
        #@+node:centerWindow
        def centerWindow(self):
        
            root = self.root    
        
            root.update_idletasks()
        
            scrW = root.winfo_screenwidth()
            scrH = root.winfo_screenheight()
        
            w = root.winfo_width()
            h = root.winfo_height()
            
            #print w, h
        
            root.geometry("+%s+%s" % ((scrW - w)/2, (scrH - h)/2))
        #@-node:centerWindow
        #@+node:run
        def run(self):
        
            #print "gui not implemented yet"
        
            self.lastPktTime = time.time()
            self.frmMain.after(100, self.on_startup)
            self.root.mainloop()
        #@-node:run
        #@+node:isRunning
        def isRunning(self):
            """
            Determines whether the daemon is running, returns True/False
            """
            return os.path.isfile(pidfile)
        
        #@-node:isRunning
        #@+node:startDaemon
        def startDaemon(self):
            """
            Launches the daemon
            """
            os.system("pyshaper -V 3 start")
        #@-node:startDaemon
        #@+node:stopDaemon
        def stopDaemon(self):
            """
            Terminates the daemon
            """
            os.system("pyshaper stop")
        #@-node:stopDaemon
        #@+node:restartDaemon
        def restartDaemon(self):
            """
            Terminates the daemon
            """
            os.system("pyshaper reload")
        #@-node:restartDaemon
        #@+node:on_startup
        def on_startup(self):
        
            """
            Callback which gets hit as soon as the gui mainloop is entered
            """
            self.root.geometry("%sx%s" % (self.config.guiWidth, self.config.guiHeight))
            #print "w=%s, h=%s" % (self.config.guiWidth, self.config.guiHeight)
            self.labTraffic.after(1000, self.on_refresh)
        #@-node:on_startup
        #@+node:on_close
        def on_close(self, ev=None):
        
            print "pyshaper gui window closed"
            self.root.destroy()
            sys.exit(0)
        #@-node:on_close
        #@+node:on_paneMainResize
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
        #@-node:on_paneMainResize
        #@+node:on_menuFileQuit
        def on_menuFileQuit(self, ev=None):
        
            self.on_close()
        #@-node:on_menuFileQuit
        #@+node:on_menuHelpAbout
        def on_menuHelpAbout(self, ev=None):
            myMessageBox(
                self.root,
                "About pyshaper",
                "\n".join(["This is pyshaper version %s" % version,
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
        #@-node:on_menuHelpAbout
        #@+node:on_chkRunning
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
        #@-node:on_chkRunning
        #@+node:on_butApplyChanges
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
        
        #@-node:on_butApplyChanges
        #@+node:on_changeValue
        def on_changeValue(self, wid, newval):
        
            print "value changed"
            self.hasChanged = True
            self.butApplyChanges.configure(state=NORMAL)
        #@-node:on_changeValue
        #@+node:on_packet
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
        
        
        
        
        
        
        #@-node:on_packet
        #@+node:on_refresh
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
        #@-node:on_refresh
        #@+node:thrdConns
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
                                            raise MatchedConnectionException # bail out to uppermost loop
                
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
            
        
        #@-node:thrdConns
        #@-others
    #@-node:class TShaperGui
    #@+node:class myMenu
    class myMenu(Menu):
        #@    @+others
        #@+node:__init__
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
        #@-node:__init__
        #@+node:add_cascade
        def add_cascade(self, underline=0, **args):
            Menu.add_cascade(self, underline=0, **args)
        #@-node:add_cascade
        #@+node:add_command
        def add_command(self, underline=0, **args):
            Menu.add_command(self, underline=0, **args)
        #@-node:add_command
        #@+node:addCmd
        def addCmd(self, label, action, shortcut=None, abbrev='', **args):
            self.add_command(label=label,
                             accelerator=abbrev,
                             command=action,
                             **args)
            if shortcut != None:
                self.bind_all("<%s>" % shortcut, action)
            
        #@-node:addCmd
        #@-others
    #@-node:class myMenu
    #@+node:class myPanedWidget
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
    
    #@-node:class myPanedWidget
    #@+node:class myFrame
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
            
    #@-node:class myFrame
    #@+node:class myLabel
    class myLabel(Label):
        #@    @+others
        #@+node:__init__
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
        
        
        #@-node:__init__
        #@-others
    #@-node:class myLabel
    #@+node:class myButton
    
    class myButton(Button):
        #@    @+others
        #@+node:__init__
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
        #@-node:__init__
        #@-others
    #@-node:class myButton
    #@+node:class myCheckbutton
    
    class myCheckbutton(Checkbutton):
        #@    @+others
        #@+node:__init__
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
        
        
        
        #@-node:__init__
        #@-others
    #@-node:class myCheckbutton
    #@+node:class myEntry
    
    class myEntry(Pmw.EntryField):
        #@    @+others
        #@+node:__init__
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
                    
        
        #@-node:__init__
        #@-others
    #@-node:class myEntry
    #@+node:class myComboBox
    class myComboBox(Pmw.ComboBox):
        #@    @+others
        #@+node:__init__
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
        #@-node:__init__
        #@-others
    #@-node:class myComboBox
    #@+node:class myProgressBar
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
    
    
    #@-node:class myProgressBar
    #@+node:class myCounter
    class myCounter(Pmw.Counter):
        """
        A customised 'counter' or 'spinner' widget
        """
        #@    @+others
        #@+node:__init__
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
        
        #@-node:__init__
        #@-others
    #@-node:class myCounter
    #@+node:class myScale
    
    class myScale(Scale):
        #@    @+others
        #@+node:__init__
        def __init__(self, parent, orient='horizontal', **args):
            Scale.__init__(self, parent,
                           #bg="red",
                           orient=orient,
                           **args)
        #@-node:__init__
        #@-others
    #@-node:class myScale
    #@+node:def myMessageBox
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
    
    
    
    #@-node:def myMessageBox
    #@+node:class WidgetListBoxItem
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
        #@    @+others
        #@+node:__init__
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
        #@-node:__init__
        #@+node:setselected
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
        #@-node:setselected
        #@+node:setcolor
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
        
        
        
        #@-node:setcolor
        #@+node:addwidget
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
        
        #@-node:addwidget
        #@+node:refresh
        def refresh(self):
            """
            Call this if you update the data cell.
            This propagates the change to the item's widgets
            """
            #print "WARNING: WidgetListItem.refresh() - you should subclass this"
        
        #@-node:refresh
        #@+node:on_select
        def on_select(self):
            """
            Called whenever this widget is selected, whether through
            mouse or keyboard actions
            
            Override as desired
            """
            #print "item selected"
        
        #@-node:on_select
        #@+node:on_deselect
        def on_deselect(self):
            """
            Called whenever this widget is deselected, whether through
            mouse or keyboard actions
            
            Override as desired
            """
            #print "item deselected"
        
        
        #@-node:on_deselect
        #@-others
    #@-node:class WidgetListBoxItem
    #@+node:class WidgetListBox
    class WidgetListBox(Pmw.ScrolledFrame):
        """
        Base bits of the WidgetListBox* classes
        """
        #@    @+others
        #@+node:__init__
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
        
        
        
        #@-node:__init__
        #@+node:clear
        def clear(self):
            self.setlist(())
            self.refresh()
        #@-node:clear
        #@+node:get
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
        
                    
        #@nonl
        #@-node:get
        #@+node:getcurselection
        def getcurselection(self):
            """
            See getvalue()
            """
            return self.getvalue()
        #@-node:getcurselection
        #@+node:getvalue
        def getvalue(self):
            """
            Returns a list of the currently selected items
            """
            if self.selected:
                return [self.selected]
            else:
                return []
        #@-node:getvalue
        #@+node:setlist
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
        #@-node:setlist
        #@+node:setvalue
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
        #@-node:setvalue
        #@+node:size
        def size(self):
            """
            Returns the number of items in the list
            """
            return len(self.items)
        #@-node:size
        #@+node:on_select
        def on_select(self, item):
            """
            Callback which gets hit whenever an item gets selected
            
            Override as desired
            """
            #print "WidgetListBox.on_select: item=%s, idx=%s" % (item, self.getItemIndex(item))
        
        #@-node:on_select
        #@+node:on_deselect
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
        
        #@-node:on_deselect
        #@+node:append
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
        
        #@-node:append
        #@+node:delete
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
        #@-node:delete
        #@+node:insert
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
        
        #@-node:insert
        #@+node:selectItem
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
        #@-node:selectItem
        #@+node:getItemIndex
        def getItemIndex(self, item):
            """
            Returns the 'index' with which the item is
            internally stored, or -1 if the item isn't known
            """
            try:
                return self.items.index(item)
            except:
                raise Exception("Item not present on list")
        #@-node:getItemIndex
        #@+node:refresh
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
        #@nonl
        #@-node:refresh
        #@+node:on_click
        def on_click(self, ev):
            """
            Callback for mouse click events.
            You likely won't need to override this.
            """
            #print "got click on widget: %s" % ev.widget.__class__
            wid = ev.widget
            wid.setselected(1)
        
        #@-node:on_click
        #@+node:on_down
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
        #@-node:on_down
        #@+node:on_up
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
        
        
        #@-node:on_up
        #@+node:scrollTo
        def scrollTo(self, idx):
            #print "scrollTo"
            self.yview('moveto', float(idx-3)/len(self.items))
        
        
        #@-node:scrollTo
        #@+node:scrollUp
        def scrollUp(self, ev=None):
            #print "scrollUp"
            self.yview('scroll', -0.33, 'pages')
        
        #@-node:scrollUp
        #@+node:scrollUpPage
        def scrollUpPage(self, ev=None):
            #print "scrollUpPage"
            self.yview('scroll', -0.8, 'pages')
        
        #@-node:scrollUpPage
        #@+node:scrollDown
        def scrollDown(self, ev=None):
            #print "scrollDown"
            self.yview('scroll', 0.33, 'pages')
        
        #@-node:scrollDown
        #@+node:scrollLeft
        def scrollLeft(self, ev=None):
            #print "scrollLeft"
            self.xview('scroll', -0.33, 'pages')
        
        #@-node:scrollLeft
        #@+node:scrollRight
        def scrollRight(self, ev=None):
            #print "scrollRight"
            self.xview('scroll', 0.33, 'pages')
        
        #@-node:scrollRight
        #@+node:scrollDownPage
        def scrollDownPage(self, ev=None):
            #print "scrollDownPage"
            self.yview('scroll', 0.8, 'pages')
        
        #@-node:scrollDownPage
        #@+node:itemPackAndBind
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
        
        
        #@-node:itemPackAndBind
        #@+node:compare
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
        #@-node:compare
        #@+node:filter
        def filter(self, item):
            """
            Used when filtering the view
            
            You should override this if you want filtering, with your method returning
            1 if a given item should appear on the display
            """
            return 1
        #@-node:filter
        #@-others
    
    #@-node:class WidgetListBox
    #@+node:class ClsListBoxItem
    class ClsListBoxItem(WidgetListBoxItem):
    
        #@    @+others
        #@+node:__init__
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
        
        
        
        
        #@-node:__init__
        #@+node:setcolor
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
        #@-node:setcolor
        #@+node:refresh
        def refresh(self):
            """
            Call this if you update the data cell.
            This propagates the change to the item's widgets
            """
            #print "WARNING: WidgetListItem.refresh() - you should subclass this"
        
        #@-node:refresh
        #@+node:refreshRate
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
        
        
        
        
        #@-node:refreshRate
        #@+node:on_select
        def on_select(self):
            """
            Called whenever this widget is selected, whether through
            mouse or keyboard actions
            
            Override as desired
            """
            #print "item selected"
        
        #@-node:on_select
        #@+node:on_deselect
        def on_deselect(self):
            """
            Called whenever this widget is deselected, whether through
            mouse or keyboard actions
            
            Override as desired
            """
            #print "item deselected"
        
        
        #@-node:on_deselect
        #@-others
    
    #@-node:class ClsListBoxItem
    #@+node:class ClsListBox
    class ClsListBox(WidgetListBox):
        
        #@    @+others
        #@+node:__init__
        def __init__(self, parent, gui, **kw):
        
            kw['bg'] = theme.myListBgColor    
            WidgetListBox.__init__(self, parent, **kw)
            self.gui = gui
            #self.services = {}
        #@-node:__init__
        #@+node:on_select
        def on_select(self, item):
            """
            Callback which gets hit whenever an item gets selected
            """
            #print "SvcListBox.on_select: item=%s, idx=%s" % (item, self.getItemIndex(item))
            #print "SvcListBox.on_select: item=%s" % item.svcName
        
        #@-node:on_select
        #@+node:on_deselect
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
        
        
        #@-node:on_deselect
        #@-others
    
    #@-node:class ClsListBox
    #@+node:class theme
    class theme:
        
        #@    @+others
        #@+node:theme attributes
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
        
        #@-node:theme attributes
        #@-others
    #@-node:class theme
    #@-others
except:
    traceback.print_exc()
    pass
#@-node:GUI
#@+node:class IPmon
class IPmon:
    #@	@+others
    #@+node:__init__
    def __init__(self, handler=None):
    
        if not handler:
            handler = self.defaultHandler
        self.handler = handler
    
        self.conns = {}
    #@-node:__init__
    #@+node:run
    def run(self):
    
        reSpaces = re.compile("\\s+")
        tOut, tIn = popen2.popen2("tcpdump -vnl", 1024)
    
        while 1:
            try:
                line = line0 = tOut.readline().strip()
    
                #print line
                #continue
    
                line = reSpaces.split(line, 1)[1]
    
                if line.startswith("arp"):
                    continue
    
                try:
                    addrs, rest = line.split(":", 1)
                except:
                    continue
        
                addrs = addrs.strip()
                src, dst = addrs.split(" > ")
        
                # print "src=%s dst=%s" % (repr(src), repr(dst))
    
                srcbits = src.split(".")
                src = ".".join(srcbits[:4])
                if len(srcbits) == 5:
                    sport = int(srcbits[-1])
                else:
                    sport = 0
        
                dstbits = dst.split(".")
                dst = ".".join(dstbits[:4])
                if len(dstbits) == 5:
                    dport = int(dstbits[-1])
                else:
                    dport = 0
    
                pktlen = int(rest[:-1].split(" ")[-1])
        
                # print "---------------------------"
                # print line
    
                k = '%s:%s>%s:%s' % (src,sport,dst,dport)
                conns = self.conns
                if not conns.has_key(k):
                    conns[k] = 0
                conns[k] += pktlen
                
    
                pkt = {'src':src, 'sport':sport,
                       'dst':dst, 'dport':dport,
                       'len':pktlen, 'total':conns[k]}
                #print "IPmon: pkt=%s" % pkt
                self.handler(pkt)
    
            except KeyboardInterrupt:
                print "IPmon: got kbd int"
                return
    
            except:
                #traceback.print_exc()
                #print "IPmon exception"
                #print line0
                pass
    
    
    
    
    
    
    #@-node:run
    #@+node:runPcap
    def runPcap(self):
    
        p = pcap.pcapObject()
        dev = "eth0"
    
        net, mask = pcap.lookupnet(dev)
        # note:  to_ms does nothing on linux
        p.open_live(dev, 1600, 0, 100)
        # p.dump_open('dumpfile')
    
        #p.setfilter(string.join(sys.argv[2:],' '), 0, 0)
    
        # try-except block to catch keyboard interrupt.  Failure to shut
        # down cleanly can result in the interface not being taken out of promisc.
        # mode
        # p.setnonblock(1)
        while 1:
            try:
                p.dispatch(1, self.pcapCallback)
            except KeyboardInterrupt:
                print '%s' % sys.exc_type
                print 'shutting down'
                print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
                return
            except:
                traceback.print_exc()
    #@-node:runPcap
    #@+node:pcapCallback
    def pcapCallback(self, pktlen, data, timestamp):
    
        if not data:
            return
    
        if data[12:14]=='\x08\x00':
            decoded = self.pcapDecode(data[14:])
            print '\n%s.%f %s > %s' % (time.strftime('%H:%M',
                                                     time.localtime(timestamp)),
                                       timestamp % 60,
                                       decoded['source_address'],
                                       decoded['destination_address'])
            for key in ['version', 'header_len', 'tos', 'total_len', 'id',
                        'flags', 'fragment_offset', 'ttl']:
                print '  %s: %d' % (key, decoded[key])
    #@-node:pcapCallback
    #@+node:pcapDecode
    def pcapDecode(self, s):
    
        d={}
        d['version']=(ord(s[0]) & 0xf0) >> 4
        d['header_len']=ord(s[0]) & 0x0f
        d['tos']=ord(s[1])
        d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
        d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
        d['flags']=(ord(s[6]) & 0xe0) >> 5
        d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
        d['ttl']=ord(s[8])
        d['protocol']=ord(s[9])
        d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
        d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
        d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
        if d['header_len']>5:
            d['options']=s[20:4*(d['header_len']-5)]
        else:
            d['options']=None
        d['data']=s[4*d['header_len']:]
        return d
    #@-node:pcapDecode
    #@+node:defaultHandler
    def defaultHandler(self, pkt):
    
        print "%s:%s => %s:%s %s %s" % (pkt['src'], pkt['sport'],
                                     pkt['dst'], pkt['dport'],
                                     pkt['len'], pkt['total'])
    #@-node:defaultHandler
    #@-others
#@-node:class IPmon
#@+node:class TShaper
class TShaper:
    """
    Implements tc-based traffic shaping
    """
    #@    @+others
    #@+node:attribs
    dir = configDir
    configPath = configPath
    
    shaperPeriod = shaperPeriod # do a shaping run every few seconds
    
    debug = False
    verbosity = verbosity
    
    #@-node:attribs
    #@+node:__init__
    def __init__(self, *args, **kw):
    
        # ensure we are root
        if os.getuid() != 0:
            raise Exception("You must be root to run this program")
    
        # reload sentinel
        self.reloadFlag = False
    
        # load initial config
        self.config = ShaperConfig(os.environ.get("PYSHAPERCONFIG", None))
        self.shaperPeriod = self.config.shaperPeriod
    
        self.verbosity = kw.get('verbosity', self.verbosity)
        self.debug = kw.get('debug', self.debug)
    
        # set up 'queue' of commands to execute, if not verbose
        if not self.debug:
            self.cmdq = []
            self.cmdBuf = ''
            self.cmdBufOld = ''
            self.cmdBufHash = ''
            self.cmdBufHashOld = ''
    
    
    #@-node:__init__
    #@+node:run
    def run(self):
        """
        Sits in a loop, periodically examining the current
        connections, applying user-given rules, and issuing
        shaping commands
        """
        # terminate sentinel
        self.quitFlag = False
    
        # reload sentinel
        self.reloadFlag = False
    
        # check for existing instance
        if os.path.isfile(pidfile):
            print "pyshaper pid file %s exists, pyshaper is likely running" % pidfile
            print "If you are sure pyshaper is not running, delete this"
            print "file and try again"
            sys.exit(1)
    
        #print self.config
    
        # create pidfile
        file(pidfile, "w").write(str(os.getpid()))
    
        # enable signal handler
        signal.signal(signal.SIGQUIT, self.sigHandler)
        signal.signal(signal.SIGHUP, self.sigHandler)
        signal.signal(signal.SIGTERM, self.sigHandler)
    
        self.log(2, "version %s now running on %s second cycle..." % (
            version, self.config.shaperPeriod))
    
        try:
            while not self.quitFlag:
    
                # do a run of shaping
                self.setupShaping()
                
                # wait a bit
                i = 0
                while i < self.shaperPeriod:
                    # reload config if needed
                    if self.reloadFlag:
                        self.log(2, "RELOADING CONFIG")
                        self.config.load()
                        self.shaperPeriod = self.config.shaperPeriod
                        self.reloadFlag = False
                        break
                    if self.quitFlag:
                        break
                    time.sleep(1)
                    i += 1
            
        except KeyboardInterrupt:
            # user pressed control-C - remove shaping
            print "Shaping terminated by keyboard interrupt"
    
        except:
            traceback.print_exc()
            print "pyshaper terminated"
    
        else:
            # quit flag got set
            print "Shaping terminated by kill signal"
    
        self.terminateShaping(immediate=True)
        try:
            os.unlink(pidfile)
        except:
            pass
    #@-node:run
    #@+node:sigHandler
    def sigHandler(self, signum, frame):
        
        if signum in [signal.SIGQUIT, signal.SIGTERM]:
            self.quitFlag = True
        elif signum == signal.SIGHUP:
            self.reloadFlag = True
    #@-node:sigHandler
    #@+node:setupShaping
    def setupShaping(self):
        """
        Generates and executes actual tc shaping commands,
        according to current setup
        """
        # get table of current connections
        self.currentConns = TCPConns()
    
        #self.currentConns.dump()
    
        # set up the dynamic shaping
        self.setupDynamic()
    
    #@-node:setupShaping
    #@+node:setupDynamic
    def setupDynamic(self):
        """
        Creates/runs rules for dynamic (current-connection-based) shaping
        as configured.
        """
        # start the minor class ids at 100
        next_clsid = 100
        
        self.log(3, "---------- setupDynamic: start ------------")
    
        # first pass - backup connections lists, sort classes into static and dynamic
        for iface in self.config.interfaces:
            for cls in iface.classes:
                cls.oldconns = cls.conns
                cls.conns = []
            iface.default.oldconns = iface.default.conns
            iface.default.conns = []
    
            iface.staticClasses = filter(lambda c:c.mode == 'static', iface.classes)
    
        # second pass - classify all connections
        for conn in self.currentConns:
            #print conn.laddr, conn.lport, conn.raddr, conn.rport
            try:
                localip = conn.laddr
                
                # match against each rule
                for iface in self.config.interfaces:
                    # ditch connections that aren't on this interface
                    if iface.ipaddr != localip:
                        continue
    
                    # ignore connection if it matches a static class
                    for cls in iface.staticClasses:
                        if cls.matches(conn):
                            raise MatchedConnectionException
    
                    # try to match against all classes
                    for cls in iface.classes:
                        if cls.matches(conn):
                            self.log(3, "MATCH:\n  %s\n  %s" % (
                                str(conn), str(cls).replace("\n", "\n    ")))
                            cls.conns.append(conn)
                            raise MatchedConnectionException # bail out to uppermost loop
                    # no rule found for conn, add to default
                    iface.default.conns.append(conn)
                    break # quicker than raising exception
    
            except MatchedConnectionException:
                pass
    
        # third pass - generate/execute shaping commands
        for iface in self.config.interfaces:
            dev = iface.name
    
            # clear out dev
            self.tcResetDev(dev)
    
            # basic interface setup
            self.tcAddQdisc(dev, "root handle 1: htb default 1000")
            self.tcAddClassHtb(dev=dev, parent="1:", classid="1:1", pri=1, rate=iface.bwOut)
            self.tcAddQdisc(dev, "ingress handle ffff:")
        
            nextCls = 100
    
            # set up shaping for each class
            for cls in iface.classes:
                nextCls += 1
    
                # bail if not static and no matching rules
                if cls.mode != 'static' and not cls.conns:
                    continue
    
                # we have either static and/or dynamic defs
    
                # create an htb class with sfq
                self.tcAddHtbAndSfq(
                    dev=dev,
                    parent="1:1",
                    classid="1:%s" % nextCls,
                    handle="%s:" % nextCls,
                    pri=cls.pri,
                    rate=cls.bwOutRate,
                    ceil=cls.bwOutCeil,
                    )
    
                if cls.mode == 'static':
                    # add egress filter
                    matches = []
                    if cls.raddr:
                        matches.append("dst %s" % cls.raddr)
                    if cls.rport:
                        matches.append("dport %s 0xffff" % cls.rport)
                    if cls.lport:
                        matches.append("src %s" % iface.ipaddr)
                        matches.append("sport %s 0xffff" % cls.lport)
        
                    self.tcAddFilterOut(
                        dev=dev,
                        parent="1:",
                        flowid="1:%s" % nextCls,
                        pri=cls.pri,
                        matches=matches
                        )
        
                    # add ingress policer
                    matches = []
                    if cls.raddr:
                        matches.append("src %s" % cls.raddr)
                    if cls.rport:
                        matches.append("sport %s 0xffff" % cls.rport)
                    if cls.lport:
                        matches.append("dst %s" % iface.ipaddr)
                        matches.append("dport %s 0xffff" % cls.lport)
        
                    self.tcAddFilterIngressPolice(
                        dev=dev,
                        rate=cls.bwIn,
                        pri=cls.pri,
                        flowid=nextCls,
                        matches=matches,
                        index=nextCls,
                        )
    
                # set up dynamic rules, if current conns match
                if cls.conns:
    
                    # put the connections into a deterministic order
                    cls.sortConnections()
        
                    # split up input bandwidth evenly amongst each connection
                    bwInPerConn = float(cls.bwIn) / len(cls.conns)
        
                    for conn in cls.conns:
        
                        self.log(4, "%s.%s" % (dev, cls.name))
        
                        # add egress filter
                        self.tcAddFilterOut(
                            dev=dev,
                            parent="1:",
                            flowid="1:%s" % nextCls,
                            pri=cls.pri,
                            matches=[
                                "src %s" % conn.laddr,
                                "sport %s 0xffff" % conn.lport,
                                "dst %s" % conn.raddr,
                                "dport %s 0xffff" % conn.rport,
                                ],
                            )
        
                        # add ingress policer
                        self.tcAddFilterIngressPolice(
                            dev=dev,
                            rate=bwInPerConn,
                            pri=cls.pri,
                            flowid=nextCls,
                            matches=[
                                "src %s" % conn.raddr,
                                "sport %s 0xffff" % conn.rport,
                                "dst %s" % conn.laddr,
                                "dport %s 0xffff" % conn.lport,
                                ],
                            index=nextCls,
                            )
    
            # set up interface default
            self.log(4, "DEFAULT for %s" % dev)
            default = iface.default
            self.tcAddHtbAndSfq(
                dev=dev, parent="1:1", classid="1:1000", handle="1000:",
                pri=default.pri, rate=default.bwOutRate, ceil=default.bwOutCeil)
    
            #self.tcAddFilterOut(
            #    dev=dev, parent="1:", flowid="1:1000",
            #    pri=default.pri, matches=["dst 0.0.0.0/0"])
            self.log(4, "DONE DEFAULT for %s" % dev)
    
            # if non-verbose, then we've got a shitload of commands to execute
            # and we need to pipe them in bulk to a shell
            if not self.debug:
                self.runCmdQ()
    #@nonl
    #@-node:setupDynamic
    #@+node:runCmdQ
    def runCmdQ(self):
    
        # build a single string out of all the queued cmds
        self.cmdBuf = "\n".join(self.cmdq)+"\n"
        self.cmdBufHash = sha.new(self.cmdBuf).hexdigest()
        self.cmdq = []
    
        # bail if the command set hasn't changed
        self.log(4, "oldCmdBuf=%s" % self.cmdBufHashOld)
        self.log(4, "newCmdBuf=%s" % self.cmdBufHash)
    
        if self.cmdBuf == self.cmdBufOld:
            self.log(3, "runCmdQ: no change to tc command set - bailing")
            return
        if self.cmdBufOld != '':
            self.log(2, "connections have changed, rebuilding qdiscs")
    
        # fire off the commands to a shell child proc
        shOut, shIn = popen2.popen4("/bin/sh")
        shIn.write(self.cmdBuf)
        shIn.close()
        out = shOut.read()
        shOut.close()
    
        # save the command buf for future comparison
        self.cmdBufOld = self.cmdBuf
    
        # for debugging
        self.log(3, "SCRIPT:\n%sOUT:\n%s" % (self.cmdBuf, out))
    #@-node:runCmdQ
    #@+node:terminateShaping
    def terminateShaping(self, immediate=False):
        """clean existing down- and uplink qdiscs, hide errors"""
        #tc = self.tc
    
        for iface in self.config.interfaces:
            self.tcResetDev(iface.name, immediate=immediate)
            
        #tc("qdisc del DEV root")
        #tc("qdisc del DEV ingress")
    
    #@-node:terminateShaping
    #@+node:status
    def status(self):
    
        tc = self.tc
        DEV = self.dev
    
        raw = tc("-s qdisc ls DEV") + tc("-s class ls DEV")
        return raw
    #@-node:status
    #@+node:tc
    def tc(self, cmd, **kw):
        #cmd = "tc "+(cmd.replace("DEV", "dev "+self.dev))
        cmd = "tc "+cmd
    
        # creating a queue of commands
        self.cmdq.append(cmd)
    
        # in debug mode, we execute commands and report their results one at a time
        if self.debug or kw.get('immediate', False):
            self.log(3, cmd)
            res = commands.getoutput(cmd)
            if res:
                self.log(3, res)
            return res
    #@-node:tc
    #@+node:tcResetDev
    def tcResetDev(self, dev, immediate=False):
        
        tcDelQdisc = self.tcDelQdisc
    
        tcDelQdisc(dev, "root", immediate=immediate)
        tcDelQdisc(dev, "ingress", immediate=immediate)
    #@-node:tcResetDev
    #@+node:tcDelQdisc
    def tcDelQdisc(self, dev, name, immediate=False):
        
        self.tc("qdisc del dev %s %s" % (dev, name), immediate=immediate)
    #@-node:tcDelQdisc
    #@+node:tcAddQdisc
    def tcAddQdisc(self, dev, *args):
    
        self.tc("qdisc add dev %s %s" % (dev, " ".join(args)))
    
    
    #@-node:tcAddQdisc
    #@+node:tcAddQdiscSfq
    def tcAddQdiscSfq(self, dev, parent, handle, perturb=10):
    
        self.tcAddQdisc(dev, "parent %s handle %s sfq perturb %s" % (parent, handle, perturb))
    
    #@-node:tcAddQdiscSfq
    #@+node:tcAddClass
    def tcAddClass(self, dev, *args):
    
        self.tc("class add dev %s %s" % (dev, " ".join(args)))
    
    
    #@-node:tcAddClass
    #@+node:tcAddClassHtb
    def tcAddClassHtb(self, dev, parent, classid, pri, rate, ceil=None):
    
        if ceil:
            self.tcAddClass(
                dev,
                "parent %s classid %s htb rate %s ceil %s burst 6k prio %s" % (
                    parent, classid, int(rate * 1024), int(ceil * 1024), pri)
                )
        else:
            self.tcAddClass(
                dev,
                "parent %s classid %s htb rate %s burst 6k prio %s" % (
                    parent, classid, int(rate * 1024), pri)
                )
    
    #@-node:tcAddClassHtb
    #@+node:tcAddHtbAndSfq
    def tcAddHtbAndSfq(self, dev, parent, classid, handle, pri, rate, ceil=None):
    
        if not ceil:
            ceil = self.config.interfaces[dev].bwOut
    
        self.tcAddClassHtb(dev=dev, parent=parent, classid=classid, pri=pri, rate=rate, ceil=ceil)
        self.tcAddQdiscSfq(dev=dev, parent=classid, handle=handle)
    #@-node:tcAddHtbAndSfq
    #@+node:tcAddFilter
    def tcAddFilter(self, dev, *args):
    
        self.tc("filter add dev %s %s" % (dev, " ".join(args)))
    
    
    #@-node:tcAddFilter
    #@+node:tcAddFilterOut
    def tcAddFilterOut(self, dev, parent, flowid, pri, matches):
    
        self.tcAddFilter(
            dev,
            "parent %s" % parent,
            "protocol ip prio %s u32" % pri,
            " ".join(["match ip "+m for m in matches]),
            "flowid %s" % flowid,
            )
    
        #tcAddFilter(self.dev, "parent 1: protocol ip prio 18 u32 match ip dst 0.0.0.0/0 flowid 1:10")
    #@-node:tcAddFilterOut
    #@+node:tcAddFilterIngressPolice
    def tcAddFilterIngressPolice(self, dev, rate, pri, flowid, matches, index):
    
        #if ingressMethod == 'share':
        #    indexfld = "index %s" % index
        #else:
        #    indexfld = ''
            
        self.tcAddFilter(
            dev,
            "parent ffff: protocol ip prio %s" % pri,
            "u32",
            " ".join(["match ip "+m for m in matches]),
            "police rate %s" % int(rate * 1024),
            #indexfld,
            "burst 10k drop flowid ffff:%s" % flowid,
            )
    #@-node:tcAddFilterIngressPolice
    #@+node:log
    def log(self, level, msg):
    
        if level > self.verbosity:
            return
        print "pyshaper: %s" % msg
    #@-node:log
    #@-others
#@-node:class TShaper
#@+node:class ShaperConfig
class ShaperConfig:
    """
    Loads/parses/edits/save the shaping config file
    """
    #@    @+others
    #@+node:attribs
    path = configPath
    
    forbidden = [
         'in',
         'out',
         'pri',
         'save',
         'matches',
         'classes',
         'subclasses',
         'expr',
         'bwIn',
         'bwOut',
         'name',
         'parent',
         ]
    
    shaperPeriod = shaperPeriod
    
    guiWidth = 200
    guiHeight = 200
    dontSave = False
    #@-node:attribs
    #@+node:__init__
    def __init__(self, path=None):
    
        self.reSpaces = re.compile("\\s+")
        
        if path:
           self.path = path
    
        if not os.path.isfile(self.path):
            raise Exception("Missing config file %s" % path)
    
        self.load()
    
        self.hasChanged = True
    #@-node:__init__
    #@+node:load
    def load(self):
        """
        Reloads the config, ditching old one
        """
        reComment = re.compile("#(.*)(\\n|$)")
        raw = file(self.path).read().strip()
    
        self.interfacesdict = {}
        self.interfaces = []
    
        # rip comments
        raw = reComment.sub("\n", raw)
    
        # join broken lines
        raw = re.sub("\\\\(\\s*)", "", raw)
    
        # break into lines, strip the lines, toss empties
        lines = [line.strip() for line in raw.split("\n")]
        lines = filter(lambda l: l != '', lines)
    
        cmds = []
        for line in lines:
            try:
                cmd, arg = self.reSpaces.split(line, 1)
                cmds.append((cmd, arg))
            except:
                traceback.print_exc()
                raise Exception("Invalid line '%s' in config file %s" % (line, self.path))
        #print cmds
    
        # now the hard bit - make sense of these lines and stick them into rules base
        for item, val in cmds:
            self.execute(item, val)
    
    #@-node:load
    #@+node:execute
    def execute(self, item, val=None):
        
        if val is None:
            item, val = self.reSpaces.split(item, 1)
    
        #print repr(item), repr(val)
    
        if item == 'period':
            self.shaperPeriod = int(val)
            return
        elif item == 'guiwidth':
            self.guiWidth = int(val)
            return
        elif item == 'guiheight':
            self.guiHeight = int(val)
            return
    
        try:
            ifname, rest = item.split(".", 1)
        except:
            print "Bad line in %s: %s %s" % (self.path, item, val)
            raise
        
        if ifname in self.forbidden:
            raise Exception("Illegal interface name '%s'" % ifname)
    
        # get interface rec, create if not previously known
        ifrec = self.interfacesdict.get(ifname, None)
        if not ifrec:
            ifrec = self.interfacesdict[ifname] = ShaperConfigIface(ifname)
            self.interfaces.append(ifrec)
    
        # process magic names
        if rest == 'in':
            ifrec.bwIn = float(val)
            return
        if rest == 'out':
            ifrec.bwOut = float(val)
            return
        if rest == 'ip':
            ifrec.ipaddr = val
            return
    
        # not magic - take as class name
        #print "rest=%s" % repr(rest)
        clsname, rest = rest.split(".", 1)
    
        if clsname in self.forbidden:
            raise Exception("Illegal class name '%s.%s'" % (ifname, clsname))
    
        # get class rec, create if not previously known
        clsrec = ifrec.classesdict.get(clsname, None)
        if not clsrec:
            clsrec = ifrec.classesdict[clsname] = ShaperConfigClass(ifrec, clsname)
            ifrec.classes.append(clsrec)
    
        # process magic names
        if rest in ['pri', 'priority']:
            clsrec.pri = int(val)
            return
        if rest == 'in':
            clsrec.bwIn = float(val)
            return
        if rest == 'out.rate':
            clsrec.bwOutRate = float(val)
            return
        if rest == 'out.ceil':
            clsrec.bwOutCeil = float(val)
            return
        if rest == 'test':
            clsrec.addTest(val)
            return
        if rest in ['raddr', 'rport', 'laddr', 'lport']:
            if rest.endswith('port'):
                val = int(val)
            setattr(clsrec, rest, val)
            return
    
        raise Exception("Invalid cmd field '%s' in %s.%s" % (rest, ifname, clsname))
    
    #@-node:execute
    #@+node:save
    def save(self, hasChanged=False):
        """
        Writes the configuration out to disk, if changed
        """
        print "config.save: 1"
        if self.dontSave:
            return
        print "config.save: 2"
        if hasChanged:
            self.hasChanged = True
        print "config.save: 3"
        if not self.hasChanged:
            return
    
        print "saving config"
    
        path = self.path
        pathNew = path + ".sav"
        pathBak = path + ".bak"
        f = file(pathNew, "w")
        f.write("\n".join([
            "# pyshaper configuration file",
            "# ",
            "# (regenerated by pyshaper after realtime changes)",
            "# ",
            "# Updated: %s" % time.asctime(),
            "# ",
            "",
    
            "# width and height of GUI window - ignore this",
            "guiwidth %s" % self.guiWidth,
            "guiheight %s" % self.guiHeight,
            "",
            
            "# time period in seconds between each run",
            "period %s" % self.shaperPeriod,
            "",
            "",
            ]))
    
        for iface in self.interfaces:
            iface.save(f)
            f.write("\n")
    
        try:
            os.unlink(pathBak)
        except:
            pass
        os.rename(path, pathBak)
        os.rename(pathNew, path)
        self.hasChanged = False
    
    
    #@-node:save
    #@+node:__getattr__
    def __getattr__(self, name):
        """convenience for interactive debugging"""
        if name in ['__nonzero__', '__len__']:
            raise AttributeError(name)
        try:
            return self.interfacesdict[name]
        except:
            raise Exception("No such interface '%s'" % name)
    #@-node:__getattr__
    #@+node:__str__
    def __str__(self):
        
        return "\n".join([str(i) for i in self.interfaces])
    #@-node:__str__
    #@+node:__repr__
    def __repr__(self):
        
        return str(self)
    #@-node:__repr__
    #@-others
#@-node:class ShaperConfig
#@+node:class ShaperConfigIface
class ShaperConfigIface:
    """
    Holds the config info for a specific interface
    """
    #@    @+others
    #@+node:attribs
    bwIn = 1024 * 1024   # default 1Gbit/sec - ridiculous
    bwOut = 1024 * 1024
    #@-node:attribs
    #@+node:__init__
    def __init__(self, name):
        
        self.name = name
    
        self.classesdict = {}
        self.classes = []
    
        self.staticclassesdict = {}
        self.staticclasses = []
        
        dflt = self.default = self.classesdict['default'] = ShaperConfigClass(self, 'default')
        dflt.bwIn = self.bwIn
        dflt.bwOut = self.bwOut
    
        self.ipaddr = '0.0.0.0'
    #@-node:__init__
    #@+node:__getattr__
    def __getattr__(self, name):
        """convenience for interactive debugging"""
    
        if name == 'parent':
            class P: pass
            p = P()
            p.name = '?'
            return p
        if name in ['__nonzero__', '__len__']:
            raise AttributeError(name)
        try:
            return self.classesdict[name]
        except:
            raise Exception("%s: No such class '%s'" % (self.name, name))
    
    #@-node:__getattr__
    #@+node:__setattr__
    def __setattr__(self, attr, value):
        
        self.__dict__[attr] = value
    
        if attr in ['bwIn', 'bwOut']:
            setattr(self.default, attr, value)
    #@-node:__setattr__
    #@+node:__str__
    def __str__(self):
    
        s = "%s: ip=%s in=%s out=%s" % (self.name, self.ipaddr, self.bwIn, self.bwOut)
        if self.classes:
            s += "\n" + "\n".join([str(cls) for cls in self.classes])
        s += "\n" + str(self.default)
        return s
    
    #@-node:__str__
    #@+node:__repr__
    def __repr__(self):
        return str(self)
    
    #@-node:__repr__
    #@+node:save
    def save(self, f):
        """
        Saves this interface record out to open file f
        """
        name = self.name
        f.write("\n".join([
            "%s.ip %s" % (name, self.ipaddr),
            "%s.in %s" % (name, self.bwIn),
            "%s.out %s" % (name, self.bwOut),
            ]) + "\n")
        for cls in self.classes:
            cls.save(f)
        self.default.save(f)
    #@-node:save
    #@-others
#@-node:class ShaperConfigIface
#@+node:class ShaperConfigClass
class ShaperConfigClass:
    """
    Holds a config record for a specific class on a specific
    interface
    """
    #@    @+others
    #@+node:attribs
    pri = 1
    mode = 'dynamic'
    
    # attributes for 'static mode' shaping
    raddr = None
    rport = None
    laddr = None
    lport = None
    
    # window size in seconds for calculating rates
    rateWindow1 = 5.0
    #@-node:attribs
    #@+node:__init__
    def __init__(self, parent, name):
        
        self.parent = parent
        self.name = name
        #self.subclassesdict = {}
        #self.subclasses = []
    
        self.conns = []
        self.oldconns = []
    
        self.tests = []
        self.exprs = []
    
        # these lists are for dynamic monitoring via the gui
        self.pktInHist = []   # list of (time, size) tuples for inbound pkts
        self.pktOutHist = []  # ditto for outbound packets
    
        self.rateIn = 0.0
        self.rateOut = 0.0
    
        self.silly = "xxx"
    #@-node:__init__
    #@+node:__getattr__
    def __getattr__(self, name):
        """
        convenience for interactive debugging
        """
        if name == 'parent':
            return "?"
        parent = self.parent
        if name == 'bwIn':
            return parent.bwIn
        if name == 'bwOutRate':
            return parent.bwOut/2
        if name == 'bwOutCeil':
            return parent.bwOut
        if name == 'ipaddr':
            self.ipaddr = parent.ipaddr
            return parent.ipaddr
    
        if name in ['__nonzero__', '__len__']:
            raise AttributeError(name)
    
        #try:
        #    return self.subclassesdict[name]
        #except:
        #    raise Exception("%s.%s: No such subclass '%s'" % (self.parent.name, self.name, name))
    
    #@-node:__getattr__
    #@+node:__setattr__
    def __setattr__(self, attr, val):
        """
        Setting any of the attributes 'raddr', 'rport', 'laddr', 'lport'
        converts this object into a 'static class', which means that it
        gains precedence for matching connections
        """
        # set the attrib
        self.__dict__[attr] = val
    
        # switch to static mode if a static attrib has been set
        if attr in ['raddr', 'rport', 'laddr', 'lport']:
            self.__dict__['mode'] = 'static'
    #@-node:__setattr__
    #@+node:__str__
    def __str__(self):
    
        hdr = "%s.%s: pri=%s in=%s out=%s/%s" % (
                    self.parent.name, self.name,
                    self.pri,
                    self.bwIn, self.bwOutRate, self.bwOutCeil
                    )
    
        if self.name == 'default':
            return hdr
    
        hdr1 = "\n    STATIC:"
        hdr2 = ''
        if self.raddr:
            hdr2 += " raddr=%s" % self.raddr
        if self.rport:
            hdr2 += " rport=%s" % self.rport
        if self.lport:
            hdr2 += " lport=%s" % self.lport
        if hdr2:
            hdr1 += hdr2
        else:
            hdr1 = "\n    ** NO STATIC RULE **"
    
        if self.exprs:
            hdr1 += "\n  " + "\n".join(["  "+expr for expr in self.exprs])
        else:
            hdr1 += "\n    ** NO DYNAMIC RULES **"
    
        return hdr + hdr1
    #@-node:__str__
    #@+node:__repr__
    def __repr__(self):
    
        return repr(str(self))
    #@-node:__repr__
    #@+node:addTest
    def addTest(self, expr):
        """
        Adds a test to this bw class
        """
        # convert expr into a valid lambda func
        self.exprs.append(expr)
        try:
            for term in ['cc', 'country',
                         'cmd', 'args',
                         'laddr', 'lport', 'raddr', 'rport',
                         'user']:
                expr = expr.replace(term, 'f.'+term)
            test = eval("lambda f:"+expr)
            self.tests.append(test)
        except:
            traceback.print_exc()
            raise Exception("Invalid test expression '%s'" % expr)
    #@-node:addTest
    #@+node:save
    def save(self, f):
        """
        Saves this class record out to open file f
        """
        name = self.parent.name + "." + self.name
        f.write("\n".join([
            "",
            "  # traffic class '%s' on interface '%s'" % (self.name, self.parent.name),
            "  %s.in %s" % (name, self.bwIn),
            "  %s.out.rate %s" % (name, self.bwOutRate),
            "  %s.out.ceil %s" % (name, self.bwOutCeil),
            "  %s.pri %s" % (name, self.pri),
            ]) + "\n")
    
        if self.exprs:
            f.write("  # dynamic matching rules\n")
            for e in self.exprs:
                f.write("  %s.test %s\n" % (name, e))
        if self.raddr or self.rport or self.laddr or self.lport:
            f.write("  # static matching specs\n")
            for a in ['raddr', 'rport', 'laddr', 'lport']:
                v = getattr(self, a)
                if v:
                    f.write("  %s.%s %s\n" % (name, a, v))
    #@-node:save
    #@+node:matches
    def matches(self, connrec):
        """
        Tests if a connection matches the rule of one or more of our subclasses
        
        connrec is an item of class TCPConns
        
        Returns True if matches, False if not
        """
        m = staticItemMatch
    
        if 0 and self.name == 'local-apache' and connrec.rport != 22 and connrec.lport != 25:
            print "configclass.matches: ", [getattr(self, x) for x in ['raddr', 'rport', 'lport']]
            print "configclass.matches: connrec=%s" % repr(connrec)
            print repr(self.raddr), repr(self.rport), repr(self.lport)
    
    
        if self.mode == 'static':
            # only match the static flow attributes that have been set for this class
            if (m(self.raddr, connrec.raddr)
                and m(self.rport, connrec.rport)
                and m(self.lport, connrec.lport)
            ):
                if 0 and self.name== 'local-apache':
                    print "ShaperConfigClass.matches: %s: got static match" % self.name
                return True
    
        if self.mode == 'dynamic':
            for matches in self.tests:
                if matches(connrec):
                    if 0 and self.name== 'local-apache':
                        print "ShaperConfigClass.matches: %s: got dynamic match" % self.name
                    return True
            return False
    
    
    
    #@-node:matches
    #@+node:matchesPacket
    def matchesPacket(self, src, sport, dst, dport, dynamic=False):
        """
        return True if a packet, specified  by src, sport, dst, dport matches either
        our static rule, or matches one or more connections currently known to this class
        """
        f = staticItemMatch
    
        if 0:
            if self.name == 'local-apache' and sport not in [22,25] and dport not in [22,25]:
                raddr = self.raddr
                rport = self.rport
                laddr = self.laddr
                lport = self.lport
    
                print "----vvv----------------------"    
                print "cls.matchesPacket: trying to match packet %s:%s->%s:%s against class %s" % (
                    repr(src), repr(sport), repr(dst), repr(dport), self.name)
                print "mode=%s" % self.mode
                print "raddr=%s rport=%s laddr=%s lport=%s" % (
                    repr(raddr), repr(rport), repr(laddr), repr(lport))
                print "----^^^----------------------"
    
    
        # test for dynamic match
        #print "-------------------"
        if dynamic:
            for conn in self.conns:
                #print "XXX", conn
                if conn.matchesPacket(src, sport, dst, dport):
                    #print "dynamic match %s: %s:%s -> %s:%s" % (
                    #    self.name, src, sport, dst, dport)
                    return True
        else:
            # test for static match
            if self.mode == 'static':
                raddr = self.raddr
                rport = self.rport
                laddr = self.laddr
                lport = self.lport
        
                if ((f(raddr, src) and f(rport, sport) and self.ipaddr == dst and f(lport, dport))
                    or
                    (f(raddr, dst) and f(rport, dport) and self.ipaddr == src and f(lport, sport))
                ):
                    #print "static match %s: %s:%s -> %s:%s" % (
                    #    self.name, src, sport, dst, dport)
                    return True
        
        # nothing matches
        return False
    
    #@-node:matchesPacket
    #@+node:on_packet
    def on_packet(self, src, sport, dst, dport, plen):
        
        #print "class %s.%s got packet %s:%s -> %s:%s %s" % (
        #    self.parent.name, self.name, src, sport, dst, dport, plen)
    
        dt = self.rateWindow1
        now = time.time()
        then = now - dt
        self.lastPktTime = now
    
        ipaddr = self.ipaddr
        pktInHist = self.pktInHist
        pktOutHist = self.pktOutHist
    
        # save packet in inbound and/or outbound histories
        item = (now, plen)
        if dst == ipaddr:
            pktInHist.insert(0, item)
        if src == ipaddr:
            pktOutHist.insert(0, item)
    
        # calculate current in and out rates
        i = 0
        totIn = 0
        for when, size in pktInHist:
            if when < then:
                break
            totIn += size
            i += 1
        self.rateIn = totIn / dt # determine moving avg in
        del pktInHist[i:]
        
        i = 0
        totOut = 0
        for when, size in pktOutHist:
            if when < then:
                break
            totOut += size
            i += 1
        self.rateOut = totOut / dt # determine moving avg in
        del pktOutHist[i:]
    
        #print "%s.%s: rate = %s b/s in, %s b/s out" % (
        #    self.parent.name, self.name, self.rateIn, self.rateOut)
        
        #self.pktInHist = []   # list of (time, size) tuples for inbound pkts, in reverse order
        #self.pktOutHist = []  # ditto for outbound packets
    
        self.silly = "yyy"
    
    
    #@-node:on_packet
    #@+node:sortConnections
    def sortConnections(self):
        """
        Sorts connections into a predetermined order, so that if the
        set of eligible connections is the same, the sequence
        of tc commands will be the same
        """
        def sortconn(conn1, conn2):
            
            if conn1.raddr < conn2.raddr:
                return -1
            elif conn1.raddr > conn2.raddr:
                return 1
            elif conn1.rport < conn2.rport:
                return -1
            elif conn1.rport > conn2.rport:
                return 1
            elif conn1.laddr < conn2.laddr:
                return -1
            elif conn1.laddr > conn2.laddr:
                return 1
            elif conn1.lport < conn2.lport:
                return -1
            elif conn1.lport > conn2.lport:
                return 1
            return 0
    
        self.conns.sort(sortconn)
    
    
    #@-node:sortConnections
    #@-others
#@-node:class ShaperConfigClass
#@+node:class Conn
class Conn:
    """
    Simple class representing a single current TCP connection
    """
    def __str__(self):

        if GeoIP:
            return "%s/%s %s:%s => %s:%s (%s/%s)" % (
                        self.user, self.pid,
                        self.laddr, self.lport, self.raddr, self.rport,
                        self.cc, self.country)
        else:
            return "%s/%s %s:%s => %s:%s" % (
                        self.user, self.pid,
                        self.laddr, self.lport, self.raddr, self.rport,
                        )

    def __repr__(self):
        return str(self)

    def strdetail(self):
        return str(self) + " (%s %s)" % (
            self.cmd, " ".join(["'"+arg+"'" for arg in self.args]))
    
    def matchesPacket(self, src, sport, dst, dport):
        """
        Returns True if a packet matches this connection
        """
        raddr = self.raddr
        rport = self.rport
        laddr = self.laddr
        lport = self.lport

        #print "Conn: matching %s:%s->%s:%s against %s:%s,%s:%s" % (
        #    repr(src), repr(sport), repr(dst), repr(dport),
        #    repr(raddr), repr(rport), repr(laddr), repr(lport))
        m = staticItemMatch
        
        if ((m(raddr, src) and m(rport, sport) and m(lport, dport))
            or
            (m(raddr, dst) and m(rport, dport) and m(lport, sport))
        ):
            #print "Conn.matchesPacket: true"
            return True
        else:
            return False


#@-node:class Conn
#@+node:class TCPConns
class TCPConns:
    """
    Class which scans the current TCP connections, and returns a
    list with a dict representing each connection
    """
    #@    @+others
    #@+node:attribs
    netstatCmd = netstatCmd
    
    #@-node:attribs
    #@+node:__init__
    def __init__(self):
    
        if GeoIP:
            # create a GeoIP object, enable country lookups
            try:
                g = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
                self.ip2cc = g.country_code_by_addr
                self.ip2country = g.country_name_by_addr
            except:
                self.ip2cc = None
                self.ip2country = None
                traceback.print_exc()
        else:
            self.ip2cc = None
            self.ip2country = None
    
        self.getconns()
    #@-node:__init__
    #@+node:getconns
    def getconns(self):
    
        # run 'netstat', break output into lines
        lines = commands.getoutput(self.netstatCmd).strip().split("\n")
    
        # and break each line into fields
        lines = [reSpaces.split(l) for l in lines]
    
        ip2cc = self.ip2cc
        ip2country = self.ip2country
    
        conns = []
        for line in lines:
            try:
                if line[0] == 'tcp':
                    d = Conn()
                    localend = line[3].split(":")
                    d.laddr = localend[0]
                    d.lport = int(localend[1])
                    remend = line[4].split(":")
                    raddr = remend[0]
                    d.raddr = raddr
                    d.rport = int(remend[1])
                    d.user = line[6]
                    d.inode = int(line[7])
                    proc = line[8].split("/")
                    d.pid = int(proc[0])
                    cmdline = file("/proc/%s/cmdline" % d.pid).read().strip().split("\x00")
                    if cmdline[-1] == '':
                        cmdline.pop()
                    d.cmd = cmdline[0]
                    d.args = cmdline[1:]
                    if ip2cc:
                        try:
                            d.cc = ip2cc(raddr)
                        except:
                            d.cc = None
                    if ip2cc:
                        try:
                            d.country = ip2country(raddr)
                        except:
                            d.country = None
                    conns.append(d)
            except:
                # print "hates %s" % repr(line)
                #traceback.print_exc()
                pass
        self.conns = conns
    
    #@-node:getconns
    #@+node:dump
    def dump(self):
        
        for conn in self:
            print str(conn)
    #@-node:dump
    #@+node:__getitem__
    def __getitem__(self, item):
        return self.conns[item]
    #@-node:__getitem__
    #@+node:__getslice__
    def __getslice__(self, fromidx, toidx):
        return self.conns[fromidx:toidx]
    #@-node:__getslice__
    #@+node:__len__
    def __len__(self):
        return len(self.conns)
    #@-node:__len__
    #@+node:filter
    def filter(self, **kw):
        conns = []
        for conn in self:
            matches = True
            for k,v in kw.items():
                if conn[k] != v:
                    matches = False
                    break
            if matches:
                conns.append(conn)
        return conns
    #@-node:filter
    #@-others
#@-node:class TCPConns
#@+node:staticItemMatch
def staticItemMatch(item, test):
    """
    returns true if the first arg is None, or equal to second arg
    """
    return (item is None) or (item == test)
#@-node:staticItemMatch
#@+node:takeKey
def takeKey(somedict, keyname, default=None):
    """
    Utility function to destructively read a key from a given dict.
    Same as the dict's 'takeKey' method, except that the key (if found)
    sill be deleted from the dictionary.
    """
    if somedict.has_key(keyname):
        val = somedict[keyname]
        del somedict[keyname]
    else:
        val = default
    return val
#@-node:takeKey
#@+node:splitflds
def splitflds(s):
    s = s.strip()
    if s == '':
        return []
    else:
        return reDelim.split(s)
#@-node:splitflds
#@+node:main
def main():

    argv = sys.argv
    argc = len(argv)

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "h?vdV:f",
                                   ['help', 'version', 'debug', 'foreground',
                                    'verbosity=',
                                    ])
    except:
        traceback.print_exc(file=sys.stdout)
        usage("You entered an invalid option")

    daemonise = True
    verbosity = 2
    debug = False

    for opt, val in opts:
        
        if opt in ['-h', '-?', '--help']:
            usage(True)

        elif opt in ['-d', '--debug']:
            debug = True

        elif opt in ['-f', '--foreground']:
            daemonise = False

        elif opt in ['-v', '--version']:
            print "pyshaper version %s" % version
            sys.exit(0)

        elif opt in ['-V', '--verbosity']:
            verbosity = int(val)

    #print "Debug - bailing"
    #print repr(opts)
    #print repr(args)
    #sys.exit(0)

    # Try to bring up GUI if no command given
    if len(args) == 0:
        mypid = os.getpid()
        try:
            g = TShaperGui()
        except:
            traceback.print_exc()
            print "No command given, cannot launch gui, not good - bailing"
            usage()
            sys.exit(1)
        try:
            g.run()
        except SystemExit, KeyboardInterrupt:
            print "killing self"
            os.kill(mypid, signal.SIGKILL)
            pass
        except:
            traceback.print_exc()
            print "pyshaper GUI crashed!"
            sys.exit(1)
        sys.exit(0)

    cmd = args[0]

    if cmd == 'help':
        usage(True)

    elif cmd == "start":
        if daemonise:
            pid = os.fork()
            if pid:
                print "pyshaper detached into background as daemon with pid %s" % pid
                sys.exit(0) # parent quit, leave child running
        try:
            shaper = TShaper(verbosity=verbosity, debug=debug)
            shaper.run()
        except:
            traceback.print_exc()
            print "Exception - terminating"
            sys.exit(1)

    #print shaper.currentConns[:]

    elif cmd == "status":
        shaper = TShaper()
        print shaper.status()
        sys.exit(0)

    elif cmd == 'netstat':
        cmd = netstatCmd
        if len(argv) == 3:
            cmd += "|grep %s" % argv[2]
        os.system(cmd)
        sys.exit(0)

    elif cmd == 'dumpconns':
        for conn in TCPConns():
            print conn.strdetail()
        sys.exit(0)

    elif cmd in ['reload', 'restart']:
        if os.path.isfile(pidfile):
            pid = int(file(pidfile).read())
            os.kill(pid, signal.SIGHUP)
            print "Sent SIGHUP to pyshaper (pid %s) to force config reload" % pid
            sys.exit(0)
        else:
            print "Can't find pidfile %s, pyshaper appears not to be running" % pidfile
            sys.exit(1)

    elif cmd in ['kill', 'stop']:
        if os.path.isfile(pidfile):
            pid = int(file(pidfile).read())
            os.kill(pid, signal.SIGQUIT)
            print "Terminated pyshaper (pid %s)" % pid
            sys.exit(0)
        else:
            print "Can't find pidfile %s, pyshaper appears not to be running" % pidfile
            sys.exit(1)

#@-node:main
#@+node:usage
def usage(detailed=False):
    
    print "Usage: %s <options> <command>" % sys.argv[0]
    if not detailed:
        sys.exit(0)

    print "This is pyshaper, a dynamic traffic-shaping application written"
    print "by David McNab <david@freenet.org.nz>"
    print "Program homepage is at http://www.freenet.org.nz/python/pyshaper"
    print
    print "Options:"
    print "     -f, --foreground  - stay in foreground, and do not daemonise"
    print "     -h, --help        - display this help"
    print "     -v, --version     - print program version"
    print "     -V, --verbosity=n - set verbosity to n, default 2, 1==quiet, 4==noisy"
    print "     -d, --debug       - debug mode - severely impacts performance"
    print
    print "Commands:"
    print "     (run with no commands to launch the GUI)"
    print "     start  - start pyshaper running (as daemon, unless you give '-f'"
    print "     stop   - terminate any running instance of pyshaper"
    print "     status - do a status dump of pyshaper"
    print "     netstat [keyword] - runs the netstat cmd, optionally grepping for <keyword>"
    print "     reload - force the running instance of pyshaper to re-read"
    print "              its configuration file from /etc/pyshaper/pyshaper.conf,"
    print "              then rebuild the shaping rules"
    print "     help   - display this help"
    print
    
    sys.exit(0)

    



#@-node:usage
#@+node:mainline
if __name__ == '__main__':
    main()

#if __name__ == '__main__':
#    for c in TCPConns():
#        print c
#@-node:mainline
#@-others
#@-node:@file pyshaper.py
#@-leo
