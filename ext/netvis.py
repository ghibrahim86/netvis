"""
Network visualization tool, based on the miniedit example provided in the
Mininet package.

Yujia Li, 12/2012
"""

from Tkinter import Frame, Button, Label, Scrollbar, Canvas
from Tkinter import Menu, BitmapImage, PhotoImage, Wm, Toplevel

from tooltip import ToolTip
from linetooltip import LineToolTip

import Queue

class Switch (object):
  def __init__ (self, name, desc, widget=None):
    self.name = name
    self.desc = desc
    self.links = {}
    self.widget = widget 

class Host (object):
  def __init__ (self, name, desc, ip=None, mac=None, widget=None):
    self.name = name
    self.ip = ip 
    self.desc = desc
    self.mac = mac
    self.links = {}
    self.widget = widget

class Position (object):
  def __init__ (self, x, y):
    self.x = x
    self.y = y

class NetVisMsg (object):

  MSG_TYPE_ADD    = 1
  MSG_TYPE_REMOVE = 2

  MSG_OBJ_TYPE_HOST   = 1
  MSG_OBJ_TYPE_SWITCH = 2
  MSG_OBJ_TYPE_LINK   = 3

  def __init__ (self, msgtype, objtype, switch=None, host=None, src=None,
      dst=None, desc=None):
    self.msgtype = msgtype
    self.objtype = objtype
    self.switch = switch
    self.host = host
    self.src = src
    self.dst = dst
    self.desc = desc

class NetVis (Frame):

  def __init__ (self, parent=None, cheight=200, cwidth=500):
    Frame.__init__ (self, parent)

    self.action = None
    self.appName = 'NetVis'

    # Style
    self.font = ('Geneva', 9)
    self.smallFont = ('Geneva', 7)
    self.bg = 'white'

    # Title
    self.top = self.winfo_toplevel()
    self.top.title(self.appName)

    # Canvas
    self.cheight, self.cwidth = cheight, cwidth
    self.cframe, self.canvas = self.createCanvas()

    # Button images
    self.images = netVisImages()

    # Layout
    self.cframe.grid(column=0, row=0)
    self.columnconfigure(0, weight=1)
    self.rowconfigure(0, weight=1)
    self.pack(expand=True, fill='both')

    # Constants
    self.NODE_SWITCH = 'Switch'
    self.NODE_HOST = 'Host'
    
    # Nodes
    self.nodeBindings = self.createNodeBindings()
    self.nodePrefixes = {'Switch': 's', 'Host': 'h'}
    self.widgetToItem = {}
    self.itemToWidget = {}

    Wm.wm_protocol(self.top, name="WM_DELETE_WINDOW", func=self.quit)

    # Network
    self.nextswitchpos = Position(50, 50)
    self.nexthostpos = Position(50, 150)

    self.nextnodepos = Position(50, 50)

    self.links = {}

    # Message Queue
    self.msgqueue = Queue.Queue()

  def quit (self):
    Frame.quit(self)

  def createCanvas (self):
    "Create and return our scrolling canvas frame."
    f = Frame(self)

    canvas = Canvas(f, width=self.cwidth, height=self.cheight, bg=self.bg)

    # Scroll bars
    xbar = Scrollbar(f, orient='horizontal', command=canvas.xview)
    ybar = Scrollbar(f, orient='vertical', command=canvas.yview)
    canvas.configure(xscrollcommand=xbar.set, yscrollcommand=ybar.set)

    # Resize box
    resize = Label(f, bg='white')

    # Layout
    canvas.grid(row=0, column=0, sticky='nsew')
    ybar.grid(row=0, column=1, sticky='ns')
    xbar.grid(row=1, column=0, sticky='ew')
    resize.grid(row=1, column=1, sticky='nsew')

    # Resize behavior
    f.rowconfigure(0, weight=1)
    f.columnconfigure(0, weight=1)
    f.grid(row=0, column=0, sticky='nsew')
    f.bind('<Configure>', lambda event: self.updateScrollRegion())

    # Mouse bindings
    canvas.bind('<ButtonPress-1>', self.clickCanvas)
    canvas.bind('<B1-Motion>', self.dragCanvas)
    canvas.bind('<ButtonRelease-1>', self.releaseCanvas)

    return f, canvas

  def updateScrollRegion (self):
    "Update canvas scroll region to hold everything."
    bbox = self.canvas.bbox('all')
    if bbox is not None:
      self.canvas.configure(scrollregion=(0, 0, bbox[2], bbox[3]))

  def canvasHandle (self, eventName, event):
    "Generic canvas event handler"
    #if self.active is None:
    #  return
    #toolName = self.active
    #handler = getattr( self, eventName + toolName, None )
    #if handler is not None:
    #  handler( event )

  def clickCanvas (self, event):
    "Canvas click handler."
    self.canvasHandle('click', event)

  def dragCanvas (self, event):
    "Canvas drag handler."
    self.canvasHandle('drag', event)

  def releaseCanvas (self, event):
    "Canvas mouse up handler."
    self.canvasHandle('release', event)

  def clickNode (self, event):
    w = event.widget
    if isinstance(w, Button):
      w.configure(relief='raised')

  def dragNode (self, event):
    self.dragNodeAround(event)


  def releaseNode (self, event):
    pass

  def enterNode (self, event):
    pass

  def leaveNode (self, event):
    pass

  def dragNodeAround (self, event):
    "Drag a node around on the canvas."
    c = self.canvas
    # Convert global to local coordinates;
    # Necessary since x, y are widget-relative
    x = self.canvasx(event.x_root)
    y = self.canvasy(event.y_root)
    w = event.widget
    # Adjust node position
    item = self.widgetToItem[w]
    c.coords(item, x, y)
    # Adjust link positions
    for dest in w.links:
      link = w.links[dest]
      item = self.widgetToItem[dest]
      x1, y1 = c.coords(item)
      c.coords(link, x, y, x1, y1)

  def canvasx (self, x_root):
    "Convert root x coordinate to canvas coordinate."
    c = self.canvas
    return c.canvasx(x_root) - c.winfo_rootx()

  def canvasy (self, y_root):
    "Convert root y coordinate to canvas coordinate."
    c = self.canvas
    return c.canvasy(y_root) - c.winfo_rooty()

  def createNodeBindings (self):
    "Create a set of bindings for nodes."
    bindings = {
        '<ButtonPress-1>': self.clickNode,
        '<B1-Motion>': self.dragNode,
        '<ButtonRelease-1>': self.releaseNode,
        '<Enter>': self.enterNode,
        '<Leave>': self.leaveNode
    }
    l = Label()  # lightweight-ish owner for bindings
    for event, binding in bindings.items():
      l.bind(event, binding)
    return l

  def newNode (self, node, x, y):
    if isinstance(node, Switch):
      node_type = 'Switch'
    else:
      node_type = 'Host'

    c = self.canvas
    icon = self.nodeIcon(node_type, node.name)
    item = self.canvas.create_window(x, y, anchor='c', window=icon,
        tags=node_type)
    self.widgetToItem[icon] = item
    self.itemToWidget[item] = icon
    #self.selectItem(item)
    icon.links = {}

    ToolTip(icon, msg=node.desc, delay=0)

    return icon

  def nodeIcon (self, node, name):
    "Create a new node icon."
    icon = Button(self.canvas, image=self.images[node],
        text=name, compound='top')

    # Unfortunately bindtags wants a tuple
    bindtags = [str(self.nodeBindings)]
    bindtags += list(icon.bindtags())
    icon.bindtags(tuple(bindtags))
    return icon

  def addSwitch (self, switch):
    """
    Add a switch to the network for visualization, the switch should at least 
    have a name.
    """
    switch.widget = self.newNode(
        switch, self.nextswitchpos.x, self.nextswitchpos.y)
    self.nextswitchpos.x += 100
    #if self.nextswitchpos.x > 600:
    #  self.nextswitchpos.x = 50
    #  self.nextswitchpos.y += 100

  def addHost (self, host):
    """
    Add a host to the network for visualization, the host should at least have
    a name.  ip and mac are optional.
    """
    host.widget = self.newNode(host, self.nexthostpos.x, self.nexthostpos.y)
    self.nexthostpos.x += 100
    #if self.nexthostpos.x > 600:
    #  self.nexthostpos.x = 50
    #  self.nexthostpos.y += 100


  def addLink (self, n1, n2, desc=None):
    """
    Add a link between two nodes n1 and n2.  n1 and n2 can be switches or
    hosts. In the network we have, n1 and n2 cannot be hosts at the same time.
    """
    c = self.canvas

    item1 = self.widgetToItem[n1.widget]
    x1, y1 = c.coords(item1)
    item2 = self.widgetToItem[n2.widget]
    x2, y2 = c.coords(item2)

    link = c.create_line(x1, y1, x2, y2, width=4, fill='blue', tag='link')

    def highlight(event, link=link):
      "Highlight item on mouse entry."
      self.canvas.itemconfig(link, fill='green')

    def unhighlight(event, link=link):
      "Unhighlight item on mouse exit."
      self.canvas.itemconfig(link, fill='blue')

    self.canvas.tag_bind(link, '<Enter>', highlight)
    self.canvas.tag_bind(link, '<Leave>', unhighlight)

    LineToolTip(c, link, desc, delay=0)

    n1.links[n2] = link
    n2.links[n1] = link

    n1.widget.links[n2.widget] = link
    n2.widget.links[n1.widget] = link

    self.links[link] = (n1, n2)

  def update (self):
    """
    Retrieve update events from queue and update the network, used to
    communicate with other threads.
    """
    while True:
      try:
        msg = self.msgqueue.get_nowait()

        # Handle messages
        if msg.msgtype == NetVisMsg.MSG_TYPE_ADD:
          if msg.objtype == NetVisMsg.MSG_OBJ_TYPE_HOST:
            self.addHost(msg.host)
          elif msg.objtype == NetVisMsg.MSG_OBJ_TYPE_SWITCH:
            self.addSwitch(msg.switch)
          elif msg.objtype == NetVisMsg.MSG_OBJ_TYPE_LINK:
            self.addLink(msg.src, msg.dst, msg.desc)
          else:
            print 'Wrong NetVisMsg objtype!!!'
            break

      except Queue.Empty:
        break

    # Wait for next update cycle
    self.after(1000, self.update)

  def writeMsg (self, msg):
    self.msgqueue.put(msg)


def netVisImages():
    "Create and return images for NetVis."

    # Image data. Git will be unhappy. However, the alternative
    # is to keep track of separate binary files, which is also
    # unappealing.

    return {
        'Select': BitmapImage(
            file='/usr/include/X11/bitmaps/left_ptr' ),

        'Host': PhotoImage( data=r"""
            R0lGODlhIAAYAPcAMf//////zP//mf//Zv//M///AP/M///MzP/M
            mf/MZv/MM//MAP+Z//+ZzP+Zmf+ZZv+ZM/+ZAP9m//9mzP9mmf9m
            Zv9mM/9mAP8z//8zzP8zmf8zZv8zM/8zAP8A//8AzP8Amf8AZv8A
            M/8AAMz//8z/zMz/mcz/Zsz/M8z/AMzM/8zMzMzMmczMZszMM8zM
            AMyZ/8yZzMyZmcyZZsyZM8yZAMxm/8xmzMxmmcxmZsxmM8xmAMwz
            /8wzzMwzmcwzZswzM8wzAMwA/8wAzMwAmcwAZswAM8wAAJn//5n/
            zJn/mZn/Zpn/M5n/AJnM/5nMzJnMmZnMZpnMM5nMAJmZ/5mZzJmZ
            mZmZZpmZM5mZAJlm/5lmzJlmmZlmZplmM5lmAJkz/5kzzJkzmZkz
            ZpkzM5kzAJkA/5kAzJkAmZkAZpkAM5kAAGb//2b/zGb/mWb/Zmb/
            M2b/AGbM/2bMzGbMmWbMZmbMM2bMAGaZ/2aZzGaZmWaZZmaZM2aZ
            AGZm/2ZmzGZmmWZmZmZmM2ZmAGYz/2YzzGYzmWYzZmYzM2YzAGYA
            /2YAzGYAmWYAZmYAM2YAADP//zP/zDP/mTP/ZjP/MzP/ADPM/zPM
            zDPMmTPMZjPMMzPMADOZ/zOZzDOZmTOZZjOZMzOZADNm/zNmzDNm
            mTNmZjNmMzNmADMz/zMzzDMzmTMzZjMzMzMzADMA/zMAzDMAmTMA
            ZjMAMzMAAAD//wD/zAD/mQD/ZgD/MwD/AADM/wDMzADMmQDMZgDM
            MwDMAACZ/wCZzACZmQCZZgCZMwCZAABm/wBmzABmmQBmZgBmMwBm
            AAAz/wAzzAAzmQAzZgAzMwAzAAAA/wAAzAAAmQAAZgAAM+4AAN0A
            ALsAAKoAAIgAAHcAAFUAAEQAACIAABEAAADuAADdAAC7AACqAACI
            AAB3AABVAABEAAAiAAARAAAA7gAA3QAAuwAAqgAAiAAAdwAAVQAA
            RAAAIgAAEe7u7t3d3bu7u6qqqoiIiHd3d1VVVURERCIiIhEREQAA
            ACH5BAEAAAAALAAAAAAgABgAAAiNAAH8G0iwoMGDCAcKTMiw4UBw
            BPXVm0ixosWLFvVBHFjPoUeC9Tb+6/jRY0iQ/8iVbHiS40CVKxG2
            HEkQZsyCM0mmvGkw50uePUV2tEnOZkyfQA8iTYpTKNOgKJ+C3AhO
            p9SWVaVOfWj1KdauTL9q5UgVbFKsEjGqXVtP40NwcBnCjXtw7tx/
            C8cSBBAQADs=
        """ ),

        'Switch': PhotoImage( data=r"""
            R0lGODlhIAAYAPcAMf//////zP//mf//Zv//M///AP/M///MzP/M
            mf/MZv/MM//MAP+Z//+ZzP+Zmf+ZZv+ZM/+ZAP9m//9mzP9mmf9m
            Zv9mM/9mAP8z//8zzP8zmf8zZv8zM/8zAP8A//8AzP8Amf8AZv8A
            M/8AAMz//8z/zMz/mcz/Zsz/M8z/AMzM/8zMzMzMmczMZszMM8zM
            AMyZ/8yZzMyZmcyZZsyZM8yZAMxm/8xmzMxmmcxmZsxmM8xmAMwz
            /8wzzMwzmcwzZswzM8wzAMwA/8wAzMwAmcwAZswAM8wAAJn//5n/
            zJn/mZn/Zpn/M5n/AJnM/5nMzJnMmZnMZpnMM5nMAJmZ/5mZzJmZ
            mZmZZpmZM5mZAJlm/5lmzJlmmZlmZplmM5lmAJkz/5kzzJkzmZkz
            ZpkzM5kzAJkA/5kAzJkAmZkAZpkAM5kAAGb//2b/zGb/mWb/Zmb/
            M2b/AGbM/2bMzGbMmWbMZmbMM2bMAGaZ/2aZzGaZmWaZZmaZM2aZ
            AGZm/2ZmzGZmmWZmZmZmM2ZmAGYz/2YzzGYzmWYzZmYzM2YzAGYA
            /2YAzGYAmWYAZmYAM2YAADP//zP/zDP/mTP/ZjP/MzP/ADPM/zPM
            zDPMmTPMZjPMMzPMADOZ/zOZzDOZmTOZZjOZMzOZADNm/zNmzDNm
            mTNmZjNmMzNmADMz/zMzzDMzmTMzZjMzMzMzADMA/zMAzDMAmTMA
            ZjMAMzMAAAD//wD/zAD/mQD/ZgD/MwD/AADM/wDMzADMmQDMZgDM
            MwDMAACZ/wCZzACZmQCZZgCZMwCZAABm/wBmzABmmQBmZgBmMwBm
            AAAz/wAzzAAzmQAzZgAzMwAzAAAA/wAAzAAAmQAAZgAAM+4AAN0A
            ALsAAKoAAIgAAHcAAFUAAEQAACIAABEAAADuAADdAAC7AACqAACI
            AAB3AABVAABEAAAiAAARAAAA7gAA3QAAuwAAqgAAiAAAdwAAVQAA
            RAAAIgAAEe7u7t3d3bu7u6qqqoiIiHd3d1VVVURERCIiIhEREQAA
            ACH5BAEAAAAALAAAAAAgABgAAAhwAAEIHEiwoMGDCBMqXMiwocOH
            ECNKnEixosWB3zJq3Mixo0eNAL7xG0mypMmTKPl9Cznyn8uWL/m5
            /AeTpsyYI1eKlBnO5r+eLYHy9Ck0J8ubPmPOrMmUpM6UUKMa/Ui1
            6saLWLNq3cq1q9evYB0GBAA7
        """ ),

        'Link': PhotoImage( data=r"""
            R0lGODlhFgAWAPcAMf//////zP//mf//Zv//M///AP/M///MzP/M
            mf/MZv/MM//MAP+Z//+ZzP+Zmf+ZZv+ZM/+ZAP9m//9mzP9mmf9m
            Zv9mM/9mAP8z//8zzP8zmf8zZv8zM/8zAP8A//8AzP8Amf8AZv8A
            M/8AAMz//8z/zMz/mcz/Zsz/M8z/AMzM/8zMzMzMmczMZszMM8zM
            AMyZ/8yZzMyZmcyZZsyZM8yZAMxm/8xmzMxmmcxmZsxmM8xmAMwz
            /8wzzMwzmcwzZswzM8wzAMwA/8wAzMwAmcwAZswAM8wAAJn//5n/
            zJn/mZn/Zpn/M5n/AJnM/5nMzJnMmZnMZpnMM5nMAJmZ/5mZzJmZ
            mZmZZpmZM5mZAJlm/5lmzJlmmZlmZplmM5lmAJkz/5kzzJkzmZkz
            ZpkzM5kzAJkA/5kAzJkAmZkAZpkAM5kAAGb//2b/zGb/mWb/Zmb/
            M2b/AGbM/2bMzGbMmWbMZmbMM2bMAGaZ/2aZzGaZmWaZZmaZM2aZ
            AGZm/2ZmzGZmmWZmZmZmM2ZmAGYz/2YzzGYzmWYzZmYzM2YzAGYA
            /2YAzGYAmWYAZmYAM2YAADP//zP/zDP/mTP/ZjP/MzP/ADPM/zPM
            zDPMmTPMZjPMMzPMADOZ/zOZzDOZmTOZZjOZMzOZADNm/zNmzDNm
            mTNmZjNmMzNmADMz/zMzzDMzmTMzZjMzMzMzADMA/zMAzDMAmTMA
            ZjMAMzMAAAD//wD/zAD/mQD/ZgD/MwD/AADM/wDMzADMmQDMZgDM
            MwDMAACZ/wCZzACZmQCZZgCZMwCZAABm/wBmzABmmQBmZgBmMwBm
            AAAz/wAzzAAzmQAzZgAzMwAzAAAA/wAAzAAAmQAAZgAAM+4AAN0A
            ALsAAKoAAIgAAHcAAFUAAEQAACIAABEAAADuAADdAAC7AACqAACI
            AAB3AABVAABEAAAiAAARAAAA7gAA3QAAuwAAqgAAiAAAdwAAVQAA
            RAAAIgAAEe7u7t3d3bu7u6qqqoiIiHd3d1VVVURERCIiIhEREQAA
            ACH5BAEAAAAALAAAAAAWABYAAAhIAAEIHEiwoEGBrhIeXEgwoUKG
            Cx0+hGhQoiuKBy1irChxY0GNHgeCDAlgZEiTHlFuVImRJUWXEGEy
            lBmxI8mSNknm1Dnx5sCAADs=
        """ )
    }


if __name__ == '__main__':
  import thread 
  from time import sleep

  app = NetVis()
  app.after(2000, app.update)

  def thread_func(app):
    while True:
      s = Switch('sx')
      app.writeMsg(NetVisMsg(
        NetVisMsg.MSG_TYPE_ADD, NetVisMsg.MSG_OBJ_TYPE_SWITCH, switch=s))
      sleep(2)

  thread.start_new(thread_func, (app,))

  app.mainloop()


