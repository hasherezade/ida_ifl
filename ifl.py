#!/usr/bin/env python
#
# IFL - Interactive Functions List
#
# how to install: copy the script into plugins directory, i.e: C:\Program Files\IDA 6.8\plugins
# then:
# run from IDA menu: View -> PLUGIN_NAME
# or press: PLUGIN_HOTKEY
#
"""
(c) hasherezade, 2015 run via IDA Pro 6.8
"""
__VERSION__ = '1.2'
__AUTHOR__ = 'hasherezade'

PLUGIN_NAME = "IFL - Interactive Functions List"
PLUGIN_HOTKEY = "Alt-F"

import idautils
from idaapi import *
from idc import *

from idaapi import PluginForm
from PySide import QtGui, QtCore
from PySide.QtCore import QObject, Signal, Slot

# --------------------------------------------------------------------------
# custom functions:
# --------------------------------------------------------------------------

def rva_to_va(rva):
    base = idaapi.get_imagebase()
    return rva + base
    
def va_to_rva(va):
    base = idaapi.get_imagebase()
    return va - base

def function_at(ea):
    start = ea
    functions = Functions(start)
    for func in Functions():
        return func
    return None
    
def parse_function_args(ea):
  local_variables = [ ]
  arguments = [ ]
  current = local_variables

  frame = idc.GetFrame(ea)
  arg_string = ""
  if frame == None:
    return ""
        
  start = idc.GetFirstMember(frame)
  end = idc.GetLastMember(frame)
  count = 0
  max_count = 10000
  args_str = ""     
  while start <= end and count <= max_count:
    size = idc.GetMemberSize(frame, start)
    count = count + 1
    if size == None:
      start = start + 1
      continue

    name = idc.GetMemberName(frame, start)  
    start += size
            
    if name in [" r", " s"]:
      # Skip return address and base pointer
      current = arguments
      continue
    arg_string += " " + name
    current.append(name)
  args_str = ", ".join(arguments)
  if len(args_str) == 0:
    args_str = "void"
  return "(" + args_str + ")"

def parse_function_type(ea, end=None):
  frame = idc.GetFrame(ea)
  if frame == None:
    return ""
  if end == None: #try to find end
      func = function_at(ea)
      if not func :
        return "?"
      end = PrevAddr(GetFunctionAttr(func, FUNCATTR_END)) 
  end_addr = end
  mnem = GetDisasm(end_addr)
  
  if not "ret" in mnem:
    #it's not a real end, get instruction before...
    end_addr = PrevAddr(end)
    if end_addr == BADADDR:
      #cannot get the real end
      return ""
    mnem = GetDisasm(end_addr)

  if not "ret" in mnem:
    #cannot get the real end
    return ""

  op = GetOpType(end_addr, 0)
  if op == o_void:
    #retn has NO parameters
    return "__cdecl"
  #retn has parameters
  return "__stdcall"

def _getFunctionType(start, end=None):
    type = GetType(start)
    if type == None:
        return parse_function_type(start, end)
    args_start = type.find('(')
    if not args_start == None:
        type = type[:args_start]
    return type
    
def _isFunctionMangled(ea):
    name = GetFunctionName(ea)
    disable_mask = GetLongPrm(INF_SHORT_DN)
    if Demangle(name, disable_mask) == None:
        return False
    return True
    
def _getFunctionNameAt(ea):
    name = GetFunctionName(ea)
    disable_mask = GetLongPrm(INF_SHORT_DN)
    demangled_name = Demangle(name, disable_mask)
    if demangled_name == None:
        return name
    args_start = demangled_name.find('(')
    if args_start == None:
        return demangled_name
    return demangled_name[:args_start]

def _getArgsDescription(ea):
    name = Demangle(GetFunctionName(ea), GetLongPrm(INF_SHORT_DN)) #get from mangled name
    if not name:
        name = GetType(ea) #get from type
        if not name:
            return parse_function_args(ea) #cannot get params from the mangled name
    args_start = name.find('(')
    if args_start != None and args_start != (-1):
        return name[args_start:]
    return ""
    
def _getArgsNum(ea):
    args = _getArgsDescription(ea)
    if not args:
        return 0
    delimiter = ','
    args_list = args.split(delimiter)
    args_num = 0
    for arg in args_list:
        if arg == "()" or arg == "(void)":
            continue
        args_num += 1
    return args_num
    
# --------------------------------------------------------------------------
# custom data types:
# --------------------------------------------------------------------------

#Global DataManager

class DataManager(QObject):
    updateSignal = Signal()
    
    def __init__(self, parent=None):
        QtCore.QObject.__init__(self, parent=parent)
        self.currentRva = long(BADADDR)
        
    def setFunctionName(self, start, func_name):
        flags = idaapi.SN_NOWARN | idaapi.SN_NOCHECK
        if idc.MakeNameEx(start, func_name, flags):
            self.updateSignal.emit()
            return True
        return False
 
    def setCurrentRva(self, rva):
        if self.currentRva == rva:
            return # nothing changed
            
        if rva is None:
            rva = long(BADADDR) 
        self.currentRva = long(rva)
        self.updateSignal.emit()
 
# --------------------------------------------------------------------------

class FunctionInfo_t():
    def __init__(self, start, end, refs_list, called_list, is_import=False):
        self.start = start
        self.end = end
        self.args_num = _getArgsNum(start)
        self.type = _getFunctionType(start, end)
        self.is_import = is_import
        self.refs_list = refs_list
        self.called_list = called_list
    
    def contains(self, addr):
        bng = self.start
        end = self.end
        #swap if order is opposite:
        if self.start > self.end:
            end = self.start
            start = self.end
        if addr >= bgn and  addr < end:
            return True
        return False
# --------------------------------------------------------------------------
# custom models:
# --------------------------------------------------------------------------
class TableModel_t(QtCore.QAbstractTableModel):
    """Model for the table """
    COL_START = 0
    COL_END = 1
    COL_NAME = 2
    COL_TYPE = 3
    COL_ARGS = 4
    COL_REFS = 5
    COL_CALLED = 6
    COL_IMPORT = 7
    COL_COUNT = 8
    header_names = ['Start', 'End', 'Name', 'Type', 'Args', 'Is refered by', 'Refers to', 'Imported?']
    
#private:

    def _displayHeader(self, orientation, col):
      if orientation == QtCore.Qt.Vertical:
        return None
      if col == self.COL_START:
        return self.header_names[self.COL_START]
      if col == self.COL_END:
        return self.header_names[self.COL_END]
      if col == self.COL_TYPE:
        return self.header_names[self.COL_TYPE]
      if col == self.COL_ARGS:
        return self.header_names[self.COL_ARGS]
      if col == self.COL_NAME:
        return self.header_names[self.COL_NAME]
      if col == self.COL_REFS:
        return self.header_names[self.COL_REFS]
      if col == self.COL_CALLED:
        return self.header_names[self.COL_CALLED]
      if col == self.COL_IMPORT:
        return self.header_names[self.COL_IMPORT]
      return None
      
    def _displayData(self, row, col):
      func_info = self.function_info_list[row]
      if col == self.COL_START:
        return "%08x" % func_info.start
      if col == self.COL_END:
        return "%08x" % func_info.end
      if col == self.COL_TYPE:
        return func_info.type
      if col == self.COL_ARGS:
        return _getArgsDescription(func_info.start)
      if col == self.COL_NAME:
        return _getFunctionNameAt(func_info.start)
      if col == self.COL_REFS:
        return len(func_info.refs_list)
      if col == self.COL_CALLED:
        return len(func_info.called_list)
      if col == self.COL_IMPORT:
        if func_info.is_import:
            return "+"
        return "-"
      return None
      
    def _displayToolTip(self, row, col):
      func_info = self.function_info_list[row]
      if col == self.COL_START or col == self.COL_END:
        return "Double Click to follow"
      if col == self.COL_NAME:
        return "Double Click to edit"
      if col == self.COL_REFS:
        return self._listRefs(func_info.refs_list)
      if col == self.COL_CALLED:
        return self._listRefs(func_info.called_list)
      return ""
      
    def _displayBackground(self, row, col):
      func_info = self.function_info_list[row]
      if col == self.COL_START or col == self.COL_END:
        return QtGui.QColor("lightblue")
        
      if col == self.COL_NAME:
        if func_info.is_import :
            return QtGui.QColor("orange")
        return QtGui.QColor("khaki")
      return None
     
    def _listRefs(self, refs_list):
      str_list = []
      for ea, ea_to in refs_list:
        str = "%08x @ %s" % (ea, _getFunctionNameAt(ea_to))
        str_list.append(str)
      return '\n'.join(str_list)  
      
#public:
    def __init__(self, function_info_list, parent=None, *args):
        super(TableModel_t, self).__init__()
        self.function_info_list = function_info_list
        
    def isFollowable(self, col):
        if col == self.COL_START:
            return True
        if col == self.COL_END:
            return True
        return False
        
#Qt4 API
    def rowCount(self, parent):
        return len(self.function_info_list)

    def columnCount(self, parent):
        return self.COL_COUNT
    
    def setData(self, index, content, role):
      if not index.isValid():
        return False
      func_info = self.function_info_list[index.row()]
      if index.column() == self.COL_NAME:
        MakeNameEx(func_info.start, str(content), SN_NOWARN) 
      return True
      
    def data(self, index, role):
        if not index.isValid():
            return None
        col = index.column()
        row = index.row()
        if len(self.function_info_list) <= row:
          return None
          
        func_info = self.function_info_list[row]
        
        if role == QtCore.Qt.UserRole:
          if col == self.COL_START:
            return func_info.start
          elif col == self.COL_END:
            return func_info.end
          else:
            return func_info.start
        elif role == QtCore.Qt.DisplayRole or role == QtCore.Qt.EditRole:
          return self._displayData(row, col)
        elif role == QtCore.Qt.ToolTipRole:
          return self._displayToolTip(row, col)
        elif role == QtCore.Qt.BackgroundColorRole:
          return self._displayBackground(row, col)
        else:
            return None

    def flags(self, index):
        if not index.isValid():
            return None
        flags = QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable
        if index.column() == self.COL_NAME:
          return flags | QtCore.Qt.ItemIsEditable
        return flags
        
    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole:
            return self._displayHeader(orientation, section)
        else:
            return None
# --------------------------------------------------------------------------
class RefsTableModel_t(QtCore.QAbstractTableModel):
    """Model for the table """
    COL_NAME = 0
    COL_ADDR = 1
    COL_TOADDR = 2
    COL_COUNT = 3
    
#private:
    def _displayHeader(self, orientation, col):
        if orientation == QtCore.Qt.Vertical:
            return None
        if col == self.COL_ADDR:
            return "From Address"
        if col == self.COL_TOADDR:
            return "To Address"
        if col == self.COL_NAME:
            return "Foreign Val."
        return None
    
    def _getTargetAddr(self, row):
        curr_ref_fromaddr = self.refs_list[row][0] #fromaddr
        curr_ref_addr = self.refs_list[row][1] #toaddr
        target_addr = BADADDR
        if self.is_refs_to :
            target_addr = curr_ref_fromaddr
        else:
            target_addr = curr_ref_addr
        return target_addr
            
    def _getForeignFuncName(self, row):
        curr_ref_fromaddr = self.refs_list[row][0] #fromaddr
        curr_ref_addr = self.refs_list[row][1] #toaddr
        
        target_addr = self._getTargetAddr(row)
        if GetMnem(target_addr) != "":
            func_name = _getFunctionNameAt(target_addr)
            if func_name:
                return func_name

        addr_str = "[%08lx]" % target_addr
        target_name = GetDisasm(target_addr)
        return addr_str+ " : " + GetDisasm(target_addr)
        
    def _displayData(self, row, col):
    
      if len(self.refs_list) <= row:
          return None    
      curr_ref_fromaddr = self.refs_list[row][0] #fromaddr
      curr_ref_addr = self.refs_list[row][1] #toaddr
      if col == self.COL_ADDR:
        return "%08x" % curr_ref_fromaddr
      if col == self.COL_TOADDR:
        return "%08x" % curr_ref_addr
      if col == self.COL_NAME:
        return self._getForeignFuncName(row)
      return None
    
    def _getAddrToFollow(self, row, col):
        if col == self.COL_ADDR:
            return self.refs_list[row][0]
        if col == self.COL_TOADDR:
            return self.refs_list[row][1]
        return BADADDR
        
    def _displayBackground(self, row, col):
        if self.isFollowable(col):
            return QtGui.QColor("lightblue")
        return None
      
#public:
    def __init__(self, function_info_list, is_refs_to=True, parent=None, *args):
        super(RefsTableModel_t, self).__init__()
        self.function_info_list = function_info_list
        self.curr_index = (-1)
        self.refs_list = []
        self.is_refs_to = is_refs_to
        
    def isFollowable(self, col):
        if col == self.COL_ADDR:
            return True
        if col == self.COL_TOADDR:
            return True
        return False
        
    def findOffsetIndex(self, data):
        index = 0
        for func_info in self.function_info_list:
            if data >= func_info.start and data <= func_info.end:
                return index
            index += 1
        return (-1)

    def setCurrentIndex(self, curr_index):
        self.curr_index = curr_index
        if self.curr_index == (-1) or self.curr_index >= len(self.function_info_list):
          #reset list
          self.refs_list = []
        else:
            if self.is_refs_to :
                self.refs_list = self.function_info_list[self.curr_index].refs_list
            else:
                self.refs_list = self.function_info_list[self.curr_index].called_list
        self.reset()
    
#Qt4 API
    def rowCount(self, parent=None):
        return len(self.refs_list)

    def columnCount(self, parent):
        return self.COL_COUNT
    
    def data(self, index, role):
        if not index.isValid():
            return None
        col = index.column()
        row = index.row()
        if len(self.refs_list) <= row:
          return None
          
        curr_ref_addr = self.refs_list[row][0]
        
        if role == QtCore.Qt.UserRole:
          if self.isFollowable(col):
            return self._getAddrToFollow(row, col)
        elif role == QtCore.Qt.DisplayRole or role == QtCore.Qt.EditRole:
          return self._displayData(row, col)
        elif role == QtCore.Qt.BackgroundColorRole:
          return self._displayBackground(row, col)
        else:
            return None

    def flags(self, index):
        if not index.isValid():
            return None
        flags = QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable
        return flags
        

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole:
            return self._displayHeader(orientation, section)
        else:
            return None

# --------------------------------------------------------------------------
# custom views:
  
COLOR_NORMAL = 0xFFFFFF

class FunctionsView_t(QtGui.QTableView):

    # private    
    def _set_segment_color(self, ea, color):
        seg = idaapi.getseg(ea)
        seg.color = COLOR_NORMAL
        seg.update()
   
    # public
    def __init__(self, dataManager, color_hilight, func_model, parent=None):
        super(FunctionsView_t, self).__init__(parent=parent)
        self.setSelectionMode(QtGui.QAbstractItemView.SingleSelection)
        #
        self.prev_addr = BADADDR
        self.color_hilight = color_hilight
        self.func_model = func_model
        self.dataManager = dataManager
        #
        self.setMouseTracking(True)
        self.setAutoFillBackground(True)
        
    #Qt API
    def currentChanged(self, current, previous):
        index_data = self.get_index_data(current)
        self.dataManager.setCurrentRva(index_data)
        
    def hilight_addr(self, addr):
        if self.prev_addr != BADADDR:
            ea = self.prev_addr
            self._set_segment_color(ea, COLOR_NORMAL)
            SetColor(ea, CIC_ITEM, COLOR_NORMAL)
        if addr != BADADDR:
            ea = addr
            self._set_segment_color(ea, COLOR_NORMAL)
            SetColor(addr, CIC_ITEM, self.color_hilight)
        self.prev_addr = addr
        
    def get_index_data(self, index):
        if not index.isValid():
            return None
            
        index_data = index.data(QtCore.Qt.UserRole)

        if not type(index_data) is long:
            return None
        return index_data
        
    def mousePressEvent(self, event):
        event.accept()
        index = self.indexAt(event.pos())
        data = self.get_index_data(index)
        super(QtGui.QTableView, self).mousePressEvent(event)
      
    def mouseDoubleClickEvent(self, event):
        event.accept()
        index = self.indexAt(event.pos())
        if not index.isValid():
            return
        data = self.get_index_data(index)  
        if not data:
            super(QtGui.QTableView, self).mouseDoubleClickEvent(event)
            return
        col = index.column()
        if self.func_model.isFollowable(col):
            self.hilight_addr(data)
            Jump(data)
        super(QtGui.QTableView, self).mouseDoubleClickEvent(event)
        
    def mouseMoveEvent(self, event):
        index = self.indexAt(event.pos())
        if not index.isValid():
            return
        col = index.column()
        if self.func_model.isFollowable(col):
            self.setCursor(QtCore.Qt.PointingHandCursor)
        else:
            self.setCursor(QtCore.Qt.ArrowCursor)
        
    def leaveEvent(self, event):
        self.setCursor(QtCore.Qt.ArrowCursor)
        
    def OnDestroy(self):
        self.hilight_addr(BADADDR)
        
# --------------------------------------------------------------------------

class FunctionsListForm_t(PluginForm):
#private
    _COLOR_HILIGHT_FUNC = 0xFFDDBB # BBGGRR
    _COLOR_HILIGHT_REFTO = 0xBBFFBB
    _COLOR_HILIGHT_REFFROM = 0xDDBBFF
    
    def _getCallingOffset(self, func, called_list):
        start = GetFunctionAttr(func, FUNCATTR_START)
        end = PrevAddr(GetFunctionAttr(func, FUNCATTR_END))
        func_name = _getFunctionNameAt(start)
        curr = start
        calling_list = []
        while (True):
            if curr >= end:
                break
            op = GetOperandValue(curr, 0)
            if op in called_list:
                calling_list.append((curr, op))
            curr = NextAddr(curr)
        return calling_list
    
    def _listFunctionsAddr(self):
        fn_list = list()
        for func in Functions():
            start = GetFunctionAttr(func, FUNCATTR_START)
            fn_list.append(start)
        return fn_list
        
    def _saveFunctionsNames(self, file_name):
        if file_name is None or len(file_name) == 0:
            return False
        delim = ","
        fn_list = list()
        for func in Functions():
            start = GetFunctionAttr(func, FUNCATTR_START)
            func_name = _getFunctionNameAt(start)
            start_rva = va_to_rva(start)
            line = "%lx%c%s" %(start_rva, delim, func_name)
            fn_list.append(line)   
        idaapi.msg(str(file_name))
        with open(file_name, 'w') as f:
            for item in fn_list:
                f.write("%s\n" % item)
            return True     
        return False

    def _loadFunctionsNames(self,file_name):
        if file_name is None or len(file_name) == 0:
            return False
        curr_functions = self._listFunctionsAddr()
        delim = "," # new delimiter (for CSV format)
        delim2 = ":" # old delimiter
        loaded = 0
        with open(file_name, 'r') as f:
            for line in f.readlines():
                line = line.strip()
                fn = line.split(delim)
                if len(fn) != 2:
                    fn = line.split(delim2) # try old delimiter
                if len(fn) != 2:
                    continue
                start = int(fn[0].strip(), 16)
                func_name = fn[1].strip()
                if start < idaapi.get_imagebase(): # it is RVA
                    start = rva_to_va(start) # convert to VA
                if start in curr_functions:
                    if self.subDataManager.setFunctionName(start, func_name) == True:
                        loaded += 1
        return loaded

    def imports_names_callback(self, ea, name, ord):
        self.importsSet.add(ea)
        self.importNamesSet.add(name)
        # True -> Continue enumeration
        return True
        
    def _loadImports(self):
        self.importsSet = set()
        self.importNamesSet = set()
        nimps = idaapi.get_import_module_qty()
        for i in xrange(0, nimps):
            idaapi.enum_import_names(i, self.imports_names_callback)

    def _isImportName(self, name):
        if name in self.importNamesSet:
            return True
        return False
    
    def _isImportStart(self, start):
        if start in self.importsSet:
            return True
        if GetMnem(start) == 'call':
            return False
        #print GetMnem(start)
        op = GetOperandValue(start, 0)
        if op in self.importsSet:
            return True
        return False
    
    def _listRefsTo(self, start):
        func_refs_to = XrefsTo(start, 1)
        refs_list = []
        for ref in func_refs_to:
          if idc.GetMnem(ref.frm) == "":
            continue
          refs_list.append((ref.frm, start))
        return refs_list
    
    def _listRefsFrom(self, func, start, end):
        dif = end - start
        called_list = []
        func_name = _getFunctionNameAt(start)
        
        for indx in xrange(0, dif):
          addr = start + indx
          func_refs_from = XrefsFrom(addr, 1)
          for ref in func_refs_from:
            if _getFunctionNameAt(ref.to) == func_name:
              #skip jumps inside self
              continue 
            called_list.append(ref.to)
        calling_list = self._getCallingOffset(func, called_list)
        return calling_list
    
    def _loadLocals(self):
      #loadImports first : 
      self._loadImports()
      
      for func in Functions():
        start = GetFunctionAttr(func, FUNCATTR_START)
        end = PrevAddr(GetFunctionAttr(func, FUNCATTR_END))
        
        is_import = self._isImportStart(start)
        
        refs_list = self._listRefsTo(start)
        calling_list = self._listRefsFrom(func, start, end)

        func_info = FunctionInfo_t(start, end, refs_list, calling_list, is_import)
        self.functionsMap[va_to_rva(start)] = func_info
        self.functionsMap[va_to_rva(end)] = func_info
        self.addr_list.append(func_info)
    
    def _setup_sorted_model(self, view, model):
        sorted_model = QtGui.QSortFilterProxyModel()    
        sorted_model.setDynamicSortFilter(True)
        sorted_model.setSourceModel(model)
        view.setModel(sorted_model)
        view.setSortingEnabled(True)
        #
        sorted_model.setParent(view)        
        model.setParent(sorted_model)
        return sorted_model
        
    def _update_current_offset(self, view, refs_model, offset):
        if offset:
            index = refs_model.findOffsetIndex(offset)
        else:
            index = (-1)
        refs_model.setCurrentIndex(index)
        refs_model.reset()
        view.reset()
        view.repaint()
    
    def _update_function_name(self, ea):
        try:
            func_info = self.functionsMap[va_to_rva(ea)]
        except KeyError:
            return
            
        func_type = func_info.type
        func_args = _getArgsDescription(ea)
        func_name = _getFunctionNameAt(ea)
        func_name = _getFunctionNameAt(ea)
        self.refs_label.setText(func_type + " <b>"+func_name+"</b> " + func_args)

    def _update_ref_tabs(self, ea):
        tocount = 0
        fromcount = 0
        try:
            func_info = self.functionsMap[va_to_rva(ea)]
            tocount = len(func_info.refs_list)
            fromcount = len(func_info.called_list)
        except KeyError:
            pass
        self.refs_tabs.setTabText(0,  "Is refered by %d:" % tocount)
        self.refs_tabs.setTabText(1,  "Refers to %d:" % fromcount)
        
    def adjustColumnsToContents(self):
        self.addr_view.resizeColumnToContents(0)
        self.addr_view.resizeColumnToContents(1)     
        self.addr_view.resizeColumnToContents(2)
        #
        self.addr_view.resizeColumnToContents(5)     
        self.addr_view.resizeColumnToContents(6)
        self.addr_view.resizeColumnToContents(7)
#public
    @QtCore.Slot()
    def longoperationcomplete(self):
        data = g_DataManager.currentRva
        self.setRefOffset(data)
                
    def setRefOffset(self, data):
        if not data:
            return  
        self._update_current_offset(self.refs_view, self.refsto_model, data)
        self._update_current_offset(self.refsfrom_view, self.refsfrom_model, data)
        self._update_ref_tabs(data)
        self._update_function_name(data)
        
    def filterByColumn(self, col_num, str):
        filter_type = QtCore.QRegExp.FixedString
        sensitivity = QtCore.Qt.CaseInsensitive
        if self.criterium_id != 0:
            filter_type = QtCore.QRegExp.RegExp
        self.addr_sorted_model.setFilterRegExp(QtCore.QRegExp(str, sensitivity, filter_type));
        self.addr_sorted_model.setFilterKeyColumn(col_num)
        
    def filterChanged(self):
        self.filterByColumn(self.filter_combo.currentIndex(), self.filter_edit.text() )
        
    def criteriumChanged(self):
        self.criterium_id = self.criterium_combo.currentIndex()
        if self.criterium_id == 0:
            self.filter_edit.setPlaceholderText("keyword")
        else:
            self.filter_edit.setPlaceholderText("regex")
        self.filterChanged()
        
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """
        
        #init data structures:
        self.functionsMap = dict()
        self.addr_list = []
        self._loadLocals()
        self.criterium_id = 0
        
        # Get parent widget
        self.parent = self.FormToPySideWidget(form)
        
        # Create models
        self.table_model = TableModel_t(self.addr_list)
        self.subDataManager = DataManager()
        
        #init
        self.addr_sorted_model = QtGui.QSortFilterProxyModel()    
        self.addr_sorted_model.setDynamicSortFilter(True)
        self.addr_sorted_model.setSourceModel(self.table_model)
        self.addr_view = FunctionsView_t(g_DataManager, self._COLOR_HILIGHT_FUNC, self.table_model)
        self.addr_view.setModel(self.addr_sorted_model)
        self.addr_view.setSortingEnabled(True)
        self.addr_view.setWordWrap(False)
        self.addr_view.setAlternatingRowColors(True)
        self.addr_view.horizontalHeader().setStretchLastSection(False);
        self.addr_view.verticalHeader().show()
    
        self.adjustColumnsToContents()
        #
        self.refsto_model = RefsTableModel_t(self.addr_list, True)
        self.refs_view = FunctionsView_t(self.subDataManager, self._COLOR_HILIGHT_REFTO, self.refsto_model)
        self._setup_sorted_model(self.refs_view, self.refsto_model)
        self.refs_view.setColumnHidden(RefsTableModel_t.COL_TOADDR, True)
        self.refs_view.setWordWrap(False)
        self.refs_view.setAlternatingRowColors(True)
        
        font = self.refs_view.font()
        font.setPointSize(8)
        self.refs_view.setFont(font)
        #
        self.refsfrom_model = RefsTableModel_t(self.addr_list, False)
        self.refsfrom_view = FunctionsView_t(self.subDataManager, self._COLOR_HILIGHT_REFFROM, self.refsfrom_model)
        self._setup_sorted_model(self.refsfrom_view, self.refsfrom_model)
        self.refsfrom_view.setColumnHidden(RefsTableModel_t.COL_TOADDR, True)
        self.refsfrom_view.setWordWrap(False)
        self.refsfrom_view.setAlternatingRowColors(True)
        
        #important for proper order of objects destruction:
        self.table_model.setParent(self.addr_sorted_model)
        self.addr_sorted_model.setParent(self.addr_view)

        # connect SIGNAL
        g_DataManager.updateSignal.connect(self.longoperationcomplete)
        
        # Create a Tab widget for references:
        self.refs_tabs = QtGui.QTabWidget()
        self.refs_tabs.insertTab(0, self.refs_view, "Is refered by")
        self.refs_tabs.insertTab(1, self.refsfrom_view, "Refers to")
        
        # Create filter
        self.filter_edit = QtGui.QLineEdit()
        self.filter_edit.setPlaceholderText("keyword")
        self.filter_edit.textChanged.connect(self.filterChanged)
        
        self.filter_combo = QtGui.QComboBox()
        self.filter_combo.addItems(TableModel_t.header_names)
        self.filter_combo.setCurrentIndex(TableModel_t.COL_NAME)
        #connect SIGNAL
        self.filter_combo.activated.connect(self.filterChanged)
        
        self.criterium_combo = QtGui.QComboBox()
        criteria = ["contains", "matches"]
        self.criterium_combo.addItems(criteria)
        self.criterium_combo.setCurrentIndex(0)
        #connect SIGNAL
        self.criterium_combo.activated.connect(self.criteriumChanged)
        

        filter_panel = QtGui.QFrame()
        filter_layout = QtGui.QHBoxLayout()
        filter_layout.addWidget(QtGui.QLabel("Where "))
        filter_layout.addWidget(self.filter_combo)
        filter_layout.addWidget(self.criterium_combo)
        filter_layout.addWidget(self.filter_edit)
        
        filter_panel.setLayout(filter_layout)
        self.filter_edit.setFixedHeight(20)
        filter_panel.setFixedHeight(40)
        filter_panel.setAutoFillBackground(True)
        #
        self.refs_label = QtGui.QLabel("Function")
        self.refs_label.setTextFormat(QtCore.Qt.RichText)
        self.refs_label.setWordWrap(True)
        
        panel1 = QtGui.QFrame()
        layout1 = QtGui.QVBoxLayout()
        panel1.setLayout(layout1)
        
        layout1.addWidget(filter_panel)
        layout1.addWidget(self.addr_view)      
        layout1.setContentsMargins(0,0,0,0)

        panel2 = QtGui.QFrame()
        layout2 = QtGui.QVBoxLayout()
        layout2.addWidget(self.refs_label)
        layout2.addWidget(self.refs_tabs)
        layout2.addWidget(self._makeButtonsPanel())  
        layout2.setContentsMargins(0,10,0,0)
        panel2.setLayout(layout2)
        
        self.main_splitter = QtGui.QSplitter()
        self.main_splitter.setOrientation(QtCore.Qt.Vertical)
        self.main_splitter.addWidget(panel1)
        self.main_splitter.addWidget(panel2)
        
        # Populate PluginForm
        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.main_splitter)
        layout.setSpacing(0)
        layout.setContentsMargins(0,0,0,0)
        self.parent.setLayout(layout)

        idaapi.set_dock_pos(PLUGIN_NAME, "IDA HExview-1", idaapi.DP_RIGHT)
    
    def _makeButtonsPanel(self):
        buttons_panel = QtGui.QFrame()
        buttons_layout = QtGui.QHBoxLayout()
        buttons_panel.setLayout(buttons_layout)
        
        importButton = QtGui.QPushButton("Load names")
        importButton.clicked.connect(self.importNames)
        buttons_layout.addWidget(importButton)
        
        exportButton = QtGui.QPushButton("Save names")
        exportButton.clicked.connect(self.exportNames)
        buttons_layout.addWidget(exportButton)
        return buttons_panel
        
    def importNames(self):
        file_name, ext = QtGui.QFileDialog.getOpenFileName( None, "Export functions names", QtCore.QDir.homePath(), "CSV Files (*.csv);;TXT Files (*.txt);;All files (*)")
        if file_name is not None and len(file_name) > 0 :
            loaded = self._loadFunctionsNames(file_name)
            if loaded == 0:
                idaapi.warning("Failed importing functions names! Not matching offsets!")
            else:
                idaapi.info("Imported %d function names " % (loaded))
                
    def exportNames(self):
        file_name, ext = QtGui.QFileDialog.getSaveFileName( None, "Import functions names", QtCore.QDir.homePath(), "CSV Files (*.csv)")
        if file_name is not None and len(file_name) > 0 :
            if self._saveFunctionsNames(file_name) == False:
                idaapi.warning("Failed exporting functions names!")
            else:
                idaapi.info("Exported to: "+ file_name)
        
    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        #clear last selection
        self.addr_view.hilight_addr(BADADDR)
        self.refs_view.hilight_addr(BADADDR)
        self.refsfrom_view.hilight_addr(BADADDR)
        del self
        print "Closed"

    def Show(self):
        """Creates the form if not created or focuses it if it was"""
        return PluginForm.Show(self,
                               PLUGIN_NAME,
                               options = PluginForm.FORM_PERSIST)

# --------------------------------------------------------------------------
class IFLMenuManager():
    """ Manages menu items belonging to IFL"""

    # public
    def __init__(self):
        self.menuItems = None
        
    # private
    def _makeMenuItems(self):
        self.menuItems = list()
        
        if self._addMenuItem("View/", PLUGIN_NAME, PLUGIN_HOTKEY, 0, self._queryItem1, None) == False:
            return False

        return True
        
    def _destroyMenuItems(self):
        if self.menuItems is None:
            return
        for mItem in self.menuItems:
            idaapi.del_menu_item(self.menuItems)
            
    def _addMenuItem(self, menupath, name, hotkey, flags, pyfunc, args):
        menuItem = idaapi.add_menu_item(menupath, name, hotkey, flags, pyfunc, args)
        if menuItem is None:
            return False
        self.menuItems.append(menuItem)
        return True
        
    def _queryItem1(self):
        open_form()
        

# --------------------------------------------------------------------------

def open_form():
    global m_functionInfoForm
    global g_DataManager
    #-----
    try:
        g_DataManager
    except:
        g_DataManager = DataManager()
    #-----
    try:
        m_functionInfoForm
    except:
        idaapi.msg("Loading Interactive Function List...")
        m_functionInfoForm = FunctionsListForm_t()

    m_functionInfoForm.Show()

# --------------------------------------------------------------------------

#IDA api:

class funclister_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Interactive Functions List"

    help = "Interactive Function List. Comments? Remarks? Mail to: hasherezade@op.pl"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ''
    
    IFLMngr = None
 
    def init(self):
        IFLMngr = IFLMenuManager()
        if IFLMngr._makeMenuItems():
            return idaapi.PLUGIN_OK
        IFLMngr._destroyMenuItems()
        return idaapi.PLUGIN_SKIP
        
    def run(self, arg):
        open_form()
        pass

    def term(self):
        pass

def PLUGIN_ENTRY():
    return funclister_t()
    

