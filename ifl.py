#!/usr/bin/env python3
#
# IFL - Interactive Functions List
#
# how to install: copy the script into plugins directory, i.e: C:\Program Files\IDA <version>\plugins
# then:
# run from IDA menu: View -> PLUGIN_NAME
# or press: PLUGIN_HOTKEY
#
"""
CC-BY: hasherezade, run via IDA Pro >= 7.0
"""
__VERSION__ = '1.4.2.1'
__AUTHOR__ = 'hasherezade'

PLUGIN_NAME = "IFL - Interactive Functions List"
PLUGIN_HOTKEY = "Ctrl-Alt-F"

import idaapi  # type: ignore
import idc  # type: ignore
import ida_kernwin

from idaapi import BADADDR, jumpto, next_addr, o_void, prev_addr,\
    print_insn_mnem, set_cmt, set_name, SN_NOWARN
from idc import CIC_ITEM, demangle_name, FUNCATTR_END, FUNCATTR_FRAME,\
    get_func_attr, get_func_name, get_inf_attr, get_operand_type,\
    get_operand_value, get_type, GetDisasm, INF_SHORT_DN, set_color, \
    FUNCATTR_START
from idautils import Functions, XrefsFrom, XrefsTo  # type: ignore

from idaapi import PluginForm  # type: ignore
from PyQt5 import QtGui, QtCore, QtWidgets  # type: ignore
from PyQt5.QtCore import QObject, pyqtSignal  # type: ignore

from typing import Optional, List, Tuple, Any, Union

VERSION_INFO = f"IFL v{__VERSION__} - check for updates: https://github.com/hasherezade/ida_ifl"

transp_l = 230
light_theme = [ QtGui.QColor(173, 216, 230, transp_l), QtGui.QColor(255, 165, 0, transp_l), QtGui.QColor(240, 230, 140, transp_l) ]
transp_d = 70
dark_theme = [ QtGui.QColor(173, 216, 240, transp_d), QtGui.QColor(255, 0, 255, transp_d), QtGui.QColor(255, 130, 130, transp_d) ]

COLOR_HILIGHT_FUNC = 0xFFDDBB # BBGGRR
COLOR_HILIGHT_REFTO = 0xBBFFBB
COLOR_HILIGHT_REFFROM = 0xDDBBFF

IS_ALTERNATE_ROW = False

# --------------------------------------------------------------------------
# custom functions:
# --------------------------------------------------------------------------

# Theme 

def get_bg_color():
    w = ida_kernwin.get_current_widget()
    widget = ida_kernwin.PluginForm.FormToPyQtWidget(w)
    color = widget.palette().color(QtGui.QPalette.Background)
    return color

def is_darker(color1, color2):
    if QtGui.QColor(color2).lightness() > QtGui.QColor(color1).lightness():
        return False
    return True

def is_dark_theme():
    if is_darker(get_bg_color(), COLOR_HILIGHT_FUNC):
        return False
    return True

def color_to_val(color):
    return (((color.red() << 8) | color.green()) << 8) | color.blue()

def get_theme():
    theme = light_theme
    if is_dark_theme():
        theme = dark_theme
    return theme
	
# Addressing 

def rva_to_va(rva: int) -> int:
    base = idaapi.get_imagebase()
    return rva + base


def va_to_rva(va: int) -> int:
    base = idaapi.get_imagebase()
    return va - base

# Functions and args 

def function_at(ea: int) -> Optional[int]:
    start = ea
    functions = Functions(start)
    for func in functions:
        return func
    return None


def parse_function_args(ea: int) -> str:
    local_variables = []
    arguments = []
    current = local_variables

    frame = idc.get_func_attr(ea, FUNCATTR_FRAME)
    arg_string = ""
    if frame is None:
        return ""

    start = idc.get_first_member(frame)
    end = idc.get_last_member(frame)
    count = 0
    max_count = 10000
    args_str = ""
    while start <= end and count <= max_count:
        size = idc.get_member_size(frame, start)
        count = count + 1
        if size is None:
            start = start + 1
            continue

        name = idc.get_member_name(frame, start)
        start += size

        if name in [" r", " s"]:
            # Skip return address and base pointer
            current = arguments
            continue
        arg_string += f" {name}"
        current.append(name)
    args_str = ", ".join(arguments)
    if len(args_str) == 0:
        args_str = "void"
    return f"({args_str})"


def parse_function_type(ea: int, end: Optional[int] = None) -> str:
    frame = idc.get_func_attr(ea, FUNCATTR_FRAME)
    if frame is None:
        return ""
    if end is None:  # try to find end
        func = function_at(ea)
        if not func:
            return "?"
        end = prev_addr(get_func_attr(func, FUNCATTR_END))
    end_addr = end
    mnem = GetDisasm(end_addr)

    if "ret" not in mnem:
        # it's not a real end, get instruction before...
        end_addr = prev_addr(end)
        if end_addr == BADADDR:
            # cannot get the real end
            return ""
        mnem = GetDisasm(end_addr)

    if "ret" not in mnem:
        # cannot get the real end
        return ""

    op = get_operand_type(end_addr, 0)
    if op == o_void:
        # retn has NO parameters
        return "__cdecl"
    # retn has parameters
    return "__stdcall"


def _getFunctionType(start: int, end: Optional[int] = None) -> str:
    type = get_type(start)
    if type is None:
        return parse_function_type(start, end)
    args_start = type.find('(')
    if args_start is not None:
        type = type[:args_start]
    return type


def _isFunctionMangled(ea: int) -> bool:
    name = get_func_name(ea)
    disable_mask = get_inf_attr(INF_SHORT_DN)
    if demangle_name(name, disable_mask) is None:
        return False
    return True


def _getFunctionNameAt(ea: int) -> str:
    name = get_func_name(ea)
    disable_mask = get_inf_attr(INF_SHORT_DN)
    demangled_name = demangle_name(name, disable_mask)
    if demangled_name is None:
        return name
    args_start = demangled_name.find('(')
    if args_start is None:
        return demangled_name
    return demangled_name[:args_start]


def _getArgsDescription(ea: int) -> str:
    name = demangle_name(get_func_name(ea), get_inf_attr(INF_SHORT_DN))  # get from mangled name
    if not name:
        name = get_type(ea)  # get from type
        if not name:
            return parse_function_args(ea)  # cannot get params from the mangled name
    args_start = name.find('(')
    if args_start is not None and args_start != (-1):
        return name[args_start:]
    return ""


def _getArgsNum(ea: int) -> int:
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


# Global DataManager
class DataManager(QObject):
    """Keeps track on the changes in data and signalizies them.
    """

    updateSignal = pyqtSignal()

    def __init__(self, parent=None) -> None:
        QtCore.QObject.__init__(self, parent=parent)
        self.currentRva = BADADDR

    def setFunctionName(self, start: int, func_name: str) -> bool:
        flags = idaapi.SN_NOWARN | idaapi.SN_NOCHECK
        if idc.set_name(start, func_name, flags):
            self.updateSignal.emit()
            return True
        return False

    def setCurrentRva(self, rva: Optional[int]) -> None:
        if rva is None:
            rva = BADADDR
        self.currentRva = rva
        self.updateSignal.emit()

    def refreshData(self) -> None:
        self.updateSignal.emit()

# --------------------------------------------------------------------------


class FunctionInfo_t():
    """A class representing a single function's record.
    """

    def __init__(self, start: int, end: int, refs_list, called_list, is_import: bool = False) -> None:
        self.start = start
        self.end = end
        self.args_num = _getArgsNum(start)
        self.type = _getFunctionType(start, end)
        self.is_import = is_import
        self.refs_list = refs_list
        self.called_list = called_list

    def contains(self, addr: int) -> bool:
        """Check if the given address lies inside the function.
        """
        bgn = self.start
        end = self.end
        # swap if order is opposite:
        if self.start > self.end:
            end = self.start
            bgn = self.end
        if addr >= bgn and addr < end:
            return True
        return False
# --------------------------------------------------------------------------
# custom models:
# --------------------------------------------------------------------------


class TableModel_t(QtCore.QAbstractTableModel):
    """The model for the top view: storing all the functions.
    """

    COL_START = 0
    COL_END = 1
    COL_NAME = 2
    COL_TYPE = 3
    COL_ARGS = 4
    COL_REFS = 5
    COL_CALLED = 6
    COL_IMPORT = 7
    COL_COUNT = 8
    header_names = ['Start', 'End', 'Name', 'Type', 'Args', 'Is referred by', 'Refers to', 'Imported?']

# private:

    def _displayHeader(self, orientation: QtCore.Qt.Orientation, col: int) -> Optional[str]:
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

    def _displayData(self, row: int, col: int) -> Optional[Union[int, str]]:
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

    def _displayToolTip(self, row: int, col: int) -> str:
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

    def _displayBackground(self, row: int, col: int) -> Any:
        theme = get_theme()

        func_info = self.function_info_list[row]
        if col == self.COL_START or col == self.COL_END:
            return QtGui.QColor(theme[0])
        if col == self.COL_NAME:
            if func_info.is_import:
                return QtGui.QColor(theme[1])
            return QtGui.QColor(theme[2])
        return None

    def _listRefs(self, refs_list: List[Tuple[int, int]]) -> str:
        str_list = []
        for ea, ea_to in refs_list:
            str = "%08x @ %s" % (ea, _getFunctionNameAt(ea_to))
            str_list.append(str)
        return '\n'.join(str_list)

# public:
    def __init__(self, function_info_list, parent=None, *args) -> None:
        super(TableModel_t, self).__init__()
        self.function_info_list = function_info_list

    def isFollowable(self, col: int) -> bool:
        if col == self.COL_START:
            return True
        if col == self.COL_END:
            return True
        return False

# Qt API
    def rowCount(self, parent) -> int:
        return len(self.function_info_list)

    def columnCount(self, parent) -> int:
        return self.COL_COUNT

    def setData(self, index, content, role) -> bool:
        if not index.isValid():
            return False
        func_info = self.function_info_list[index.row()]
        if index.column() == self.COL_NAME:
            set_name(func_info.start, str(content), SN_NOWARN)
            g_DataManager.refreshData()
        return True

    def data(self, index, role) -> Any:
        if not index.isValid():
            return None
        col = index.column()
        row = index.row()

        func_info = self.function_info_list[row]

        if role == QtCore.Qt.UserRole:
            if col == self.COL_END:
                return func_info.end
            return func_info.start
        elif role == QtCore.Qt.DisplayRole or role == QtCore.Qt.EditRole:
            return self._displayData(row, col)
        elif role == QtCore.Qt.ToolTipRole:
            return self._displayToolTip(row, col)
        elif role == QtCore.Qt.BackgroundColorRole:
            return self._displayBackground(row, col)
        else:
            return None

    def flags(self, index) -> Any:
        if not index.isValid():
            return None
        flags = QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable
        if index.column() == self.COL_NAME:
            return flags | QtCore.Qt.ItemIsEditable
        return flags

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole) -> Any:
        if role == QtCore.Qt.DisplayRole:
            return self._displayHeader(orientation, section)
        else:
            return None

# --------------------------------------------------------------------------


class RefsTableModel_t(QtCore.QAbstractTableModel):
    """The model for the bottom view: the references to the functions.
    """

    COL_NAME = 0
    COL_ADDR = 1
    COL_TOADDR = 2
    COL_COUNT = 3

# private:
    def _displayHeader(self, orientation, col: int) -> Optional[str]:
        """Retrieves a field description to be displayed in the header.
        """

        if orientation == QtCore.Qt.Vertical:
            return None
        if col == self.COL_ADDR:
            return "From Address"
        if col == self.COL_TOADDR:
            return "To Address"
        if col == self.COL_NAME:
            return "Foreign Val."
        return None

    def _getTargetAddr(self, row: int) -> int:
        """Retrieves the address from which function was referenced, or to which it references.
        """

        curr_ref_fromaddr = self.refs_list[row][0]  # fromaddr
        curr_ref_addr = self.refs_list[row][1]  # toaddr
        target_addr = BADADDR
        if self.is_refs_to:
            target_addr = curr_ref_fromaddr
        else:
            target_addr = curr_ref_addr
        return target_addr

    def _getForeignFuncName(self, row: int) -> str:
        """Retrieves a name of the foreign function or the details on the referenced address.
        """

        # curr_ref_fromaddr = self.refs_list[row][0]  # fromaddr
        # curr_ref_addr = self.refs_list[row][1]  # toaddr

        target_addr = self._getTargetAddr(row)
        if print_insn_mnem(target_addr) != "":
            func_name = _getFunctionNameAt(target_addr)
            if func_name:
                return func_name

        addr_str = "[%08lx]" % target_addr
        # target_name = GetDisasm(target_addr)
        return f"{addr_str} : {GetDisasm(target_addr)}"

    def _displayData(self, row: int, col: int) -> Optional[str]:
        """Retrieves the data to be displayed. appropriately to the row and column.
        """

        if len(self.refs_list) <= row:
            return None
        curr_ref_fromaddr = self.refs_list[row][0]  # fromaddr
        curr_ref_addr = self.refs_list[row][1]  # toaddr
        if col == self.COL_ADDR:
            return "%08x" % curr_ref_fromaddr
        if col == self.COL_TOADDR:
            return "%08x" % curr_ref_addr
        if col == self.COL_NAME:
            return self._getForeignFuncName(row)
        return None

    def _getAddrToFollow(self, row: int, col: int) -> int:
        """Retrieves the address that can be followed on click.
        """

        if col == self.COL_ADDR:
            return self.refs_list[row][0]
        if col == self.COL_TOADDR:
            return self.refs_list[row][1]
        return BADADDR

    def _displayBackground(self, row: int, col: int) -> Any:
        """Retrieves a background color appropriate for the data.
        """

        theme = get_theme() 
        if self.isFollowable(col):
            return QtGui.QColor(theme[0])
        return None

# public:
    def __init__(self, function_info_list, is_refs_to=True, parent=None, *args) -> None:
        super(RefsTableModel_t, self).__init__()
        self.function_info_list = function_info_list
        self.curr_index = (-1)
        self.refs_list = []
        self.is_refs_to = is_refs_to

    def isFollowable(self, col: int) -> bool:
        """Is the address possible to follow in the disassembly view?
        """
        if col == self.COL_ADDR:
            return True
        if col == self.COL_TOADDR:
            return True
        return False

    def findOffsetIndex(self, data: int) -> int:
        """Serches the given address on the list of functions and returns it if found.
        """

        index = 0
        for func_info in self.function_info_list:
            if data >= func_info.start and data <= func_info.end:
                return index
            index += 1
        return (-1)

    def setCurrentIndex(self, curr_index: int) -> None:
        self.curr_index = curr_index
        if self.curr_index == (-1) or self.curr_index >= len(self.function_info_list):
            # reset list
            self.refs_list = []
        else:
            if self.is_refs_to:
                self.refs_list = self.function_info_list[self.curr_index].refs_list
            else:
                self.refs_list = self.function_info_list[self.curr_index].called_list
        self.reset()

    def reset(self) -> None:
        self.beginResetModel()
        self.endResetModel()

# Qt API
    def rowCount(self, parent=None) -> int:
        return len(self.refs_list)

    def columnCount(self, parent) -> int:
        return self.COL_COUNT

    def data(self, index, role) -> Any:
        if not index.isValid():
            return None
        col = index.column()
        row = index.row()

        # curr_ref_addr = self.refs_list[row][0]

        if role == QtCore.Qt.UserRole:
            if self.isFollowable(col):
                return self._getAddrToFollow(row, col)
        elif role == QtCore.Qt.DisplayRole or role == QtCore.Qt.EditRole:
            return self._displayData(row, col)
        elif role == QtCore.Qt.BackgroundColorRole:
            return self._displayBackground(row, col)
        else:
            return None

    def flags(self, index) -> Any:
        if not index.isValid():
            return None
        flags = QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable
        return flags

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole) -> Any:
        if role == QtCore.Qt.DisplayRole:
            return self._displayHeader(orientation, section)
        else:
            return None

# --------------------------------------------------------------------------
# custom views:

class FunctionsView_t(QtWidgets.QTableView):
    """The top view: listing all the functions.
    """

    # private
    def _get_default_color(self) -> None:
        return idc.DEFCOLOR

    def _set_segment_color(self, ea, color) -> None:
        seg = idaapi.getseg(ea)
        seg.color = color
        seg.update()

    def _set_item_color(self, addr: int, color: int) -> None:
        ea = addr
        # reset to default
        self._set_segment_color(ea, self.color_normal)
        # set desired item color
        set_color(addr, CIC_ITEM, color)

    def _get_themed_color(self, color: int) -> int:
        if is_dark_theme():
            color_hilight = color_to_val(QtGui.QColor(color).darker(200))
        else:
            color_hilight = color
        return color_hilight

    # public
    def __init__(self, dataManager, color_hilight, func_model, parent=None) -> None:
        super(FunctionsView_t, self).__init__(parent=parent)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        #
        self.color_normal = self._get_default_color()
        self.prev_addr = BADADDR
        self.color_hilight = color_hilight
        self.func_model = func_model
        self.dataManager = dataManager

        self.setMouseTracking(True)
        self.setAutoFillBackground(True)

    # Qt API
    def currentChanged(self, current, previous) -> None:
        index_data = self.get_index_data(current)
        self.dataManager.setCurrentRva(index_data)

    def hilight_addr(self, addr: int) -> None:
        color_hilight = self._get_themed_color(self.color_hilight)

        if self.prev_addr != BADADDR:
            self._set_item_color(self.prev_addr, self.color_normal)
        if addr != BADADDR:
            self._set_item_color(addr, color_hilight)
        self.prev_addr = addr

    def get_index_data(self, index: Any) -> Any:
        if not index.isValid():
            return None
        try:
            data_val = index.data(QtCore.Qt.UserRole)
            if data_val is None:
                return None
            index_data = data_val
        except ValueError:
            return None
        return index_data

    def mousePressEvent(self, event: Any) -> None:
        event.accept()
        # index = self.indexAt(event.pos())
        # data = self.get_index_data(index)
        super(QtWidgets.QTableView, self).mousePressEvent(event)

    def mouseDoubleClickEvent(self, event: Any) -> None:
        event.accept()
        index = self.indexAt(event.pos())
        if not index.isValid():
            return
        data = self.get_index_data(index)
        if not data:
            super(QtWidgets.QTableView, self).mouseDoubleClickEvent(event)
            return
        col = index.column()
        if self.func_model.isFollowable(col):
            self.hilight_addr(data)
            jumpto(data)
        super(QtWidgets.QTableView, self).mouseDoubleClickEvent(event)

    def mouseMoveEvent(self, event: Any) -> None:
        index = self.indexAt(event.pos())
        if not index.isValid():
            return
        col = index.column()
        if self.func_model.isFollowable(col):
            self.setCursor(QtCore.Qt.PointingHandCursor)
        else:
            self.setCursor(QtCore.Qt.ArrowCursor)

    def leaveEvent(self, event: Any) -> None:
        self.setCursor(QtCore.Qt.ArrowCursor)

    def OnDestroy(self) -> None:
        self.hilight_addr(BADADDR)

# --------------------------------------------------------------------------


class FunctionsMapper_t(QObject):
    """The class keeping the mapping of all the functions.
    """

    # private

    def _isImportStart(self, start: int) -> bool:
        """Check if the given function is imported or internal.
        """

        if start in self._importsSet:
            return True
        if print_insn_mnem(start) == 'call':
            return False
        # print(print_insn_mnem(start))
        op = get_operand_value(start, 0)
        if op in self._importsSet:
            return True
        return False

    def imports_names_callback(self, ea: int, name: str, ord: Any) -> bool:
        """A callback adding a particular name and offset to the internal set of the imported functions.
        """

        self._importsSet.add(ea)
        self._importNamesSet.add(name)
        # True -> Continue enumeration
        return True

    def _loadImports(self) -> None:
        """Enumerates imported functions with the help of IDA API and adds them to the internal sets.
        """

        self._importsSet = set()
        self._importNamesSet = set()
        nimps = idaapi.get_import_module_qty()
        for i in range(0, nimps):
            idaapi.enum_import_names(i, self.imports_names_callback)

    def _isImportName(self, name: str) -> bool:
        """Checks if the given name belongs to the imported function with the help of internal set.
        """

        if name in self._importNamesSet:
            return True
        return False

    def _listRefsTo(self, start: int) -> List[Tuple[int, int]]:
        """Make a list of all the references to the given function.
        Args:
          func : The function references to which we are searching.
          start : The function's start offset.

        Returns:
          list : A list of tuples.
            Each tuple represents: the offsets:
            0 : the offset from where the given function was referenced by the foreign function
            1 : the function's start address
        """

        func_refs_to = XrefsTo(start, 1)
        refs_list = []
        for ref in func_refs_to:
            if idc.print_insn_mnem(ref.frm) == "":
                continue
            refs_list.append((ref.frm, start))
        return refs_list

    def _getCallingOffset(self, func, called_list) -> List[Tuple[int, int]]:
        """Lists the offsets from where the given function references the list of other function.
        """

        start = get_func_attr(func, FUNCATTR_START)
        end = prev_addr(get_func_attr(func, FUNCATTR_END))
        # func_name = _getFunctionNameAt(start)
        curr = start
        calling_list = []
        while (True):
            if curr >= end:
                break
            op = get_operand_value(curr, 0)
            if op in called_list:
                calling_list.append((curr, op))
            curr = next_addr(curr)
        return calling_list

    def _listRefsFrom(self, func, start: int, end: int) -> List[Tuple[int, int]]:
        """Make a list of all the references made from the given function.

        Args:
          func : The function inside of which we are searching.
          start : The function's start offset.
          end : The function's end offset.

        Returns:
          list : A list of tuples. Each tuple represents:
            0 : the offset from where the given function referenced the other entity
            1 : the address that was referenced
        """

        dif = end - start
        called_list = []
        func_name = _getFunctionNameAt(start)

        for indx in range(0, dif):
            addr = start + indx
            func_refs_from = XrefsFrom(addr, 1)
            for ref in func_refs_from:
                if _getFunctionNameAt(ref.to) == func_name:
                    # skip jumps inside self
                    continue
                called_list.append(ref.to)
        calling_list = self._getCallingOffset(func, called_list)
        return calling_list

    def _loadLocals(self) -> None:
        """Enumerates functions using IDA API and loads them into the internal mapping.
        """
        self._loadImports()
        for func in Functions():
            start = get_func_attr(func, FUNCATTR_START)
            end = prev_addr(get_func_attr(func, FUNCATTR_END))

            is_import = self._isImportStart(start)

            refs_list = self._listRefsTo(start)
            calling_list = self._listRefsFrom(func, start, end)

            func_info = FunctionInfo_t(start, end, refs_list, calling_list, is_import)
            self._functionsMap[va_to_rva(start)] = func_info
            self._functionsMap[va_to_rva(end)] = func_info
            self.funcList.append(func_info)

    # public
    def __init__(self, parent=None) -> None:
        super(FunctionsMapper_t, self).__init__(parent=parent)
        self._functionsMap = dict()
        self.funcList = []  # public
        self._loadLocals()

    def funcAt(self, rva: int) -> FunctionInfo_t:
        func_info = self._functionsMap[rva]
        return func_info


class FunctionsListForm_t(PluginForm):
    """The main form of the IFL plugin.
    """

# private
    _LIVE_FILTER = True

    def _listFunctionsAddr(self) -> List[int]:
        """Lists all the starting addresses of the functions using IDA API.
        """

        fn_list = list()
        for func in Functions():
            start = get_func_attr(func, FUNCATTR_START)
            fn_list.append(start)
        return fn_list

    def _saveFunctionsNames(self, file_name: Optional[str], ext: str) -> bool:
        """Saves functions names and offsets from the internal mappings into a file.
        Fromats: CSV (default), or TAG (PE-bear, PE-sieve compatibile).
        """

        if file_name is None or len(file_name) == 0:
            return False
        delim = ","
        if ".tag" in ext:  # a TAG format was chosen
            delim = ";"
        fn_list = list()
        for func in Functions():
            start = get_func_attr(func, FUNCATTR_START)
            func_name = _getFunctionNameAt(start)
            start_rva = va_to_rva(start)
            line = "%lx%c%s" % (start_rva, delim, func_name)
            fn_list.append(line)
        idaapi.msg(str(file_name))
        with open(file_name, 'w') as f:
            for item in fn_list:
                f.write("%s\n" % item)
            return True
        return False

    def _loadFunctionsNames(self, file_name: Optional[str], ext: str) -> Optional[Tuple[int, int]]:
        """Loads functions names from the given file into the internal mappings.
        Fromats: CSV (default), or TAG (PE-bear, PE-sieve compatibile).
        """

        if file_name is None or len(file_name) == 0:
            return None
        curr_functions = self._listFunctionsAddr()
        delim = ","  # new delimiter (for CSV format)
        delim2 = ":"  # old delimiter
        if ".tag" in ext:  # a TAG format was chosen
            delim2 = ";"
        functions = 0
        comments = 0
        with open(file_name, 'r') as f:
            for line in f.readlines():
                line = line.strip()
                fn = line.split(delim)
                if len(fn) < 2:
                    fn = line.split(delim2)  # try old delimiter
                if len(fn) < 2:
                    continue
                start = 0
                try:
                    start = int(fn[0].strip(), 16)
                except ValueError:
                    # this line doesn't start from an offset, so skip it
                    continue
                func_name = fn[1].strip()
                if start < idaapi.get_imagebase():  # it is RVA
                    start = rva_to_va(start)  # convert to VA

                if start in curr_functions:
                    if self.subDataManager.setFunctionName(start, func_name):
                        functions += 1
                else:
                    set_cmt(start, func_name, 1)  # set the name as a comment
                    comments += 1
        return (functions, comments)

    def _setup_sorted_model(self, view, model) -> QtCore.QSortFilterProxyModel:
        """Connects the given sorted data model with the given view.
        """

        sorted_model = QtCore.QSortFilterProxyModel()
        sorted_model.setDynamicSortFilter(True)
        sorted_model.setSourceModel(model)
        view.setModel(sorted_model)
        view.setSortingEnabled(True)
        #
        sorted_model.setParent(view)
        model.setParent(sorted_model)
        return sorted_model

    def _update_current_offset(self, view, refs_model, offset) -> None:
        """Update the given data model to follow given offset.
        """

        if offset:
            index = refs_model.findOffsetIndex(offset)
        else:
            index = (-1)
        refs_model.setCurrentIndex(index)
        refs_model.reset()
        view.reset()
        view.repaint()

    def _update_function_name(self, ea: int) -> None:
        """Sets on the displayed label the name of the function and it's arguments.
        """

        try:
            func_info = self.funcMapper.funcAt(va_to_rva(ea))
        except KeyError:
            return

        func_type = func_info.type
        func_args = _getArgsDescription(ea)
        func_name = _getFunctionNameAt(ea)
        self.refs_label.setText(f"{func_type} <b>{func_name}</b> {func_args}")

    def _update_ref_tabs(self, ea: int) -> None:
        """Sets on the tabs headers the numbers of references to the selected function.
        """

        tocount = 0
        fromcount = 0
        try:
            func_info = self.funcMapper.funcAt(va_to_rva(ea))
            tocount = len(func_info.refs_list)
            fromcount = len(func_info.called_list)
        except KeyError:
            pass
        self.refs_tabs.setTabText(0,  "Is referred by %d:" % tocount)
        self.refs_tabs.setTabText(1,  "Refers to %d:" % fromcount)

    def adjustColumnsToContents(self) -> None:
        """Adjusts columns' sizes to fit the data.
        """

        self.addr_view.resizeColumnToContents(0)
        self.addr_view.resizeColumnToContents(1)
        self.addr_view.resizeColumnToContents(2)
        #
        self.addr_view.resizeColumnToContents(5)
        self.addr_view.resizeColumnToContents(6)
        self.addr_view.resizeColumnToContents(7)
# public
    # @pyqtSlot()

    def longoperationcomplete(self) -> None:
        """A callback executed when the current RVA has changed.
        """
        global g_DataManager

        data = g_DataManager.currentRva
        self.setRefOffset(data)

    def setRefOffset(self, data: Any) -> None:
        """Updates the views to follow to the given RVA.
        """

        if not data:
            return
        self._update_current_offset(self.refs_view, self.refsto_model, data)
        self._update_current_offset(self.refsfrom_view, self.refsfrom_model, data)
        self._update_ref_tabs(data)
        self._update_function_name(data)

    def filterByColumn(self, col_num, str) -> None:
        """Applies a filter defined by the string on data model.
        """

        filter_type = QtCore.QRegExp.FixedString
        sensitivity = QtCore.Qt.CaseInsensitive
        if self.criterium_id != 0:
            filter_type = QtCore.QRegExp.RegExp
        self.addr_sorted_model.setFilterRegExp(QtCore.QRegExp(str, sensitivity, filter_type))
        self.addr_sorted_model.setFilterKeyColumn(col_num)

    def filterChanged(self) -> None:
        """A wrapper for the function: filterByColumn(self, col_num, str)
        """

        self.filterByColumn(self.filter_combo.currentIndex(), self.filter_edit.text())

    def filterKeyEvent(self, event: Any = None) -> None:
        if event is not None:
            QtWidgets.QLineEdit.keyReleaseEvent(self.filter_edit, event)
        if event and (not self.is_livefilter and event.key() != QtCore.Qt.Key_Enter and event.key() != QtCore.Qt.Key_Return):
            return
        self.filterChanged()

    def criteriumChanged(self) -> None:
        """A callback executed when the criterium of sorting has changed and the data has to be sorted again.
        """

        self.criterium_id = self.criterium_combo.currentIndex()
        if self.criterium_id == 0:
            self.filter_edit.setPlaceholderText("keyword")
        else:
            self.filter_edit.setPlaceholderText("regex")
        self.filterChanged()

    def liveSearchCheckBox(self) -> None:
        self.is_livefilter = self.livefilter_box.isChecked()
        if self.is_livefilter:
            self.filterByColumn(self.filter_combo.currentIndex(), self.filter_edit.text())

    def alternateRowColors(self, enable):
        self.refsfrom_view.setAlternatingRowColors(enable)
        self.addr_view.setAlternatingRowColors(enable)
        self.refs_view.setAlternatingRowColors(enable)

    def OnCreate(self, form) -> None:
        """Called when the plugin form is created
        """

        # init data structures:
        self.funcMapper = FunctionsMapper_t()
        self.criterium_id = 0

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)

        # Create models
        self.subDataManager = DataManager()

        self.table_model = TableModel_t(self.funcMapper.funcList)

        # init
        self.addr_sorted_model = QtCore.QSortFilterProxyModel()
        self.addr_sorted_model.setDynamicSortFilter(True)
        self.addr_sorted_model.setSourceModel(self.table_model)
        self.addr_view = FunctionsView_t(g_DataManager, COLOR_HILIGHT_FUNC, self.table_model)
        self.addr_view.setModel(self.addr_sorted_model)
        self.addr_view.setSortingEnabled(True)
        self.addr_view.setWordWrap(False)
        self.addr_view.horizontalHeader().setStretchLastSection(False)
        self.addr_view.verticalHeader().show()

        self.adjustColumnsToContents()
        #
        self.refsto_model = RefsTableModel_t(self.funcMapper.funcList, True)
        self.refs_view = FunctionsView_t(self.subDataManager, COLOR_HILIGHT_REFTO, self.refsto_model)
        self._setup_sorted_model(self.refs_view, self.refsto_model)
        self.refs_view.setColumnHidden(RefsTableModel_t.COL_TOADDR, True)
        self.refs_view.setWordWrap(False)

        font = self.refs_view.font()
        font.setPointSize(8)
        self.refs_view.setFont(font)

        self.refsfrom_model = RefsTableModel_t(self.funcMapper.funcList, False)
        self.refsfrom_view = FunctionsView_t(self.subDataManager, COLOR_HILIGHT_REFFROM, self.refsfrom_model)
        self._setup_sorted_model(self.refsfrom_view, self.refsfrom_model)
        self.refsfrom_view.setColumnHidden(RefsTableModel_t.COL_TOADDR, True)
        self.refsfrom_view.setWordWrap(False)

        # add a box to enable/disable live filtering
        self.livefilter_box = QtWidgets.QCheckBox("Live filtering")
        self.livefilter_box.setToolTip("If live filtering is enabled, functions are searched as you type in the edit box.\nOtherwise they are searched when you press Enter.")
        self.livefilter_box.setChecked(self._LIVE_FILTER)
        self.is_livefilter = self._LIVE_FILTER
        # connect SIGNAL
        self.livefilter_box.stateChanged.connect(self.liveSearchCheckBox)

        # important for proper order of objects destruction:
        self.table_model.setParent(self.addr_sorted_model)
        self.addr_sorted_model.setParent(self.addr_view)

        # connect SIGNAL
        g_DataManager.updateSignal.connect(self.longoperationcomplete)

        # Create a Tab widget for references:
        self.refs_tabs = QtWidgets.QTabWidget()
        self.refs_tabs.insertTab(0, self.refs_view, "Is refered by")
        self.refs_tabs.insertTab(1, self.refsfrom_view, "Refers to")

        # Create filter
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("keyword")
        self.filter_edit.keyReleaseEvent = self.filterKeyEvent

        self.filter_combo = QtWidgets.QComboBox()
        self.filter_combo.addItems(TableModel_t.header_names)
        self.filter_combo.setCurrentIndex(TableModel_t.COL_NAME)
        # connect SIGNAL
        self.filter_combo.activated.connect(self.filterChanged)

        self.criterium_combo = QtWidgets.QComboBox()
        criteria = ["contains", "matches"]
        self.criterium_combo.addItems(criteria)
        self.criterium_combo.setCurrentIndex(0)
        # connect SIGNAL
        self.criterium_combo.activated.connect(self.criteriumChanged)

        filter_panel = QtWidgets.QFrame()
        filter_layout = QtWidgets.QHBoxLayout()
        filter_layout.addWidget(QtWidgets.QLabel("Where "))
        filter_layout.addWidget(self.filter_combo)
        filter_layout.addWidget(self.criterium_combo)
        filter_layout.addWidget(self.filter_edit)

        filter_panel.setLayout(filter_layout)
        self.filter_edit.setFixedHeight(20)
        filter_panel.setFixedHeight(40)
        filter_panel.setAutoFillBackground(True)

        self.refs_label = QtWidgets.QLabel("Function")
        self.refs_label.setTextFormat(QtCore.Qt.RichText)
        self.refs_label.setWordWrap(True)

        panel1 = QtWidgets.QFrame()
        layout1 = QtWidgets.QVBoxLayout()
        panel1.setLayout(layout1)

        layout1.addWidget(filter_panel)
        layout1.addWidget(self.livefilter_box)
        layout1.addWidget(self.addr_view)
        layout1.setContentsMargins(0, 0, 0, 0)

        panel2 = QtWidgets.QFrame()
        layout2 = QtWidgets.QVBoxLayout()
        layout2.addWidget(self.refs_label)
        layout2.addWidget(self.refs_tabs)
        layout2.addWidget(self._makeButtonsPanel())
        layout2.setContentsMargins(0, 10, 0, 0)
        panel2.setLayout(layout2)

        self.main_splitter = QtWidgets.QSplitter()
        self.main_splitter.setOrientation(QtCore.Qt.Vertical)
        self.main_splitter.addWidget(panel1)
        self.main_splitter.addWidget(panel2)

        # Populate PluginForm
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.main_splitter)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.parent.setLayout(layout)
        self.alternateRowColors(IS_ALTERNATE_ROW)

        idaapi.set_dock_pos(PLUGIN_NAME, None, idaapi.DP_RIGHT)

    def _makeButtonsPanel(self) -> QtWidgets.QFrame:
        """Creates on the form's bottom the panel with buttons.
        """

        buttons_panel = QtWidgets.QFrame()
        buttons_layout = QtWidgets.QHBoxLayout()
        buttons_panel.setLayout(buttons_layout)

        importButton = QtWidgets.QPushButton("Load names")
        importButton.clicked.connect(self.importNames)
        buttons_layout.addWidget(importButton)

        exportButton = QtWidgets.QPushButton("Save names")
        exportButton.clicked.connect(self.exportNames)
        buttons_layout.addWidget(exportButton)
        return buttons_panel

    def importNames(self) -> None:
        """Imports functions list from a file.
        """

        file_name, ext = QtWidgets.QFileDialog.getOpenFileName(None, "Import functions names", QtCore.QDir.homePath(), "CSV Files (*.csv);;TAG Files (*.tag);;All files (*)")
        if file_name is not None and len(file_name) > 0:
            names = self._loadFunctionsNames(file_name, ext)
            if names is None:
                idaapi.warning(f"Malformed file %s" % file_name)
                return

            (loaded, comments) = names
            if loaded == 0 and comments == 0:
                idaapi.warning("Failed importing functions names! Not matching offsets!")
            else:
                idaapi.info("Imported %d function names and %d comments" % (loaded, comments))

    def exportNames(self) -> None:
        """Exports functions list into a file.
        """

        file_name, ext = QtWidgets.QFileDialog.getSaveFileName(None, "Export functions names", QtCore.QDir.homePath(), "CSV Files (*.csv);;TAG Files (*.tag)")
        if file_name is not None and len(file_name) > 0:
            if not self._saveFunctionsNames(file_name, ext):
                idaapi.warning("Failed exporting functions names!")
            else:
                idaapi.info("Exported to: " + file_name)

    def OnClose(self, form: Any) -> None:
        """Called when the plugin form is closed
        """

        # clear last selection
        self.addr_view.hilight_addr(BADADDR)
        self.refs_view.hilight_addr(BADADDR)
        self.refsfrom_view.hilight_addr(BADADDR)
        del self

    def Show(self) -> PluginForm.Show:
        """Creates the form if not created or sets the focus if the form already exits.
        """

        title = PLUGIN_NAME + " v" + __VERSION__
        return PluginForm.Show(self,
                               title,
                               options=PluginForm.WOPN_PERSIST)


# --------------------------------------------------------------------------
class IFLMenuHandler(idaapi.action_handler_t):
    """Manages menu items belonging to IFL.
    """

    def __init__(self) -> None:
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx: Any) -> int:
        open_form()
        return 1

    def update(self, ctx: Any) -> int:
        return idaapi.AST_ENABLE_ALWAYS


# --------------------------------------------------------------------------
def open_form() -> None:
    global m_functionInfoForm
    global g_DataManager
    # -----
    try:
        g_DataManager
    except Exception:
        g_DataManager = DataManager()
    # -----
    try:
        m_functionInfoForm
    except Exception:
        idaapi.msg("%s\nLoading Interactive Function List...\n" % VERSION_INFO)
        m_functionInfoForm = FunctionsListForm_t()

    m_functionInfoForm.Show()

# --------------------------------------------------------------------------
# IDA api:

class funclister_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Interactive Functions List"

    help = "Interactive Function List. Comments? Remarks? Mail to: hasherezade@gmail.com"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ''

    def init(self) -> None:
        idaapi.register_action(idaapi.action_desc_t(
            'ifl:open',  # action name
            PLUGIN_NAME,
            IFLMenuHandler(),
            PLUGIN_HOTKEY,
            'Opens Interactive Function List Pane')
        )

        idaapi.attach_action_to_menu(
            'View/',
            'ifl:open',
            idaapi.SETMENU_APP)

        return idaapi.PLUGIN_OK

    def run(self, arg: Any) -> None:
        open_form()
        pass

    def term(self) -> None:
        pass

def PLUGIN_ENTRY() -> funclister_t:
    return funclister_t()


if __name__ == "__main__":
    PLUGIN_ENTRY().init()
