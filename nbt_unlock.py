#!/usr/bin/env python3
"""
BMW NBT Evo HDD ATA Security Unlock
------------------------------------
Unlocks an ATA-locked BMW NBT Evo hard drive connected via SATA.

GUI (default, needs tkinter):   sudo python3 nbt_unlock.py
Command line (no tkinter):      python3 nbt_unlock.py --help

  list                                   list SATA drives
  derive  --eth MAC --bt MAC --snr HEX   print the ATA password (no root)
  status  DEVICE                         show ATA security status
  unlock  DEVICE (--eth/--bt/--snr | --password PWD)
  disable DEVICE (--eth/--bt/--snr | --password PWD) [--yes]
  gui                                    launch the GUI

Exit codes: 0 success, 1 operation failed, 2 usage/validation error.
tkinter is only required for the GUI.
"""

import ctypes
import fcntl
import hashlib
import argparse
import base64
import os
import re
import subprocess
import sys
import threading
import types

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, font as tkfont
    HAVE_TK = True
except ImportError:      # headless / tkinter not installed: CLI still works
    HAVE_TK = False
    tk = types.SimpleNamespace(Tk=object, Frame=object, Canvas=object,
                               StringVar=object, Button=object)
    ttk = messagebox = tkfont = None


# ─── Low-level constants ─────────────────────────────────────────────────────

SG_IO           = 0x2285
SG_DXFER_TO_DEV = -2


# ─── ATA structures ──────────────────────────────────────────────────────────

class SgIoHdr(ctypes.Structure):
    _fields_ = [
        ('interface_id',    ctypes.c_int),
        ('dxfer_direction', ctypes.c_int),
        ('cmd_len',         ctypes.c_uint8),
        ('mx_sb_len',       ctypes.c_uint8),
        ('iovec_count',     ctypes.c_uint16),
        ('dxfer_len',       ctypes.c_uint32),
        ('dxferp',          ctypes.c_void_p),
        ('cmdp',            ctypes.c_void_p),
        ('sbp',             ctypes.c_void_p),
        ('timeout',         ctypes.c_uint32),
        ('flags',           ctypes.c_uint32),
        ('pack_id',         ctypes.c_int32),
        ('usr_ptr',         ctypes.c_void_p),
        ('status',          ctypes.c_uint8),
        ('masked_status',   ctypes.c_uint8),
        ('msg_status',      ctypes.c_uint8),
        ('sb_len_wr',       ctypes.c_uint8),
        ('host_status',     ctypes.c_uint16),
        ('driver_status',   ctypes.c_uint16),
        ('resid',           ctypes.c_int32),
        ('duration',        ctypes.c_uint32),
        ('info',            ctypes.c_uint32),
    ]


# ─── Core logic ──────────────────────────────────────────────────────────────

def build_password(eth_mac: str, bt_mac: str, snr_hex: str) -> bytes:
    """
    Derive the 20-byte ATA password used by BMW NBT Evo (srv-hddmgr2).

    Algorithm (reversed from srv-hddmgr2 ARM binary):
      1. Hex-decode ETH_MAC, BT_MAC, and SNR_HEX to raw bytes
      2. Concatenate:  raw_eth (6B) + raw_bt (6B) + raw_snr (nB)
      3. MD5 hash the result  -> 16 bytes
      4. Base64-encode the first 15 of those 16 bytes  -> 20 ASCII chars
    """
    data = bytes.fromhex(eth_mac) + bytes.fromhex(bt_mac) + bytes.fromhex(snr_hex)
    md5  = hashlib.md5(data).digest()
    return base64.b64encode(md5[:15])   # 20 ASCII bytes, no padding


def send_ata_security_unlock(device: str, password: bytes):
    """Send ATA SECURITY UNLOCK via SG_IO ATA passthrough."""
    buf = bytearray(512)
    buf[0] = 0          # flags word: bit0=0 -> user password
    buf[2:22] = password

    data_arr = (ctypes.c_uint8 * 512)(*buf)
    sb_arr   = (ctypes.c_uint8 * 32)()

    cdb = (ctypes.c_uint8 * 12)(
        0xA1,           # ATA PASS-THROUGH (12)
        4 << 1,         # PROTOCOL = 4 (PIO data-out)
        0x06,           # T_DIR=to device, BYTE_BLOCK=1, T_LENGTH=sector count
        0x00,           # FEATURES
        0x01,           # SECTOR_COUNT = 1
        0x00, 0x00, 0x00,
        0x00,           # DEVICE
        0xF2,           # COMMAND: ATA SECURITY UNLOCK
        0x00, 0x00,
    )

    hdr = SgIoHdr()
    hdr.interface_id    = ord('S')
    hdr.dxfer_direction = SG_DXFER_TO_DEV
    hdr.cmd_len         = 12
    hdr.mx_sb_len       = 32
    hdr.dxfer_len       = 512
    hdr.dxferp          = ctypes.addressof(data_arr)
    hdr.cmdp            = ctypes.addressof(cdb)
    hdr.sbp             = ctypes.addressof(sb_arr)
    hdr.timeout         = 30000

    fd = os.open(device, os.O_RDWR | os.O_NONBLOCK)
    try:
        fcntl.ioctl(fd, SG_IO, hdr)
    finally:
        os.close(fd)

    sense = bytes(sb_arr[:hdr.sb_len_wr])
    return hdr.status, hdr.host_status, hdr.driver_status, sense


def get_drive_security_status(device: str) -> str:
    """Query hdparm for ATA security status lines."""
    try:
        out = subprocess.check_output(
            ['hdparm', '-I', device],
            stderr=subprocess.STDOUT,
            timeout=10
        ).decode(errors='replace')
        lines = []
        capture = False
        for line in out.splitlines():
            if 'Security' in line and ':' not in line:
                capture = True
            if capture:
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)
                else:
                    break   # blank line ends the section
        return '\n'.join(lines) if lines else "(hdparm Security section not found)"
    except FileNotFoundError:
        return "(hdparm not installed)"
    except subprocess.TimeoutExpired:
        return "(hdparm timed out)"
    except subprocess.CalledProcessError as e:
        return e.output.decode(errors='replace').strip()


def list_sata_drives() -> list[tuple[str, str]]:
    """Return list of (device_path, description) for SATA block devices."""
    drives = []
    try:
        out = subprocess.check_output(
            ['lsblk', '-d', '-o', 'NAME,SIZE,MODEL,TRAN', '--noheadings'],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode(errors='replace')
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[-1].lower() == 'sata':
                name  = parts[0]
                size  = parts[1]
                model = ' '.join(parts[2:-1])
                dev   = f'/dev/{name}'
                desc  = f'{dev}  [{size}]  {model}'
                drives.append((dev, desc))
    except Exception:
        pass
    # fallback: any /dev/sd* that exists
    if not drives:
        import glob
        for p in sorted(glob.glob('/dev/sd?')):
            drives.append((p, p))
    return drives


def normalize_mac(raw: str) -> str:
    """Strip colons/dashes/spaces and upper-case a MAC string."""
    return re.sub(r'[:\-\s]', '', raw).upper()


def validate_hex(s: str, expected_len: int | None = None) -> str | None:
    """
    Validate a hex string.  Returns error message or None if valid.
    expected_len is the required number of hex characters (bytes * 2).
    """
    s = s.strip()
    if not s:
        return "Field is empty"
    if not re.fullmatch(r'[0-9A-Fa-f]+', s):
        return "Invalid characters — must be hex (0-9, A-F)"
    if len(s) % 2 != 0:
        return "Odd number of hex characters"
    if expected_len is not None and len(s) != expected_len:
        return f"Expected {expected_len} hex chars ({expected_len//2} bytes), got {len(s)}"
    return None


def parse_security_state(text: str) -> str:
    """
    Reduce hdparm -I "Security:" output to one of:
    'frozen', 'locked', 'unlocked', 'disabled' (security not enabled), 'unknown'.
    """
    flags = {}
    for line in text.splitlines():
        s = ' '.join(line.lower().split())
        for word in ('frozen', 'locked', 'enabled'):
            if s == word:
                flags[word] = True
            elif s == 'not ' + word:
                flags[word] = False
    if flags.get('frozen'):
        return 'frozen'
    if flags.get('locked'):
        return 'locked'
    if flags.get('enabled'):
        return 'unlocked'
    if flags.get('enabled') is False:
        return 'disabled'
    return 'unknown'


# ─── GUI ─────────────────────────────────────────────────────────────────────

# ── Graphite palette (one accent: green, used only on the derived password) ──
C_BG       = '#141415'   # page
C_DEEP     = '#0f0f10'   # header, log, code blocks
C_CARD     = '#19191b'   # card surface
C_RAISED   = '#232325'   # inputs, secondary buttons
C_RAISED_H = '#2c2c2f'   # raised hover
C_HAIR     = '#2a2a2d'   # hairline borders
C_HAIR_HI  = '#45454a'   # focus / hover hairline
C_FG       = '#ededed'   # primary text
C_FG2      = '#a1a1a6'   # secondary text
C_FG3      = '#85858b'   # muted text
C_DIS      = '#5c5c61'   # disabled text
C_ACCENT   = '#6be075'   # brand green: derived password only
C_POS      = '#4cc38a'
C_NEG      = '#e5484d'

# Font families are resolved when the app starts (see _pick_fonts); sizes are
# negative so they are pixels.
F_SANS_FAMILIES = ('Inter', 'IBM Plex Sans', 'Segoe UI', 'SF Pro Text',
                   'Helvetica Neue', 'Noto Sans', 'DejaVu Sans', 'Helvetica')
F_MONO_FAMILIES = ('JetBrains Mono', 'IBM Plex Mono', 'Cascadia Mono',
                   'Consolas', 'Menlo', 'DejaVu Sans Mono', 'Liberation Mono',
                   'Courier')
F_UI     = ('Helvetica', -13)
F_SM     = ('Helvetica', -12)
F_WORD   = ('Helvetica', -16)
F_H      = ('Helvetica', -15)
F_MONO   = ('Courier', -13)
F_MONO_S = ('Courier', -12)
F_MONO_L = ('Courier', -24)

_LOGO32_PNG_B64 = (
    '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'
    '+/b8f1xiFz1ssvynAAAAAElFTkSuQmCC'
)

_LOGO64_PNG_B64 = (
    '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'
)


class Card(tk.Frame):
    """Flat panel with a 1px hairline border; put children in .inner."""

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C_CARD, highlightthickness=1,
                         highlightbackground=C_HAIR, highlightcolor=C_HAIR, **kw)
        self.inner = tk.Frame(self, bg=C_CARD)
        self.inner.pack(fill='both', expand=True, padx=20, pady=20)


class Btn(tk.Button):
    """Flat button with fixed pixel height and colour-only hover."""

    # kind: (bg, fg, hover bg, hover fg, border, hover border)
    KINDS = {
        'secondary': (C_RAISED, C_FG, C_RAISED_H, C_FG, C_HAIR, C_HAIR_HI),
        'primary':   (C_FG, C_BG, '#ffffff', C_BG, C_FG, '#ffffff'),
        'quiet':     (C_BG, C_NEG, C_RAISED, C_NEG, C_BG, C_RAISED),
        'link':      (C_BG, C_FG2, C_BG, C_FG, C_BG, C_BG),
    }

    def __init__(self, parent, text, command, kind='secondary', height=36,
                 bg=None):
        c = list(self.KINDS[kind])
        if bg is not None and kind in ('quiet', 'link'):
            c[0] = c[4] = bg
            if kind == 'link':
                c[2] = bg
                c[5] = bg
        self._c = c
        self._kind = kind
        border = 1 if kind in ('secondary', 'primary') else 0
        self._pix = tk.PhotoImage(master=parent, width=1, height=1)
        pad = 16 if kind != 'link' else 0
        w = tkfont.Font(root=parent, font=F_UI).measure(text) + 2 * pad + 2 * border
        super().__init__(parent, text=text, command=command, image=self._pix,
                         compound='center', width=w, height=height,
                         font=F_UI, bg=c[0], fg=c[1], activebackground=c[2],
                         activeforeground=c[3], disabledforeground=C_DIS,
                         relief='flat', bd=0, padx=0, pady=0, cursor='hand2',
                         highlightthickness=border, highlightbackground=c[4],
                         highlightcolor=c[5], takefocus=0)
        self.update_idletasks()   # Tk adds internal padding; trim to exact size
        super().configure(width=w - (self.winfo_reqwidth() - w),
                          height=height - (self.winfo_reqheight() - height))
        self.bind('<Enter>', self._enter)
        self.bind('<Leave>', self._leave)

    def _enter(self, _e):
        if str(self['state']) != 'disabled':
            tk.Button.configure(self, highlightbackground=self._c[5])

    def _leave(self, _e):
        tk.Button.configure(self, highlightbackground=self._c[4])

    def configure(self, cnf=None, **kw):
        super().configure(cnf, **kw)
        if 'state' in kw:
            off = kw['state'] == 'disabled'
            c = self._c
            if self._kind == 'primary':
                super().configure(bg=C_RAISED if off else c[0],
                                  highlightbackground=C_HAIR if off else c[4])
            if off:
                super().configure(cursor='arrow')
            else:
                super().configure(cursor='hand2')


class NbtUnlockApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('NBT Evo HDD Unlock')
        self.configure(bg=C_BG)
        self.geometry('780x860')
        self.minsize(740, 780)
        self.resizable(True, True)
        self._current_password = ''
        self._drive_map: dict[str, str] = {}
        self._state_seq = 0
        self._logo_imgs = []
        self._pick_fonts()
        self._load_logos()
        self._setup_styles()
        self._build_ui()
        self._refresh_drives()
        self._update_root_status()

    # ── Fonts, logo, styles ───────────────────────────────────────────────────

    def _pick_fonts(self):
        global F_UI, F_SM, F_WORD, F_H, F_MONO, F_MONO_S, F_MONO_L
        have = {f.lower(): f for f in tkfont.families(self)}

        def first(cands, default):
            for c in cands:
                if c.lower() in have:
                    return have[c.lower()]
            return default

        sans = first(F_SANS_FAMILIES, 'Helvetica')
        mono = first(F_MONO_FAMILIES, 'Courier')
        F_UI, F_SM = (sans, -13), (sans, -12)
        F_WORD, F_H = (sans, -16), (sans, -15)
        F_MONO, F_MONO_S, F_MONO_L = (mono, -13), (mono, -12), (mono, -24)

    def _load_logos(self):
        self._logo32 = None
        try:
            self._logo32 = tk.PhotoImage(master=self, data=''.join(_LOGO32_PNG_B64))
            logo64 = tk.PhotoImage(master=self, data=''.join(_LOGO64_PNG_B64))
            self._logo_imgs = [self._logo32, logo64]
            self.iconphoto(True, logo64)
        except tk.TclError:
            pass

    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use('clam')
        self.option_add('*TCombobox*Listbox.background', C_RAISED)
        self.option_add('*TCombobox*Listbox.foreground', C_FG)
        self.option_add('*TCombobox*Listbox.selectBackground', C_RAISED_H)
        self.option_add('*TCombobox*Listbox.selectForeground', C_FG)
        self.option_add('*TCombobox*Listbox.font', F_MONO)

        lh = tkfont.Font(root=self, font=F_MONO).metrics('linespace')
        vpad = max(2, (36 - lh - 2) // 2)
        s.configure('Dev.TCombobox',
                    fieldbackground=C_RAISED, background=C_RAISED,
                    foreground=C_FG, arrowcolor=C_FG2,
                    bordercolor=C_HAIR, lightcolor=C_HAIR, darkcolor=C_HAIR,
                    selectbackground=C_RAISED, selectforeground=C_FG,
                    borderwidth=1, relief='flat', padding=(8, vpad))
        s.map('Dev.TCombobox',
              fieldbackground=[('readonly', C_RAISED)],
              background=[('active', C_RAISED_H), ('readonly', C_RAISED)],
              selectbackground=[('readonly', C_RAISED)],
              selectforeground=[('readonly', C_FG)],
              foreground=[('readonly', C_FG)],
              bordercolor=[('focus', C_HAIR_HI)],
              lightcolor=[('focus', C_HAIR_HI)],
              darkcolor=[('focus', C_HAIR_HI)])

        s.configure('Log.Vertical.TScrollbar', background=C_HAIR,
                    troughcolor=C_DEEP, bordercolor=C_DEEP, lightcolor=C_HAIR,
                    darkcolor=C_HAIR, borderwidth=0, gripcount=0, width=10)
        s.map('Log.Vertical.TScrollbar',
              background=[('active', C_HAIR_HI), ('pressed', C_HAIR_HI)])
        s.layout('Log.Vertical.TScrollbar',
                 [('Vertical.Scrollbar.trough', {'sticky': 'ns', 'children': [
                     ('Vertical.Scrollbar.thumb',
                      {'expand': '1', 'sticky': 'nswe'})]})])

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=C_DEEP, height=56)
        hdr.pack(fill='x')
        hdr.pack_propagate(False)
        if self._logo32 is not None:
            tk.Label(hdr, image=self._logo32, bg=C_DEEP, bd=0).pack(
                side='left', padx=(20, 12))
            word_pad = 0
        else:
            word_pad = 20
        tk.Label(hdr, text='NBT Evo HDD Unlock', bg=C_DEEP, fg=C_FG,
                 font=F_WORD).pack(side='left', padx=(word_pad, 12))
        tk.Label(hdr, text='ATA security unlock for BMW NBT Evo drives',
                 bg=C_DEEP, fg=C_FG2, font=F_SM).pack(side='left', pady=(2, 0))
        tk.Frame(self, bg=C_HAIR, height=1).pack(fill='x')

        # Tab bar
        self._tab_bar = tk.Frame(self, bg=C_BG, height=41)
        self._tab_bar.pack(fill='x')
        self._tab_bar.pack_propagate(False)
        self._tab_btns: dict[str, tuple[tk.Label, tk.Frame]] = {}
        self._tab_frames: dict[str, tk.Frame] = {}
        self._active_tab = 'Unlock'
        for name in ('Unlock', 'Help'):
            col = tk.Frame(self._tab_bar, bg=C_BG)
            col.pack(side='left', fill='y', padx=(20 if name == 'Unlock' else 8, 8))
            lbl = tk.Label(col, text=name, bg=C_BG, fg=C_FG2, font=F_UI,
                           cursor='hand2')
            lbl.pack(expand=True)
            under = tk.Frame(col, bg=C_BG, height=2)
            under.pack(fill='x', side='bottom')
            self._tab_btns[name] = (lbl, under)
            lbl.bind('<Button-1>', lambda e, n=name: self._show_tab(n))
            lbl.bind('<Enter>', lambda e, l=lbl: l.configure(fg=C_FG))
            lbl.bind('<Leave>', lambda e, n=name: self._tab_leave(n))
        tk.Frame(self, bg=C_HAIR, height=1).pack(fill='x')

        self._tab_host = tk.Frame(self, bg=C_BG)
        self._tab_host.pack(fill='both', expand=True)

        self._build_unlock_tab()
        self._build_help_tab()
        self._show_tab('Unlock')

    def _tab_leave(self, name):
        lbl, _ = self._tab_btns[name]
        lbl.configure(fg=C_FG if name == self._active_tab else C_FG2)

    def _show_tab(self, name: str):
        self._active_tab = name
        for n, f in self._tab_frames.items():
            f.pack_forget()
        for n, (lbl, under) in self._tab_btns.items():
            on = n == name
            lbl.configure(fg=C_FG if on else C_FG2)
            under.configure(bg=C_FG if on else C_BG)
        self._tab_frames[name].pack(fill='both', expand=True)

    # ── Unlock Tab ───────────────────────────────────────────────────────────

    def _build_unlock_tab(self):
        frame = tk.Frame(self._tab_host, bg=C_BG)
        self._tab_frames['Unlock'] = frame
        E = 20   # page edge

        # ── Identifiers card ─────────────────────────────────────────────────
        ic = Card(frame)
        ic.pack(fill='x', padx=E, pady=(16, 0))
        inner = ic.inner

        hrow = tk.Frame(inner, bg=C_CARD)
        hrow.grid(row=0, column=0, columnspan=3, sticky='ew', pady=(0, 12))
        tk.Label(hrow, text='Drive identifiers', bg=C_CARD, fg=C_FG,
                 font=F_UI).pack(side='left')
        tk.Label(hrow, text='From the head unit over SSH, see Help', bg=C_CARD,
                 fg=C_FG3, font=F_SM).pack(side='left', padx=(12, 0))

        inner.columnconfigure(0, minsize=104)
        inner.columnconfigure(1, weight=1)
        inner.columnconfigure(2, minsize=250)

        fields = [
            ('ETH MAC',      'E2P.Networking.Eth0MacAddr',  12),
            ('BT MAC',       'E2P.Networking.Bt0Addr',      12),
            ('Serial (hex)', 'E2P.ProdLogistic.SerialNo',   None),
        ]
        self._vars:       dict[str, tuple[tk.StringVar, int|None]] = {}
        self._err_labels: dict[str, tk.Label] = {}
        self._hints:      dict[str, str] = {}
        self._entries:    dict[str, tk.Entry] = {}

        def rp(i):   # 8px gap between rows
            return (0 if i == 0 else 4, 4)

        for i, (label, hint, elen) in enumerate(fields):
            row = i + 1
            tk.Label(inner, text=label, bg=C_CARD, fg=C_FG2, font=F_UI,
                     anchor='w').grid(row=row, column=0, sticky='w', pady=rp(i))
            var = tk.StringVar()
            self._vars[label] = (var, elen)
            box = tk.Frame(inner, bg=C_CARD, height=36)
            box.pack_propagate(False)
            box.grid(row=row, column=1, sticky='ew', pady=rp(i))
            ent = tk.Entry(box, textvariable=var, font=F_MONO, width=24,
                           bg=C_RAISED, fg=C_FG, insertbackground=C_FG,
                           relief='flat', bd=0, highlightthickness=1,
                           highlightbackground=C_HAIR, highlightcolor=C_HAIR_HI,
                           selectbackground=C_HAIR_HI, selectforeground=C_FG)
            ent.pack(fill='both', expand=True)
            self._entries[label] = ent
            self._hints[label] = hint
            err_lbl = tk.Label(inner, text=hint, bg=C_CARD, fg=C_FG3,
                               font=F_MONO_S, anchor='w', justify='left',
                               wraplength=240)
            err_lbl.grid(row=row, column=2, sticky='w', padx=(16, 0), pady=rp(i))
            self._err_labels[label] = err_lbl
            var.trace_add('write', lambda *_, l=label: self._on_field_change(l))

        drow = len(fields) + 1
        tk.Label(inner, text='SATA drive', bg=C_CARD, fg=C_FG2, font=F_UI,
                 anchor='w').grid(row=drow, column=0, sticky='w', pady=(4, 0))
        self._dev_var = tk.StringVar()
        dbox = tk.Frame(inner, bg=C_CARD, height=36)
        dbox.pack_propagate(False)
        dbox.grid(row=drow, column=1, sticky='ew', pady=(4, 0))
        self._dev_combo = ttk.Combobox(dbox, textvariable=self._dev_var,
                                       state='readonly', font=F_MONO, width=24,
                                       style='Dev.TCombobox')
        self._dev_combo.pack(fill='both', expand=True)
        self._dev_combo.bind('<<ComboboxSelected>>',
                             lambda _e: self._refresh_drive_state())
        self._rescan_btn = Btn(inner, 'Rescan', self._refresh_drives, bg=C_CARD)
        self._rescan_btn.grid(row=drow, column=2, sticky='w', padx=(16, 0),
                              pady=(4, 0))

        # Drive-state readout (signature detail)
        srow = tk.Frame(inner, bg=C_CARD)
        srow.grid(row=drow + 1, column=1, columnspan=2, sticky='w', pady=(8, 0))
        self._state_dot = tk.Canvas(srow, width=8, height=8, bg=C_CARD,
                                    highlightthickness=0)
        self._state_dot.pack(side='left', padx=(2, 8))
        self._state_dot_id = self._state_dot.create_oval(0, 0, 7, 7, fill=C_FG3,
                                                         outline='')
        self._state_lbl = tk.Label(srow, text='', bg=C_CARD, fg=C_FG3,
                                   font=F_MONO_S)
        self._state_lbl.pack(side='left')
        self._set_drive_state('no drive selected', C_FG3)

        # ── Password card ────────────────────────────────────────────────────
        pc = Card(frame)
        pc.pack(fill='x', padx=E, pady=(16, 0))
        pw_top = tk.Frame(pc.inner, bg=C_CARD)
        pw_top.pack(fill='x', pady=(0, 12))
        tk.Label(pw_top, text='ATA password', bg=C_CARD, fg=C_FG,
                 font=F_UI).pack(side='left')
        tk.Label(pw_top, text='MD5 · base64 · 20 characters', bg=C_CARD,
                 fg=C_FG3, font=F_MONO_S).pack(side='left', padx=(12, 0))

        pw_row = tk.Frame(pc.inner, bg=C_CARD)
        pw_row.pack(fill='x')
        self._pwd_lbl = tk.Label(pw_row, text=self._EMPTY_PWD, bg=C_CARD,
                                 fg=C_FG3, font=F_MONO_L)
        self._pwd_lbl.pack(side='left')
        self._copy_btn = Btn(pw_row, 'Copy', self._copy_password, height=32)
        self._copy_btn.pack(side='right')
        self._pwd_hint = tk.Label(pc.inner, text='Fill in the identifiers and derive',
                                  bg=C_CARD, fg=C_FG3, font=F_SM, anchor='w')
        self._pwd_hint.pack(fill='x', pady=(4, 0))

        # ── Actions ──────────────────────────────────────────────────────────
        btn_wrap = tk.Frame(frame, bg=C_BG)
        btn_wrap.pack(fill='x', padx=E, pady=(16, 0))
        self._derive_btn = Btn(btn_wrap, 'Derive password', self._derive_password)
        self._derive_btn.pack(side='left', padx=(0, 8))
        self._unlock_btn = Btn(btn_wrap, 'Unlock drive', self._do_unlock,
                               kind='primary')
        self._unlock_btn.pack(side='left', padx=(0, 8))
        self._status_btn = Btn(btn_wrap, 'Check status', self._query_status)
        self._status_btn.pack(side='left')
        self._perm_btn = Btn(btn_wrap, 'Remove password…', self._remove_password,
                             kind='quiet')
        self._perm_btn.pack(side='right')

        # ── Log ──────────────────────────────────────────────────────────────
        log_wrap = tk.Frame(frame, bg=C_BG)
        log_wrap.pack(fill='both', expand=True, padx=E, pady=(16, 20))
        tk.Label(log_wrap, text='Log', bg=C_BG, fg=C_FG2, font=F_UI,
                 anchor='w').pack(fill='x', pady=(0, 8))

        log_box = tk.Frame(log_wrap, bg=C_DEEP, highlightthickness=1,
                           highlightbackground=C_HAIR, highlightcolor=C_HAIR)
        log_box.pack(fill='both', expand=True)

        self._log = tk.Text(
            log_box, height=4, wrap='word', bg=C_DEEP, fg=C_FG2, font=F_MONO_S,
            insertbackground=C_FG, relief='flat', bd=0, highlightthickness=0,
            padx=12, pady=12, spacing3=2, state='disabled',
            selectbackground=C_HAIR_HI, selectforeground=C_FG)
        lsb = ttk.Scrollbar(log_box, orient='vertical', command=self._log.yview,
                            style='Log.Vertical.TScrollbar')
        self._log.configure(yscrollcommand=lsb.set)
        lsb.pack(side='right', fill='y')
        self._log.pack(side='left', fill='both', expand=True)

        self._log.tag_config('info',    foreground=C_FG2)
        self._log.tag_config('key',     foreground=C_FG)
        self._log.tag_config('success', foreground=C_POS)
        self._log.tag_config('error',   foreground=C_NEG)
        self._log.tag_config('warn',    foreground=C_FG)
        self._log.tag_config('dim',     foreground=C_FG3)
        self._log.tag_config('sep',     foreground=C_HAIR_HI)

        self._log_line('Enter the identifiers from the head unit, then derive the password', 'info')
        self._log_line('', 'info')
        self._log_line('sysetadjread --get=E2P.Networking.Eth0MacAddr', 'key')
        self._log_line('sysetadjread --get=E2P.Networking.Bt0Addr', 'key')
        self._log_line('sysetadjread --get=E2P.ProdLogistic.SerialNo', 'key')

    _EMPTY_PWD = '···· ···· ···· ···· ····'

    # ── Help Tab ─────────────────────────────────────────────────────────────

    def _build_help_tab(self):
        frame = tk.Frame(self._tab_host, bg=C_BG)
        self._tab_frames['Help'] = frame
        P = 20

        canvas = tk.Canvas(frame, bg=C_BG, highlightthickness=0)
        vsb = ttk.Scrollbar(frame, orient='vertical', command=canvas.yview,
                            style='Log.Vertical.TScrollbar')
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)

        inner = tk.Frame(canvas, bg=C_BG)
        win_id = canvas.create_window((0, 0), window=inner, anchor='nw')
        wrapped: list[tk.Label] = []

        def _on_resize(e):
            canvas.itemconfigure(win_id, width=e.width)
            for lb in wrapped:
                lb.configure(wraplength=max(200, e.width - 2 * P - 16))
        canvas.bind('<Configure>', _on_resize)
        inner.bind('<Configure>', lambda e: canvas.configure(
            scrollregion=canvas.bbox('all')))

        def _on_wheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), 'units')
        canvas.bind_all('<MouseWheel>', _on_wheel)
        canvas.bind_all('<Button-4>', lambda e: canvas.yview_scroll(-1, 'units'))
        canvas.bind_all('<Button-5>', lambda e: canvas.yview_scroll( 1, 'units'))

        tk.Frame(inner, bg=C_BG, height=16).pack()
        self._help_n = 0

        def section(text):
            if self._help_n:
                tk.Frame(inner, bg=C_HAIR, height=1).pack(
                    fill='x', padx=P, pady=(16, 16))
            self._help_n += 1
            row = tk.Frame(inner, bg=C_BG)
            row.pack(fill='x', padx=P, pady=(0, 8))
            tk.Label(row, text=f'{self._help_n:02d}', bg=C_BG, fg=C_FG3,
                     font=F_MONO_S).pack(side='left', padx=(0, 12))
            tk.Label(row, text=text, bg=C_BG, fg=C_FG, font=F_H,
                     anchor='w').pack(side='left')

        def body(text):
            lb = tk.Label(inner, text=text, bg=C_BG, fg=C_FG2, font=F_UI,
                          anchor='w', justify='left', wraplength=640)
            lb.pack(fill='x', padx=P, pady=(0, 8))
            wrapped.append(lb)

        def cmd_block(label, cmd):
            lbl_row = tk.Frame(inner, bg=C_BG)
            lbl_row.pack(fill='x', padx=P, pady=(0, 4))
            tk.Label(lbl_row, text=label, bg=C_BG, fg=C_FG3,
                     font=F_SM).pack(side='left')
            Btn(lbl_row, 'Copy', lambda c=cmd: self._copy_text(c), kind='link',
                height=20).pack(side='right')
            blk = tk.Frame(inner, bg=C_DEEP, highlightthickness=1,
                           highlightbackground=C_HAIR, highlightcolor=C_HAIR)
            blk.pack(fill='x', padx=P, pady=(0, 8))
            tk.Label(blk, text=cmd, bg=C_DEEP, fg=C_FG, font=F_MONO_S,
                     anchor='w', justify='left').pack(fill='x', padx=12, pady=12)

        def note(text):
            lb = tk.Label(inner, text='•  ' + text, bg=C_BG, fg=C_FG2,
                          font=F_UI, anchor='w', justify='left', wraplength=640)
            lb.pack(fill='x', padx=P, pady=(0, 4))
            wrapped.append(lb)

        section('Connect to the head unit')
        body('SSH into the BMW NBT Evo head unit.  Default port is 22 or 2222, '
             'depending on firmware.  Use the Ethernet port on the back of the unit '
             'or the OBD-II diagnostic port with a BMW ENET cable.')
        cmd_block('SSH command', 'ssh root@192.168.1.x   (or via ENET: 169.254.x.x)')

        section('Read the device identifiers')
        body('Run each command below on the head unit shell.  Paste the raw output '
             'directly into the field.  Colons, dashes, and spaces are stripped automatically.')
        cmd_block('Ethernet MAC, goes in ETH MAC',
                  'sysetadjread --get=E2P.Networking.Eth0MacAddr')
        body('Expected output:  E2P.Networking.Eth0MacAddr = 001122334455')
        cmd_block('Bluetooth MAC, goes in BT MAC',
                  'sysetadjread --get=E2P.Networking.Bt0Addr')
        body('Expected output:  E2P.Networking.Bt0Addr = 001122334466')
        cmd_block('Serial number, goes in Serial (hex)',
                  'sysetadjread --get=E2P.ProdLogistic.SerialNo')
        body('Expected output:  E2P.ProdLogistic.SerialNo = 00303132333435363738\n'
             'Paste the full hex string exactly as shown (20 hex chars = 10 bytes).')

        section('Run the unlock tool')
        body('Root is required to send ATA commands via SG_IO.')
        cmd_block('Launch with root', 'sudo python3 nbt_unlock.py')

        section('Prepare the drive')
        note('The drive must not be in a frozen state.  Power off the PC completely, '
             'connect the NBT HDD via SATA, then power on.  Do not hot-plug it.')
        note('If hdparm shows  "frozen"  then the drive cannot be unlocked until '
             'a fresh cold boot is performed with the drive already attached.')
        note('Each wrong password attempt decrements the security counter.  After '
             '5 failures the counter may freeze.  Power cycle the drive to reset it.')

        section('Remove the password permanently')
        body('The "Unlock drive" button is temporary and resets on every power cycle.  '
             'After a successful unlock, click "Remove password" or run:')
        cmd_block('hdparm command',
                  'sudo hdparm --security-disable <password> /dev/sdX')
        note('Replace <password> with the 20-char derived password shown in the app.')
        note('This permanently disables ATA security on the drive.  No password is '
             'needed on subsequent boots.')

        section('Password algorithm (reference)')
        body('BMW derives the ATA password in srv-hddmgr2 (ARM binary):')
        cmd_block('Python equivalent',
                  'import hashlib, base64\n'
                  'data = bytes.fromhex(ETH) + bytes.fromhex(BT) + bytes.fromhex(SNR)\n'
                  'password = base64.b64encode(hashlib.md5(data).digest()[:15])')

        tk.Frame(inner, bg=C_BG, height=24).pack()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _log_write(self, text: str, tag: str = 'info'):
        self._log.configure(state='normal')
        self._log.insert('end', text, tag)
        self._log.see('end')
        self._log.configure(state='disabled')

    def _log_line(self, text: str, tag: str = 'info'):
        self._log_write(text + '\n', tag)

    def _log_sep(self):
        self._log_write('─' * 52 + '\n', 'sep')

    def _update_root_status(self):
        if os.geteuid() == 0:
            return
        bar = tk.Frame(self, bg=C_BG)
        bar.pack(fill='x', padx=20, pady=(12, 0), before=self._tab_bar)
        dot = tk.Canvas(bar, width=8, height=8, bg=C_BG, highlightthickness=0)
        dot.create_oval(0, 0, 7, 7, fill=C_NEG, outline='')
        dot.pack(side='left', padx=(0, 8))
        tk.Label(bar, text='Not running as root, so unlock, status and password '
                 'removal will fail', bg=C_BG, fg=C_FG2, font=F_UI).pack(side='left')
        tk.Label(bar, text='sudo python3 nbt_unlock.py', bg=C_BG, fg=C_FG3,
                 font=F_MONO_S).pack(side='right')
        tk.Frame(self, bg=C_BG, height=12).pack(fill='x', before=self._tab_bar)

    def _set_drive_state(self, text: str, color: str):
        self._state_dot.itemconfigure(self._state_dot_id, fill=color)
        self._state_lbl.configure(text=text, fg=color)

    def _apply_security_state(self, sec: str):
        st = parse_security_state(sec)
        if st == 'locked':
            self._set_drive_state('locked', C_NEG)
        elif st == 'unlocked':
            self._set_drive_state('unlocked', C_POS)
        elif st == 'frozen':
            self._set_drive_state(
                'frozen · power-cycle the PC with the drive attached', C_NEG)
        elif st == 'disabled':
            self._set_drive_state('security not enabled', C_FG3)
        else:
            self._set_drive_state('state unknown', C_FG3)

    def _refresh_drive_state(self):
        self._state_seq += 1
        seq = self._state_seq
        device = self._get_device()
        if not device:
            self._set_drive_state('no drive selected', C_FG3)
            return
        if os.geteuid() != 0:
            self._set_drive_state('state unknown · needs root', C_FG3)
            return

        def _thread():
            sec = get_drive_security_status(device)

            def _apply():
                if seq == self._state_seq:
                    self._apply_security_state(sec)
            try:
                self.after(0, _apply)
            except RuntimeError:
                pass

        threading.Thread(target=_thread, daemon=True).start()

    def _refresh_drives(self):
        drives = list_sata_drives()
        descriptions = [desc for _, desc in drives]
        self._drive_map = {desc: dev for dev, desc in drives}
        self._dev_combo['values'] = descriptions
        if descriptions:
            self._dev_combo.current(0)
            self._dev_var.set(descriptions[0])
        else:
            self._dev_var.set('')
        self._refresh_drive_state()

    def _get_device(self) -> str | None:
        desc = self._dev_var.get()
        if desc in self._drive_map:
            return self._drive_map[desc]
        tok = desc.strip().split()[0] if desc.strip() else ''
        return tok if tok.startswith('/dev/') else None

    def _set_field_error(self, label: str, err: str | None):
        lbl = self._err_labels[label]
        ent = self._entries[label]
        if err:
            lbl.configure(text='✕ ' + err, fg=C_NEG)
            ent.configure(highlightbackground=C_NEG, highlightcolor=C_NEG,
                          fg=C_NEG)
        else:
            lbl.configure(text=self._hints[label], fg=C_FG3)
            ent.configure(highlightbackground=C_HAIR, highlightcolor=C_HAIR_HI,
                          fg=C_FG)

    def _on_field_change(self, label: str):
        var, elen = self._vars[label]
        raw = var.get()
        normalized = normalize_mac(raw) if label in ('ETH MAC', 'BT MAC') else raw.strip()
        self._set_field_error(label, validate_hex(normalized, elen))

    def _collect_inputs(self) -> tuple[str, str, str] | None:
        results = {}
        ok = True
        for label, (var, elen) in self._vars.items():
            raw = var.get()
            val = normalize_mac(raw) if label in ('ETH MAC', 'BT MAC') else raw.strip()
            err = validate_hex(val, elen)
            self._set_field_error(label, err)
            if err:
                ok = False
            else:
                results[label] = val
        return (results['ETH MAC'], results['BT MAC'], results['Serial (hex)']) if ok else None

    def _copy_text(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)

    def _show_password(self, pwd_str: str):
        grouped = ' '.join(pwd_str[i:i + 4] for i in range(0, len(pwd_str), 4))
        self._pwd_lbl.configure(text=grouped, fg=C_ACCENT)
        self._pwd_hint.configure(text='Copy it, or unlock the drive directly')

    # ── Actions ───────────────────────────────────────────────────────────────

    def _derive_password(self):
        inputs = self._collect_inputs()
        if inputs is None:
            self._log_line('!  Fix validation errors before deriving.', 'warn')
            return
        eth, bt, snr = inputs
        try:
            pwd = build_password(eth, bt, snr)
        except ValueError as e:
            self._log_line(f'✕  {e}', 'error')
            return
        pwd_str = pwd.decode()
        self._show_password(pwd_str)
        self._current_password = pwd_str
        self._log_sep()
        self._log_write('ETH   ', 'dim');  self._log_line(eth, 'info')
        self._log_write('BT    ', 'dim');  self._log_line(bt,  'info')
        self._log_write('SNR   ', 'dim');  self._log_line(snr, 'info')
        self._log_write('PWD   ', 'dim');  self._log_line(pwd_str, 'key')
        self._log_line('')

    def _copy_password(self):
        pwd = self._current_password
        if pwd:
            self.clipboard_clear()
            self.clipboard_append(pwd)
            self._log_line('  Copied password to clipboard.', 'dim')

    def _do_unlock(self):
        inputs = self._collect_inputs()
        if inputs is None:
            self._log_line('!  Fix validation errors.', 'warn')
            return
        device = self._get_device()
        if not device:
            self._log_line('!  No device selected.', 'warn')
            return
        if os.geteuid() != 0:
            self._log_line('✕  Root required for ATA commands.', 'error')
            return
        eth, bt, snr = inputs
        try:
            pwd = build_password(eth, bt, snr)
        except ValueError as e:
            self._log_line(f'✕  {e}', 'error')
            return
        pwd_str = pwd.decode()
        self._show_password(pwd_str)
        self._current_password = pwd_str
        self._lock_buttons(True)
        self._log_sep()
        self._log_write('ATA security unlock → ', 'dim')
        self._log_line(device, 'key')

        def _thread():
            try:
                status, host, driver, sense = send_ata_security_unlock(device, pwd)
                self.after(0, lambda: self._on_unlock_done(
                    device, pwd_str, status, host, driver, sense))
            except OSError as e:
                self.after(0, lambda: self._on_unlock_error(str(e)))

        threading.Thread(target=_thread, daemon=True).start()

    def _on_unlock_done(self, device, pwd_str, status, host, driver, sense):
        self._lock_buttons(False)
        if status == 0 and host == 0:
            self._log_line('✓  Drive unlocked successfully', 'success')
            self._log_write('  hdparm disable: ', 'dim')
            self._log_line(f'sudo hdparm --security-disable "{pwd_str}" {device}', 'key')
            sec = get_drive_security_status(device)
            if sec:
                self._log_line('')
                for line in sec.splitlines():
                    self._log_line('  ' + line, 'info')
                self._apply_security_state(sec)
        else:
            self._log_line(f'✕  Failed  (status={status} host={host} drv={driver})', 'error')
            if sense:
                self._log_line(f'  sense: {sense.hex()}', 'error')
            self._log_line('  Possible: wrong MAC/Serial, count expired, or drive frozen.', 'warn')
            self._refresh_drive_state()
        self._log_line('')

    def _on_unlock_error(self, msg: str):
        self._lock_buttons(False)
        self._log_line(f'✕  OS error: {msg}', 'error')

    def _query_status(self):
        device = self._get_device()
        if not device:
            self._log_line('!  No device selected.', 'warn')
            return
        self._log_sep()
        self._log_write('Security status → ', 'dim')
        self._log_line(device, 'key')

        def _thread():
            sec = get_drive_security_status(device)
            self.after(0, lambda: self._show_status(sec))

        threading.Thread(target=_thread, daemon=True).start()

    def _show_status(self, sec: str):
        for line in sec.splitlines():
            low = line.lower()
            if 'locked' in low and 'not' not in low:
                tag = 'error'
            elif 'not locked' in low or 'enabled' not in low:
                tag = 'success'
            else:
                tag = 'info'
            self._log_line('  ' + line, tag)
        self._log_line('')
        if os.geteuid() == 0:
            self._apply_security_state(sec)
        else:
            self._refresh_drive_state()

    def _remove_password(self):
        pwd_str = self._current_password
        if not pwd_str:
            self._log_line('!  Derive or unlock first to get the password.', 'warn')
            return
        device = self._get_device()
        if not device:
            self._log_line('!  No device selected.', 'warn')
            return
        if os.geteuid() != 0:
            self._log_line('✕  Root required.', 'error')
            return
        confirm = messagebox.askyesno(
            'Confirm permanent removal',
            f'Permanently remove ATA password from:\n\n  {device}\n\n'
            f'Password: {pwd_str}\n\n'
            'The drive will be accessible without a password on every boot.\n\nContinue?',
            icon='warning'
        )
        if not confirm:
            return
        self._lock_buttons(True)
        self._log_sep()
        self._log_write('Removing ATA password from ', 'warn')
        self._log_line(device + ' ...', 'key')

        def _thread():
            try:
                result = subprocess.run(
                    ['hdparm', '--security-disable', pwd_str, device],
                    capture_output=True, text=True, timeout=30
                )
                out = (result.stdout + result.stderr).strip()
                success = result.returncode == 0
                self.after(0, lambda: self._on_remove_done(success, out, device))
            except FileNotFoundError:
                self.after(0, lambda: self._on_unlock_error('hdparm not installed'))
            except subprocess.TimeoutExpired:
                self.after(0, lambda: self._on_unlock_error('hdparm timed out'))

        threading.Thread(target=_thread, daemon=True).start()

    def _on_remove_done(self, success: bool, output: str, device: str):
        self._lock_buttons(False)
        if success:
            self._log_line('✓  Password removed permanently.', 'success')
        else:
            self._log_line('✕  hdparm error:', 'error')
        for line in output.splitlines():
            self._log_line('  ' + line, 'info' if success else 'error')
        sec = get_drive_security_status(device)
        if sec:
            self._log_line('')
            for line in sec.splitlines():
                self._log_line('  ' + line, 'info')
            self._apply_security_state(sec)
        self._log_line('')

    def _lock_buttons(self, locked: bool):
        state = 'disabled' if locked else 'normal'
        for btn in (self._derive_btn, self._unlock_btn,
                    self._status_btn, self._perm_btn):
            btn.configure(state=state)


# ─── Command-line interface ──────────────────────────────────────────────────

def _err(msg: str):
    print(msg, file=sys.stderr)


def _cli_inputs(args) -> tuple[str, str, str] | None:
    """Validate --eth/--bt/--snr.  Prints errors and returns None if invalid."""
    missing = [f'--{n}' for n in ('eth', 'bt', 'snr') if getattr(args, n) is None]
    if missing:
        _err(f'error: missing {", ".join(missing)}')
        return None
    eth = normalize_mac(args.eth)
    bt  = normalize_mac(args.bt)
    snr = args.snr.strip()
    ok = True
    for label, val, elen in (('ETH MAC', eth, 12), ('BT MAC', bt, 12),
                             ('Serial (hex)', snr, None)):
        err = validate_hex(val, elen)
        if err:
            _err(f'error: {label}: {err}')
            ok = False
    return (eth, bt, snr) if ok else None


def _cli_password(args) -> str | None:
    """Return the password string from --password or derived from MAC/serial."""
    given = any(getattr(args, n) is not None for n in ('eth', 'bt', 'snr'))
    if args.password is not None:
        if given:
            _err('error: use either --password or --eth/--bt/--snr, not both')
            return None
        if not args.password:
            _err('error: --password is empty')
            return None
        return args.password
    inputs = _cli_inputs(args)
    if inputs is None:
        return None
    return build_password(*inputs).decode()


def _require_root() -> bool:
    if os.geteuid() != 0:
        _err('error: root required for ATA commands (try: sudo python3 '
             f'{os.path.basename(sys.argv[0])} ...)')
        return False
    return True


def cmd_list(args) -> int:
    drives = list_sata_drives()
    if not drives:
        _err('No SATA drives found.')
        return 1
    for _dev, desc in drives:
        print(desc)
    return 0


def cmd_derive(args) -> int:
    inputs = _cli_inputs(args)
    if inputs is None:
        return 2
    pwd = build_password(*inputs).decode()
    if args.quiet:
        print(pwd)
    else:
        print(f'ETH MAC : {inputs[0]}')
        print(f'BT MAC  : {inputs[1]}')
        print(f'Serial  : {inputs[2]}')
        print(f'Password: {pwd}')
    return 0


def cmd_status(args) -> int:
    print(get_drive_security_status(args.device))
    return 0


def cmd_unlock(args) -> int:
    pwd = _cli_password(args)
    if pwd is None:
        return 2
    if not _require_root():
        return 2
    print(f'ATA SECURITY UNLOCK -> {args.device}')
    try:
        status, host, driver, sense = send_ata_security_unlock(args.device, pwd.encode())
    except OSError as e:
        _err(f'error: OS error: {e}')
        return 1
    if status == 0 and host == 0:
        print('Drive unlocked')
        print(f'To remove the password permanently:\n'
              f'  sudo hdparm --security-disable "{pwd}" {args.device}')
        print()
        print(get_drive_security_status(args.device))
        return 0
    _err(f'FAILED  (status={status} host={host} drv={driver})')
    if sense:
        _err(f'  sense: {sense.hex()}')
    _err('  Possible: wrong MAC/Serial, count expired, or drive frozen.')
    return 1


def cmd_disable(args) -> int:
    pwd = _cli_password(args)
    if pwd is None:
        return 2
    if not _require_root():
        return 2
    if not args.yes:
        if not sys.stdin.isatty():
            _err('error: stdin is not a TTY; pass --yes to confirm non-interactively')
            return 2
        print(f'Permanently remove ATA password from {args.device}?')
        print('The drive will be accessible without a password on every boot.')
        if input('Continue? [y/N] ').strip().lower() not in ('y', 'yes'):
            print('Aborted.')
            return 1
    try:
        result = subprocess.run(['hdparm', '--security-disable', pwd, args.device],
                                capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        _err('error: hdparm not installed')
        return 1
    except subprocess.TimeoutExpired:
        _err('error: hdparm timed out')
        return 1
    out = (result.stdout + result.stderr).strip()
    if result.returncode == 0:
        print('Password removed permanently.')
        if out:
            print(out)
    else:
        _err('hdparm error:')
        if out:
            _err(out)
    print()
    print(get_drive_security_status(args.device))
    return 0 if result.returncode == 0 else 1


def cmd_gui(args=None) -> int:
    if not HAVE_TK:
        _err('error: tkinter is not installed; the GUI is unavailable.\n'
             'Use the command-line interface instead: python3 nbt_unlock.py --help')
        return 1
    try:
        app = NbtUnlockApp()
    except tk.TclError as e:
        _err(f'error: cannot start GUI ({e}).\n'
             'Use the command-line interface instead: python3 nbt_unlock.py --help')
        return 1
    app.mainloop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog='nbt_unlock.py',
        description='BMW NBT Evo HDD ATA security unlock. '
                    'With no arguments, the GUI is launched.')
    ap.add_argument('--gui', action='store_true', help='launch the GUI')
    sub = ap.add_subparsers(dest='command', metavar='COMMAND')

    def ident(p, required):
        p.add_argument('--eth', metavar='MAC', help='ETH MAC (any separators)')
        p.add_argument('--bt',  metavar='MAC', help='Bluetooth MAC (any separators)')
        p.add_argument('--snr', metavar='HEX', help='serial number, hex-encoded')

    sub.add_parser('list', help='list SATA drives').set_defaults(func=cmd_list)

    p = sub.add_parser('derive', help='derive and print the ATA password (no root)')
    ident(p, True)
    p.add_argument('-q', '--quiet', action='store_true', help='print only the password')
    p.set_defaults(func=cmd_derive)

    p = sub.add_parser('status', help='show ATA security status of a drive')
    p.add_argument('device', help='e.g. /dev/sdb')
    p.set_defaults(func=cmd_status)

    p = sub.add_parser('unlock', help='send ATA SECURITY UNLOCK (root)')
    p.add_argument('device', help='e.g. /dev/sdb')
    ident(p, False)
    p.add_argument('--password', metavar='PWD', help='use this 20-char password instead')
    p.set_defaults(func=cmd_unlock)

    p = sub.add_parser('disable', help='permanently remove the ATA password (root)')
    p.add_argument('device', help='e.g. /dev/sdb')
    ident(p, False)
    p.add_argument('--password', metavar='PWD', help='use this 20-char password instead')
    p.add_argument('-y', '--yes', action='store_true', help='skip confirmation prompt')
    p.set_defaults(func=cmd_disable)

    sub.add_parser('gui', help='launch the GUI').set_defaults(func=cmd_gui)
    return ap


# ─── Entry point ─────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        return cmd_gui()
    args = build_parser().parse_args(argv)
    if args.gui or args.command is None:
        return cmd_gui()
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
