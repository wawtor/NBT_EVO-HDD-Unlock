#!/usr/bin/env python3
"""
BMW NBT Evo HDD ATA Security Unlock — GUI
------------------------------------------
Unlocks an ATA-locked BMW NBT Evo hard drive connected via SATA.
Run with: sudo python3 nbt_unlock.py
"""

import ctypes
import fcntl
import hashlib
import base64
import os
import re
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont


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


# ─── GUI ─────────────────────────────────────────────────────────────────────

# ── BMW M Colour Palette ──────────────────────────────────────────────────────
C_BG       = '#0E0E12'   # deep carbon black
C_CARD     = '#17171D'   # card / panel surface
C_CARD2    = '#1F1F28'   # inset / input well
C_BORDER   = '#2A2A36'   # hairline borders
C_M_BLUE   = '#1A78D4'   # BMW M blue
C_M_PURPLE = '#6B35A0'   # BMW M violet
C_M_RED    = '#E4002B'   # BMW M red
C_FG       = '#EDEEF2'   # primary text
C_FG2      = '#8A8FA0'   # secondary / dim
C_FG3      = '#484D60'   # very muted
C_SUCCESS  = '#00C57A'   # green
C_WARN     = '#F0A500'   # amber
C_ERROR    = '#E4002B'
C_HOVER    = '#252530'   # generic hover surface

F_TITLE  = ('Helvetica', 15, 'bold')
F_UI     = ('Helvetica', 10)
F_UI_B   = ('Helvetica', 10, 'bold')
F_SM     = ('Helvetica', 9)
F_SM_B   = ('Helvetica', 9, 'bold')
F_MONO   = ('Courier New', 10)
F_MONO_B = ('Courier New', 11, 'bold')
F_MONO_S = ('Courier New', 9)


# ── Rounded-rect helper ───────────────────────────────────────────────────────

def _rrect(canvas: tk.Canvas, x1, y1, x2, y2, r=10, **kw):
    """Fill a rounded rectangle on *canvas* using arc + rect pieces."""
    r2 = r * 2
    canvas.create_arc(x1,      y1,      x1+r2, y1+r2, start= 90, extent=90, style='pieslice', **kw)
    canvas.create_arc(x2-r2,   y1,      x2,    y1+r2, start=  0, extent=90, style='pieslice', **kw)
    canvas.create_arc(x1,      y2-r2,   x1+r2, y2,    start=180, extent=90, style='pieslice', **kw)
    canvas.create_arc(x2-r2,   y2-r2,   x2,    y2,    start=270, extent=90, style='pieslice', **kw)
    canvas.create_rectangle(x1+r, y1,   x2-r,  y2,    **kw)
    canvas.create_rectangle(x1,   y1+r, x2,    y2-r,  **kw)


class Card(tk.Frame):
    """
    A tk.Frame that sits inside a Canvas, giving the illusion of rounded
    corners.  Use .inner for placing child widgets.
    The card occupies the whole parent area; call it inside a plain Frame
    that you size via pack/grid, then call .build() once after layout.
    """
    _RADIUS = 10

    def __init__(self, parent, fill=None, outline=C_BORDER, pad=14, **kw):
        super().__init__(parent, bg=C_BG, **kw)
        fill = fill or C_CARD
        self._fill = fill
        self._outline = outline
        self._pad = pad
        self._cv = tk.Canvas(self, bg=C_BG, highlightthickness=0)
        self._cv.pack(fill='both', expand=True)
        self.inner = tk.Frame(self._cv, bg=fill)
        self._win = self._cv.create_window(pad, pad, window=self.inner, anchor='nw')
        self._cv.bind('<Configure>', self._redraw)

    def _redraw(self, _=None):
        self._cv.delete('bg')
        w = self._cv.winfo_width()
        h = self._cv.winfo_height()
        if w < 6 or h < 6:
            return
        _rrect(self._cv, 1, 1, w-1, h-1, self._RADIUS,
               fill=self._fill, outline=self._outline, tags='bg')
        self._cv.tag_lower('bg')
        self._cv.itemconfigure(self._win,
                               width=w - self._pad*2,
                               height=h - self._pad*2)


class NbtUnlockApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('BMW NBT Evo — HDD ATA Unlock')
        self.configure(bg=C_BG)
        self.minsize(720, 660)
        self.resizable(True, True)
        self._current_password = ''
        self._drive_map: dict[str, str] = {}
        self._setup_styles()
        self._build_ui()
        self._refresh_drives()
        self._update_root_status()

    # ── Styles ────────────────────────────────────────────────────────────────

    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use('clam')

        def cfg(name, **kw):   s.configure(name, **kw)
        def mp(name, **kw):    s.map(name, **kw)

        cfg('.',
            background=C_BG, foreground=C_FG,
            fieldbackground=C_CARD2, insertcolor=C_FG,
            selectbackground=C_M_BLUE, selectforeground='#ffffff',
            font=F_UI)

        cfg('TFrame',            background=C_BG)
        cfg('Card.TFrame',       background=C_CARD)
        cfg('Inner.TFrame',      background=C_CARD)
        cfg('TLabel',            background=C_BG,    foreground=C_FG,   font=F_UI)
        cfg('Card.TLabel',       background=C_CARD,  foreground=C_FG,   font=F_UI)
        cfg('CardDim.TLabel',    background=C_CARD,  foreground=C_FG2,  font=F_SM)
        cfg('CardHead.TLabel',   background=C_CARD,  foreground=C_FG2,
            font=F_SM_B)
        cfg('Dim.TLabel',        background=C_BG,    foreground=C_FG2,  font=F_SM)
        cfg('Mono.TLabel',       background=C_CARD,  foreground=C_SUCCESS,
            font=F_MONO_B)
        cfg('Warn.TLabel',       background=C_BG,    foreground=C_WARN, font=F_SM)
        cfg('Err.TLabel',        background=C_CARD,  foreground=C_ERROR,font=F_SM)
        cfg('Err2.TLabel',       background=C_BG,    foreground=C_ERROR,font=F_SM)
        cfg('Ok.TLabel',         background=C_BG,    foreground=C_SUCCESS,font=F_SM)

        cfg('TEntry',
            fieldbackground=C_CARD2, foreground=C_FG,
            insertcolor=C_FG, borderwidth=1, relief='flat', padding=(8, 6))
        mp('TEntry',
            fieldbackground=[('focus', '#23253A')],
            bordercolor=[('focus', C_M_BLUE), ('!focus', C_BORDER)])

        cfg('TCombobox',
            fieldbackground=C_CARD2, foreground=C_FG,
            arrowcolor=C_FG2, padding=(8, 6), borderwidth=1)
        mp('TCombobox',
            fieldbackground=[('readonly', C_CARD2)],
            bordercolor=[('focus', C_M_BLUE), ('!focus', C_BORDER)])

        # Scrollbar
        cfg('TScrollbar',
            background=C_CARD2, troughcolor=C_CARD, arrowcolor=C_FG3, borderwidth=0)

        # Primary (blue) button
        cfg('Blue.TButton',
            background=C_M_BLUE, foreground='#ffffff',
            borderwidth=0, padding=(14, 8), font=F_UI_B, relief='flat')
        mp('Blue.TButton',
            background=[('active', '#2389E8'), ('disabled', '#333345')],
            foreground=[('disabled', C_FG3)])

        # Default (neutral) button
        cfg('TButton',
            background=C_CARD2, foreground=C_FG,
            borderwidth=0, padding=(12, 7), font=F_UI, relief='flat')
        mp('TButton',
            background=[('active', C_HOVER), ('disabled', C_CARD)],
            foreground=[('disabled', C_FG3)])

        # Danger (red) button
        cfg('Red.TButton',
            background='#3A1018', foreground='#FFAABB',
            borderwidth=0, padding=(14, 8), font=F_UI_B, relief='flat')
        mp('Red.TButton',
            background=[('active', C_M_RED)],
            foreground=[('active', '#ffffff')])

        # Tab buttons
        cfg('Tab.TButton',
            background=C_CARD, foreground=C_FG2,
            borderwidth=0, padding=(18, 9), font=F_UI_B, relief='flat')
        mp('Tab.TButton',
            background=[('active', C_HOVER)])

        cfg('ActiveTab.TButton',
            background=C_BG, foreground=C_FG,
            borderwidth=0, padding=(18, 9), font=F_UI_B, relief='flat')
        mp('ActiveTab.TButton',
            background=[('active', C_HOVER)])

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        P = 14   # outer horizontal pad

        # ── BMW M stripe header ───────────────────────────────────────────────
        hdr_canvas = tk.Canvas(self, bg=C_BG, height=72, highlightthickness=0)
        hdr_canvas.pack(fill='x')
        hdr_canvas.bind('<Configure>', lambda e, cv=hdr_canvas: self._draw_header(cv))

        # placeholder so _draw_header is called after geometry is known
        self._hdr_canvas = hdr_canvas

        # ── Root status pill ─────────────────────────────────────────────────
        self._root_bar = tk.Label(self, text='', bg=C_BG, fg=C_WARN,
                                  font=F_SM, anchor='w', padx=P+2)
        self._root_bar.pack(fill='x', pady=(0, 4))

        # ── Tab bar (manual, not ttk.Notebook for full styling control) ────────
        tab_bar = tk.Frame(self, bg=C_CARD, height=40)
        tab_bar.pack(fill='x')
        tab_bar.pack_propagate(False)

        self._tab_btns: dict[str, ttk.Button] = {}
        self._tab_frames: dict[str, tk.Frame] = {}

        for name in ('Unlock', 'Help'):
            btn = ttk.Button(tab_bar, text=f'  {name}  ',
                             style='Tab.TButton',
                             command=lambda n=name: self._show_tab(n))
            btn.pack(side='left')
            self._tab_btns[name] = btn

        # ── Tab content area ─────────────────────────────────────────────────
        self._tab_host = tk.Frame(self, bg=C_BG)
        self._tab_host.pack(fill='both', expand=True)

        self._build_unlock_tab()
        self._build_help_tab()
        self._show_tab('Unlock')

        # ── Footer hint bar ──────────────────────────────────────────────────
        foot = tk.Label(self,
                        text='  Run with   sudo python3 nbt_unlock.py   for hardware access',
                        bg=C_CARD, fg=C_FG3, font=F_SM, anchor='w', pady=5)
        foot.pack(fill='x', side='bottom')

    # ── Header painter ────────────────────────────────────────────────────────

    def _draw_header(self, cv: tk.Canvas):
        _P = 14
        cv.delete('all')
        w = cv.winfo_width()
        if w < 10:
            return
        h = cv.winfo_height()
        stripe_h = 5
        sw = w // 3
        # M-stripe at very top
        cv.create_rectangle(0,      0, sw,    stripe_h, fill=C_M_BLUE,   outline='')
        cv.create_rectangle(sw,     0, sw*2,  stripe_h, fill=C_M_PURPLE, outline='')
        cv.create_rectangle(sw*2,   0, w,     stripe_h, fill=C_M_RED,    outline='')
        # Title text
        cv.create_text(_P+2, stripe_h+14, text='BMW NBT Evo',
                       fill=C_FG, font=F_TITLE, anchor='nw')
        cv.create_text(_P+2, stripe_h+36, text='HDD ATA Security Unlock Tool',
                       fill=C_FG2, font=F_SM, anchor='nw')
        # right side M badge
        bx = w - 14
        bw = 36
        bs = bw // 3
        by = stripe_h + 22
        bh = 9
        cv.create_rectangle(bx-bw,    by, bx-bw+bs,   by+bh, fill=C_M_BLUE,   outline='')
        cv.create_rectangle(bx-bw+bs, by, bx-bw+bs*2, by+bh, fill=C_M_PURPLE, outline='')
        cv.create_rectangle(bx-bw+bs*2,by,bx,         by+bh, fill=C_M_RED,    outline='')
        cv.create_text(bx - bw//2, by + bh + 6, text='M', fill=C_FG2, font=F_SM_B)

    # ── Tab switcher ─────────────────────────────────────────────────────────

    def _show_tab(self, name: str):
        for n, f in self._tab_frames.items():
            f.pack_forget()
        for n, b in self._tab_btns.items():
            b.configure(style='ActiveTab.TButton' if n == name else 'Tab.TButton')
        self._tab_frames[name].pack(fill='both', expand=True)

    # ── Unlock Tab ───────────────────────────────────────────────────────────

    def _build_unlock_tab(self):
        P = 14
        frame = tk.Frame(self._tab_host, bg=C_BG)
        self._tab_frames['Unlock'] = frame

        # ── Input card ───────────────────────────────────────────────────────
        ic_wrap = tk.Frame(frame, bg=C_BG)
        ic_wrap.pack(fill='x', padx=P, pady=(10, 6))

        ic = Card(ic_wrap, pad=12)
        ic.pack(fill='x')

        # header row inside card
        hrow = tk.Frame(ic.inner, bg=C_CARD)
        hrow.grid(row=0, column=0, columnspan=4, sticky='ew', pady=(0, 8))
        tk.Label(hrow, text='DEVICE IDENTIFIERS', bg=C_CARD, fg=C_M_BLUE,
                 font=F_SM_B).pack(side='left')
        tk.Label(hrow, text='  —  from SSH: sysetadjread', bg=C_CARD,
                 fg=C_FG3, font=F_SM).pack(side='left')

        ic.inner.columnconfigure(1, weight=1)
        ic.inner.columnconfigure(3, weight=0)

        fields = [
            ('ETH MAC',      'E2P.Networking.Eth0MacAddr',  12),
            ('BT MAC',       'E2P.Networking.Bt0Addr',      12),
            ('Serial (hex)', 'E2P.ProdLogistic.SerialNo',   None),
        ]
        self._vars:       dict[str, tuple[tk.StringVar, int|None]] = {}
        self._err_labels: dict[str, tk.Label] = {}

        for row, (label, hint, elen) in enumerate(fields, start=1):
            tk.Label(ic.inner, text=label, bg=C_CARD, fg=C_FG2,
                     font=F_SM_B, anchor='e', width=13).grid(
                         row=row, column=0, sticky='e', padx=(0, 8), pady=3)

            var = tk.StringVar()
            self._vars[label] = (var, elen)

            ent = ttk.Entry(ic.inner, textvariable=var, font=F_MONO, width=30)
            ent.grid(row=row, column=1, sticky='ew', padx=(0, 10), pady=3)

            tk.Label(ic.inner, text=hint, bg=C_CARD, fg=C_FG3,
                     font=F_SM).grid(row=row, column=2, sticky='w', pady=3)

            err_lbl = tk.Label(ic.inner, text='', bg=C_CARD,
                               fg=C_ERROR, font=F_SM)
            err_lbl.grid(row=row, column=3, sticky='w', padx=(8, 0), pady=3)
            self._err_labels[label] = err_lbl

            var.trace_add('write', lambda *_, l=label: self._on_field_change(l))

        # device row
        drow = len(fields) + 1
        tk.Label(ic.inner, text='SATA Device', bg=C_CARD, fg=C_FG2,
                 font=F_SM_B, anchor='e', width=13).grid(
                     row=drow, column=0, sticky='e', padx=(0, 8), pady=(10, 3))

        self._dev_var = tk.StringVar()
        self._dev_combo = ttk.Combobox(ic.inner, textvariable=self._dev_var,
                                       state='readonly', font=F_MONO, width=30)
        self._dev_combo.grid(row=drow, column=1, sticky='ew', padx=(0, 10), pady=(10, 3))

        ref_btn = ttk.Button(ic.inner, text='⟳', width=3,
                             command=self._refresh_drives)
        ref_btn.grid(row=drow, column=2, sticky='w', pady=(10, 3))

        # ── Password card ─────────────────────────────────────────────────────
        pc_wrap = tk.Frame(frame, bg=C_BG)
        pc_wrap.pack(fill='x', padx=P, pady=(0, 6))

        pc = Card(pc_wrap, fill=C_CARD, pad=12)
        pc.pack(fill='x')

        pw_top = tk.Frame(pc.inner, bg=C_CARD)
        pw_top.pack(fill='x')
        tk.Label(pw_top, text='DERIVED ATA PASSWORD', bg=C_CARD, fg=C_FG2,
                 font=F_SM_B).pack(side='left')

        self._copy_btn = tk.Button(pw_top, text='Copy',
                                   bg=C_CARD2, fg=C_FG2, activebackground=C_HOVER,
                                   activeforeground=C_FG, font=F_SM,
                                   relief='flat', bd=0, padx=10, pady=2,
                                   cursor='hand2', command=self._copy_password)
        self._copy_btn.pack(side='right')

        self._pwd_lbl = tk.Label(pc.inner, text='—', bg=C_CARD,
                                 fg=C_SUCCESS, font=F_MONO_B)
        self._pwd_lbl.pack(anchor='w', pady=(4, 0))

        # ── Action buttons ────────────────────────────────────────────────────
        btn_wrap = tk.Frame(frame, bg=C_BG)
        btn_wrap.pack(fill='x', padx=P, pady=(0, 6))

        self._derive_btn = ttk.Button(btn_wrap, text='  Derive Password',
                                      command=self._derive_password)
        self._derive_btn.pack(side='left', padx=(0, 6))

        self._unlock_btn = ttk.Button(btn_wrap, text='  Unlock Drive',
                                      style='Blue.TButton',
                                      command=self._do_unlock)
        self._unlock_btn.pack(side='left', padx=(0, 6))

        self._status_btn = ttk.Button(btn_wrap, text='  Drive Status',
                                      command=self._query_status)
        self._status_btn.pack(side='left', padx=(0, 6))

        self._perm_btn = ttk.Button(btn_wrap, text='  Remove Password',
                                    style='Red.TButton',
                                    command=self._remove_password)
        self._perm_btn.pack(side='right')

        # thin separator
        sep = tk.Frame(frame, bg=C_BORDER, height=1)
        sep.pack(fill='x', padx=P, pady=(0, 4))

        # ── Log area ──────────────────────────────────────────────────────────
        log_wrap = tk.Frame(frame, bg=C_BG)
        log_wrap.pack(fill='both', expand=True, padx=P, pady=(0, 8))

        tk.Label(log_wrap, text='OUTPUT LOG', bg=C_BG, fg=C_FG3,
                 font=F_SM_B, anchor='w').pack(fill='x', pady=(0, 4))

        log_cv = tk.Frame(log_wrap, bg=C_CARD, bd=0)
        log_cv.pack(fill='both', expand=True)

        self._log = tk.Text(
            log_cv, height=10, wrap='word',
            bg=C_CARD, fg=C_FG, font=F_MONO,
            insertbackground=C_FG, relief='flat',
            padx=10, pady=8, state='disabled',
            selectbackground=C_M_BLUE, selectforeground='#ffffff'
        )
        lsb = ttk.Scrollbar(log_cv, orient='vertical', command=self._log.yview)
        self._log.configure(yscrollcommand=lsb.set)
        lsb.pack(side='right', fill='y')
        self._log.pack(side='left', fill='both', expand=True)

        self._log.tag_config('info',    foreground=C_FG)
        self._log.tag_config('success', foreground=C_SUCCESS)
        self._log.tag_config('error',   foreground=C_ERROR)
        self._log.tag_config('warn',    foreground=C_WARN)
        self._log.tag_config('dim',     foreground=C_FG2)
        self._log.tag_config('key',     foreground=C_M_BLUE,
                             font=F_MONO_B)

        # welcome message
        self._log_write('BMW NBT Evo  ·  ATA Security Unlock\n', 'key')
        self._log_write('─' * 52 + '\n', 'dim')
        self._log_write('Enter device identifiers, then click ', 'dim')
        self._log_write('Derive Password', 'info')
        self._log_write('.\nFor values, SSH into the head unit and run:\n\n', 'dim')
        self._log_write('  sysetadjread --get=E2P.Networking.Eth0MacAddr\n', 'key')
        self._log_write('  sysetadjread --get=E2P.Networking.Bt0Addr\n', 'key')
        self._log_write('  sysetadjread --get=E2P.ProdLogistic.SerialNo\n\n', 'key')

    # ── Help Tab ─────────────────────────────────────────────────────────────

    def _build_help_tab(self):
        P = 14
        frame = tk.Frame(self._tab_host, bg=C_BG)
        self._tab_frames['Help'] = frame

        # scrollable container
        canvas = tk.Canvas(frame, bg=C_BG, highlightthickness=0)
        vsb = ttk.Scrollbar(frame, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)

        inner = tk.Frame(canvas, bg=C_BG)
        win_id = canvas.create_window((0, 0), window=inner, anchor='nw')

        def _on_resize(e):
            canvas.itemconfigure(win_id, width=e.width)
        canvas.bind('<Configure>', _on_resize)
        inner.bind('<Configure>', lambda e: canvas.configure(
            scrollregion=canvas.bbox('all')))

        # bind mouse wheel
        def _on_wheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), 'units')
        canvas.bind_all('<MouseWheel>', _on_wheel)
        # Linux scroll
        canvas.bind_all('<Button-4>', lambda e: canvas.yview_scroll(-1, 'units'))
        canvas.bind_all('<Button-5>', lambda e: canvas.yview_scroll( 1, 'units'))

        def section(text):
            tk.Label(inner, text=text, bg=C_BG, fg=C_M_BLUE,
                     font=F_UI_B, anchor='w').pack(fill='x', padx=P, pady=(16, 4))
            tk.Frame(inner, bg=C_M_BLUE, height=1).pack(fill='x', padx=P, pady=(0, 8))

        def body(text):
            tk.Label(inner, text=text, bg=C_BG, fg=C_FG2,
                     font=F_UI, anchor='w', justify='left',
                     wraplength=640).pack(fill='x', padx=P+4, pady=(0, 4))

        def cmd_block(label, cmd):
            """A labeled copyable command block."""
            blk = Card(inner, fill=C_CARD2, pad=10)
            blk.pack(fill='x', padx=P, pady=(0, 8))

            lbl_row = tk.Frame(blk.inner, bg=C_CARD2)
            lbl_row.pack(fill='x', pady=(0, 4))
            tk.Label(lbl_row, text=label.upper(), bg=C_CARD2, fg=C_FG3,
                     font=F_SM_B).pack(side='left')

            copy_btn = tk.Button(lbl_row, text='Copy',
                                 bg=C_CARD, fg=C_FG2,
                                 activebackground=C_HOVER, activeforeground=C_FG,
                                 font=F_SM, relief='flat', bd=0,
                                 padx=8, pady=1, cursor='hand2',
                                 command=lambda c=cmd: self._copy_text(c))
            copy_btn.pack(side='right')

            tk.Label(blk.inner, text=cmd, bg=C_CARD2, fg=C_M_BLUE,
                     font=F_MONO, anchor='w', justify='left').pack(fill='x')

        def note(text):
            tk.Label(inner, text='  •  ' + text, bg=C_BG, fg=C_FG2,
                     font=F_SM, anchor='w', justify='left',
                     wraplength=640).pack(fill='x', padx=P+4, pady=1)

        # ── Section: Connection ───────────────────────────────────────────────
        section('1 · Connecting to the Head Unit')
        body('SSH into the BMW NBT Evo head unit.  Default port is 22 or 2222, '
             'depending on firmware.  Use the Ethernet port on the back of the unit '
             'or the OBD-II diagnostic port with a BMW ENET cable.')
        cmd_block('SSH command', 'ssh root@192.168.1.x   (or via ENET: 169.254.x.x)')

        # ── Section: Reading values ────────────────────────────────────────────
        section('2 · Reading Device Identifiers')
        body('Run each command below on the head unit shell.  Paste the raw output '
             'directly into the field — colons, dashes, and spaces are stripped automatically.')

        cmd_block('Ethernet MAC  →  ETH MAC field',
                  'sysetadjread --get=E2P.Networking.Eth0MacAddr')
        body('Expected output:  E2P.Networking.Eth0MacAddr = A056B27F3BDB')

        cmd_block('Bluetooth MAC  →  BT MAC field',
                  'sysetadjread --get=E2P.Networking.Bt0Addr')
        body('Expected output:  E2P.Networking.Bt0Addr = A056B21ED620')

        cmd_block('Serial Number  →  Serial (hex) field',
                  'sysetadjread --get=E2P.ProdLogistic.SerialNo')
        body('Expected output:  E2P.ProdLogistic.SerialNo = 00334633313131343338\n'
             'Paste the full hex string exactly as shown (20 hex chars = 10 bytes).')

        # ── Section: Running the tool ──────────────────────────────────────────
        section('3 · Running the Unlock Tool')
        body('Root is required to send ATA commands via SG_IO.')
        cmd_block('Launch with root', 'sudo python3 nbt_unlock.py')

        # ── Section: Drive prep ────────────────────────────────────────────────
        section('4 · Drive Preparation')
        note('The drive must not be in a FROZEN state.  Power off the PC completely, '
             'connect the NBT HDD via SATA, then power on — do NOT hot-plug it.')
        note('If hdparm shows  "frozen"  then the drive cannot be unlocked until '
             'a fresh cold boot is performed with the drive already attached.')
        note('Each wrong password attempt decrements the security counter.  After '
             '5 failures the counter may freeze.  Power cycle the drive to reset it.')

        # ── Section: Permanent removal ─────────────────────────────────────────
        section('5 · Permanently Remove the Password')
        body('The "Unlock Drive" button is temporary — it resets on every power cycle.  '
             'After a successful unlock, click "Remove Password" or run:')
        cmd_block('hdparm command',
                  'sudo hdparm --security-disable <password> /dev/sdX')
        note('Replace <password> with the 20-char derived password shown in the app.')
        note('This permanently disables ATA security on the drive — no password needed '
             'on subsequent boots.')

        # ── Section: Password algorithm ────────────────────────────────────────
        section('6 · Password Algorithm (Reference)')
        body('BMW derives the ATA password in srv-hddmgr2 (ARM binary):')
        cmd_block('Python equivalent',
                  'import hashlib, base64\n'
                  'data = bytes.fromhex(ETH) + bytes.fromhex(BT) + bytes.fromhex(SNR)\n'
                  'password = base64.b64encode(hashlib.md5(data).digest()[:15])')

        tk.Frame(inner, bg=C_BG, height=24).pack()   # bottom spacer

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _log_write(self, text: str, tag: str = 'info'):
        self._log.configure(state='normal')
        self._log.insert('end', text, tag)
        self._log.see('end')
        self._log.configure(state='disabled')

    def _log_line(self, text: str, tag: str = 'info'):
        self._log_write(text + '\n', tag)

    def _log_sep(self):
        self._log_write('─' * 52 + '\n', 'dim')

    def _update_root_status(self):
        if os.geteuid() != 0:
            self._root_bar.configure(
                text='  ⚠  Not running as root — hardware operations will fail.  '
                     'Restart with:  sudo python3 nbt_unlock.py',
                fg=C_WARN)
        else:
            self._root_bar.configure(text='  ✓  Running as root', fg=C_SUCCESS)

    def _refresh_drives(self):
        drives = list_sata_drives()
        descriptions = [desc for _, desc in drives]
        self._drive_map = {desc: dev for dev, desc in drives}
        self._dev_combo['values'] = descriptions
        if descriptions:
            self._dev_combo.current(0)
            self._dev_var.set(descriptions[0])

    def _get_device(self) -> str | None:
        desc = self._dev_var.get()
        if desc in self._drive_map:
            return self._drive_map[desc]
        tok = desc.strip().split()[0] if desc.strip() else ''
        return tok if tok.startswith('/dev/') else None

    def _on_field_change(self, label: str):
        var, elen = self._vars[label]
        raw = var.get()
        normalized = normalize_mac(raw) if label in ('ETH MAC', 'BT MAC') else raw.strip()
        err = validate_hex(normalized, elen)
        lbl = self._err_labels[label]
        if err:
            lbl.configure(text='✕ ' + err)
        else:
            lbl.configure(text='')

    def _collect_inputs(self) -> tuple[str, str, str] | None:
        results = {}
        ok = True
        for label, (var, elen) in self._vars.items():
            raw = var.get()
            val = normalize_mac(raw) if label in ('ETH MAC', 'BT MAC') else raw.strip()
            err = validate_hex(val, elen)
            if err:
                self._err_labels[label].configure(text='✕ ' + err)
                ok = False
            else:
                self._err_labels[label].configure(text='')
                results[label] = val
        return (results['ETH MAC'], results['BT MAC'], results['Serial (hex)']) if ok else None

    def _copy_text(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _derive_password(self):
        inputs = self._collect_inputs()
        if inputs is None:
            self._log_line('⚠  Fix validation errors before deriving.', 'warn')
            return
        eth, bt, snr = inputs
        try:
            pwd = build_password(eth, bt, snr)
        except ValueError as e:
            self._log_line(f'✕  {e}', 'error')
            return
        pwd_str = pwd.decode()
        self._pwd_lbl.configure(text=pwd_str)
        self._current_password = pwd_str
        self._log_sep()
        self._log_write('ETH   ', 'dim');  self._log_line(eth, 'info')
        self._log_write('BT    ', 'dim');  self._log_line(bt,  'info')
        self._log_write('SNR   ', 'dim');  self._log_line(snr, 'info')
        self._log_write('PWD   ', 'dim');  self._log_line(pwd_str, 'key')
        self._log_line('')

    def _copy_password(self):
        pwd = self._pwd_lbl.cget('text')
        if pwd and pwd != '—':
            self.clipboard_clear()
            self.clipboard_append(pwd)
            self._log_line('  Copied password to clipboard.', 'dim')

    def _do_unlock(self):
        inputs = self._collect_inputs()
        if inputs is None:
            self._log_line('⚠  Fix validation errors.', 'warn')
            return
        device = self._get_device()
        if not device:
            self._log_line('⚠  No device selected.', 'warn')
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
        self._pwd_lbl.configure(text=pwd_str)
        self._current_password = pwd_str
        self._lock_buttons(True)
        self._log_sep()
        self._log_write('ATA SECURITY UNLOCK → ', 'dim')
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
            self._log_line('✓  Drive unlocked successfully!', 'success')
            self._log_write('  hdparm disable: ', 'dim')
            self._log_line(f'sudo hdparm --security-disable "{pwd_str}" {device}', 'key')
            sec = get_drive_security_status(device)
            if sec:
                self._log_line('')
                for line in sec.splitlines():
                    self._log_line('  ' + line, 'info')
        else:
            self._log_line(f'✕  FAILED  (status={status} host={host} drv={driver})', 'error')
            if sense:
                self._log_line(f'  sense: {sense.hex()}', 'error')
            self._log_line('  Possible: wrong MAC/Serial, count expired, or drive frozen.', 'warn')
        self._log_line('')

    def _on_unlock_error(self, msg: str):
        self._lock_buttons(False)
        self._log_line(f'✕  OS error: {msg}', 'error')

    def _query_status(self):
        device = self._get_device()
        if not device:
            self._log_line('⚠  No device selected.', 'warn')
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

    def _remove_password(self):
        pwd_str = self._current_password
        if not pwd_str:
            self._log_line('⚠  Derive or unlock first to get the password.', 'warn')
            return
        device = self._get_device()
        if not device:
            self._log_line('⚠  No device selected.', 'warn')
            return
        if os.geteuid() != 0:
            self._log_line('✕  Root required.', 'error')
            return
        confirm = messagebox.askyesno(
            'Confirm Permanent Removal',
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
        self._log_line('')

    def _lock_buttons(self, locked: bool):
        state = 'disabled' if locked else 'normal'
        for btn in (self._derive_btn, self._unlock_btn,
                    self._status_btn, self._perm_btn):
            btn.configure(state=state)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    app = NbtUnlockApp()
    app.mainloop()


if __name__ == '__main__':
    main()
