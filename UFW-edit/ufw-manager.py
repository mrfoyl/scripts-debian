#!/usr/bin/env python3
"""UFW Firewall Manager — interactive TUI"""

import curses
import json
import os
import re
import subprocess
import sys

# ── colour pair IDs ────────────────────────────────────────────────────────────
CP_TITLE  = 1
CP_HEADER = 2
CP_SEL    = 3
CP_ALLOW  = 4
CP_DENY   = 5
CP_LIMIT  = 6
CP_ACTIVE = 7
CP_INACT  = 8
CP_OK     = 9
CP_ERR    = 10
CP_BORDER = 11
CP_FOOT   = 12
CP_KEY    = 13
CP_INFO   = 14
CP_DIM    = 15


# ── disabled-rules store ───────────────────────────────────────────────────────

DISABLED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.ufw_disabled.json')


def _load_disabled():
    try:
        with open(DISABLED_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_disabled(rules):
    with open(DISABLED_FILE, 'w') as f:
        json.dump(rules, f, indent=2)


# ── ufw helpers ────────────────────────────────────────────────────────────────

def _run(*args):
    cmd = list(args)
    if os.geteuid() != 0:
        cmd = ['sudo'] + cmd
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def _rule_to_add_cmd(rule):
    """Reconstruct a ufw add command from a rule dict (active or disabled)."""
    verb    = rule['action'].split()[0].lower()
    to      = rule['to']
    frm     = rule['from']
    comment = rule.get('comment', '').strip()

    if frm.lower().startswith('anywhere'):
        cmd = ['ufw', verb, to]
    else:
        cmd = ['ufw', verb, 'from', frm, 'to', 'any', 'port', to]

    if comment:
        cmd += ['comment', comment]
    return cmd


def fetch_rules():
    """Return (status_str, combined_rule_list).

    Active UFW rules come first ('disabled': False).
    Disabled (stored) rules follow  ('disabled': True).
    UFW native comments are parsed from the status output.
    """
    _rc, out, _err = _run('ufw', 'status', 'numbered')
    status = 'inactive'
    rules  = []

    # Matches:  [ 1] 22/tcp   ALLOW IN   Anywhere           # optional comment
    pat = re.compile(
        r'^\[\s*(\d+)\]\s+'
        r'(.+?)\s{2,}'
        r'(ALLOW|DENY|REJECT|LIMIT)'
        r'(\s+IN|\s+OUT|\s+FWD)?'
        r'\s+(.+)$'
    )
    for line in out.splitlines():
        if line.startswith('Status:'):
            status = line.split(':', 1)[1].strip().lower()
        m = pat.match(line.strip())
        if m:
            from_raw = m.group(5).strip()
            # UFW appends comments after 3+ spaces, with optional leading '#'
            cm = re.search(r'\s{3,}#?\s*(.+)$', from_raw)
            if cm:
                from_  = from_raw[:cm.start()].strip()
                comment = cm.group(1).strip()
            else:
                from_   = from_raw
                comment = ''

            rules.append({
                'num'     : int(m.group(1)),
                'to'      : m.group(2).strip(),
                'action'  : (m.group(3) + (m.group(4) or '')).strip(),
                'from'    : from_,
                'comment' : comment,
                'disabled': False,
            })

    for idx, r in enumerate(_load_disabled()):
        rules.append({
            'num'     : None,
            'to'      : r['to'],
            'action'  : r['action'],
            'from'    : r['from'],
            'comment' : r.get('comment', ''),
            'disabled': True,
            '_di'     : idx,
        })

    return status, rules


# ── main application class ─────────────────────────────────────────────────────

class UFWManager:

    MIN_W = 82
    MIN_H = 12

    SHORTCUTS = [
        ('Spc', 'Toggle rule'),
        ('A',   'Add'),
        ('C',   'Comment'),
        ('D',   'Delete'),
        ('↑↓',  'Navigate'),
        ('E',   'UFW on'),
        ('X',   'UFW off'),
        ('R',   'Refresh'),
        ('Q',   'Quit'),
    ]

    def __init__(self, stdscr):
        self.scr    = stdscr
        self.rules  = []
        self.status = 'unknown'
        self.cursor = 0
        self.scroll = 0
        self.flash      = ''
        self.flash_good = True

        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        self._init_colors()
        self.scr.keypad(True)
        self._reload()

    # ── colour setup ───────────────────────────────────────────────────────────

    def _init_colors(self):
        def p(i, fg, bg=-1):
            curses.init_pair(i, fg, bg)
        p(CP_TITLE,  curses.COLOR_BLACK,  curses.COLOR_CYAN)
        p(CP_HEADER, curses.COLOR_BLACK,  curses.COLOR_BLUE)
        p(CP_SEL,    curses.COLOR_BLACK,  curses.COLOR_WHITE)
        p(CP_ALLOW,  curses.COLOR_GREEN,  -1)
        p(CP_DENY,   curses.COLOR_RED,    -1)
        p(CP_LIMIT,  curses.COLOR_YELLOW, -1)
        p(CP_ACTIVE, curses.COLOR_GREEN,  -1)
        p(CP_INACT,  curses.COLOR_RED,    -1)
        p(CP_OK,     curses.COLOR_GREEN,  -1)
        p(CP_ERR,    curses.COLOR_RED,    -1)
        p(CP_BORDER, curses.COLOR_CYAN,   -1)
        p(CP_FOOT,   curses.COLOR_BLACK,  curses.COLOR_BLUE)
        p(CP_KEY,    curses.COLOR_YELLOW, curses.COLOR_BLUE)
        p(CP_INFO,   curses.COLOR_CYAN,   -1)
        p(CP_DIM,    curses.COLOR_WHITE,  -1)

    # ── data ───────────────────────────────────────────────────────────────────

    def _reload(self):
        self.status, self.rules = fetch_rules()
        self.cursor = min(self.cursor, max(0, len(self.rules) - 1))

    # ── column layout ──────────────────────────────────────────────────────────

    def _cols(self, W):
        """Return (num_w, to_w, action_w, from_w, comment_w)."""
        num_w     = 4
        action_w  = 14
        comment_w = 22
        gutters   = 5   # one space between each of the 5 columns
        spare     = W - num_w - action_w - comment_w - gutters - 2
        to_w      = max(16, spare * 52 // 100)
        from_w    = max(12, spare - to_w)
        return num_w, to_w, action_w, from_w, comment_w

    # ── drawing ────────────────────────────────────────────────────────────────

    def draw(self):
        self.scr.erase()
        H, W = self.scr.getmaxyx()
        if H < self.MIN_H or W < self.MIN_W:
            self.scr.addstr(0, 0, f'Terminal too small — need {self.MIN_W}×{self.MIN_H}')
            self.scr.refresh()
            return
        self._draw_title(W)
        self._draw_headers(W)
        self._draw_rules(H, W)
        self._draw_flash(H, W)
        self._draw_footer(H, W)
        self.scr.refresh()

    def _draw_title(self, W):
        is_active  = self.status == 'active'
        badge      = '● ACTIVE  ' if is_active else '○ INACTIVE'
        badge_pair = CP_ACTIVE if is_active else CP_INACT

        self.scr.attron(curses.color_pair(CP_TITLE) | curses.A_BOLD)
        self.scr.addstr(0, 0, ' ' * (W - 1))
        self.scr.addstr(0, 0, '  UFW Firewall Manager')
        self.scr.attroff(curses.color_pair(CP_TITLE) | curses.A_BOLD)

        label = 'Status: '
        sx = W - len(badge) - len(label) - 3
        self.scr.attron(curses.color_pair(CP_TITLE))
        self.scr.addstr(0, sx, label)
        self.scr.attroff(curses.color_pair(CP_TITLE))
        self.scr.attron(curses.color_pair(badge_pair) | curses.A_BOLD | curses.A_REVERSE)
        self.scr.addstr(0, sx + len(label), f' {badge} ')
        self.scr.attroff(curses.color_pair(badge_pair) | curses.A_BOLD | curses.A_REVERSE)

    def _draw_headers(self, W):
        nw, tw, aw, fw, cw = self._cols(W)
        self.scr.attron(curses.color_pair(CP_HEADER) | curses.A_BOLD)
        self.scr.addstr(2, 0, ' ' * (W - 1))
        x = 1
        for text, width in [('#', nw), ('To / Service', tw), ('Action', aw), ('From', fw), ('Comment', cw)]:
            self.scr.addstr(2, x, text.ljust(width))
            x += width + 1
        self.scr.attroff(curses.color_pair(CP_HEADER) | curses.A_BOLD)

    def _draw_rules(self, H, W):
        nw, tw, aw, fw, cw = self._cols(W)
        list_h = H - 6

        if self.cursor < self.scroll:
            self.scroll = self.cursor
        if self.cursor >= self.scroll + list_h:
            self.scroll = self.cursor - list_h + 1

        if not self.rules:
            self.scr.addstr(4, 3, '(no rules defined)', curses.color_pair(CP_INFO) | curses.A_ITALIC)
            return

        first_disabled = next((i for i, r in enumerate(self.rules) if r['disabled']), None)

        for i in range(list_h):
            ri = self.scroll + i
            if ri >= len(self.rules):
                break
            rule = self.rules[ri]
            y    = 3 + i
            sel  = ri == self.cursor
            dis  = rule['disabled']

            if ri == first_disabled and ri > 0:
                self.scr.attron(curses.color_pair(CP_DIM) | curses.A_DIM)
                self.scr.addstr(y, 1, '─' * (W - 2))
                self.scr.attroff(curses.color_pair(CP_DIM) | curses.A_DIM)
                i += 1; y = 3 + i
                if y >= H - 3:
                    break

            num_s     = ('--' if dis else str(rule['num'])).rjust(nw)
            to_s      = rule['to'][:tw].ljust(tw)
            action_s  = ('[OFF] ' + rule['action'])[:aw].ljust(aw) if dis else rule['action'][:aw].ljust(aw)
            from_s    = rule['from'][:fw].ljust(fw)
            comment_s = rule['comment'][:cw]

            if sel:
                self.scr.attron(curses.color_pair(CP_SEL) | curses.A_BOLD)
                self.scr.addstr(y, 0, ' ' * (W - 1))
            if dis and not sel:
                self.scr.attron(curses.color_pair(CP_DIM) | curses.A_DIM)

            x = 1
            self.scr.addstr(y, x, num_s);  x += nw + 1
            self.scr.addstr(y, x, to_s);   x += tw + 1

            if not sel and not dis:
                act = rule['action']
                if   'ALLOW' in act: attr = curses.color_pair(CP_ALLOW) | curses.A_BOLD
                elif 'DENY'  in act or 'REJECT' in act: attr = curses.color_pair(CP_DENY) | curses.A_BOLD
                elif 'LIMIT' in act: attr = curses.color_pair(CP_LIMIT) | curses.A_BOLD
                else:                attr = 0
                self.scr.attron(attr)

            self.scr.addstr(y, x, action_s); x += aw + 1

            if not sel and not dis:
                self.scr.attroff(attr)

            self.scr.addstr(y, x, from_s); x += fw + 1

            # comment in dim/italic when not selected
            if comment_s:
                if sel:
                    self.scr.addstr(y, x, comment_s)
                else:
                    self.scr.attron(curses.color_pair(CP_INFO) if not dis else curses.color_pair(CP_DIM) | curses.A_DIM)
                    self.scr.addstr(y, x, comment_s)
                    self.scr.attroff(curses.color_pair(CP_INFO) if not dis else curses.color_pair(CP_DIM) | curses.A_DIM)

            if dis and not sel:
                self.scr.attroff(curses.color_pair(CP_DIM) | curses.A_DIM)
            if sel:
                self.scr.attroff(curses.color_pair(CP_SEL) | curses.A_BOLD)

        total = len(self.rules)
        if total > list_h:
            pct = int(self.scroll / max(1, total - list_h) * 100)
            self.scr.addstr(3, W - 5, f'{pct:3d}%', curses.color_pair(CP_INFO))

    def _draw_flash(self, H, W):
        if self.flash:
            pair = CP_OK if self.flash_good else CP_ERR
            self.scr.attron(curses.color_pair(pair) | curses.A_BOLD)
            self.scr.addstr(H - 3, 2, self.flash[:W - 4])
            self.scr.attroff(curses.color_pair(pair) | curses.A_BOLD)

    def _draw_footer(self, H, W):
        self.scr.attron(curses.color_pair(CP_FOOT))
        self.scr.addstr(H - 1, 0, ' ' * (W - 1))
        self.scr.attroff(curses.color_pair(CP_FOOT))
        x = 1
        for key, label in self.SHORTCUTS:
            chunk = f'[{key}] {label}  '
            if x + len(chunk) >= W:
                break
            self.scr.attron(curses.color_pair(CP_KEY) | curses.A_BOLD)
            self.scr.addstr(H - 1, x, f'[{key}]')
            self.scr.attroff(curses.color_pair(CP_KEY) | curses.A_BOLD)
            self.scr.attron(curses.color_pair(CP_FOOT))
            self.scr.addstr(H - 1, x + len(key) + 2, f' {label}  ')
            self.scr.attroff(curses.color_pair(CP_FOOT))
            x += len(chunk)

    # ── dialog primitives ──────────────────────────────────────────────────────

    def _make_dialog(self, title, lines, extra_h=0):
        H, W = self.scr.getmaxyx()
        dw = min(W - 4, max(56, max(len(l) for l in lines) + 8))
        dh = len(lines) + 4 + extra_h
        y0 = max(1, H // 2 - dh // 2)
        x0 = max(1, W // 2 - dw // 2)
        win = curses.newwin(dh, dw, y0, x0)
        win.keypad(True)
        win.attron(curses.color_pair(CP_BORDER))
        win.box()
        win.attroff(curses.color_pair(CP_BORDER))
        win.attron(curses.A_BOLD)
        win.addstr(0, 2, f' {title} ')
        win.attroff(curses.A_BOLD)
        for i, line in enumerate(lines):
            win.addstr(i + 2, 3, line[:dw - 6])
        return win, dw, dh

    def _read_text(self, win, y, x, maxlen, prefill=''):
        """Single-line text input with optional prefill; returns text or None on ESC."""
        buf = list(prefill[:maxlen])
        win.addstr(y, x, '▸ ')
        ix = x + 2
        win.addstr(y, ix, ' ' * maxlen)
        if buf:
            win.addstr(y, ix, ''.join(buf))
        curses.curs_set(1)
        win.move(y, ix + len(buf))
        win.refresh()
        while True:
            ch = win.getch()
            if ch in (curses.KEY_ENTER, ord('\n'), ord('\r')):
                break
            elif ch == 27:
                curses.curs_set(0)
                return None
            elif ch in (curses.KEY_BACKSPACE, ord('\b'), 127):
                if buf:
                    buf.pop()
                    cx = ix + len(buf)
                    win.addstr(y, cx, ' ')
                    win.move(y, cx)
            elif 32 <= ch <= 126 and len(buf) < maxlen - 1:
                buf.append(chr(ch))
                win.addch(y, ix + len(buf) - 1, chr(ch))
                win.move(y, ix + len(buf))
            win.refresh()
        curses.curs_set(0)
        return ''.join(buf).strip()

    def _arrow_menu(self, win, y, x, options, sel=0):
        """Arrow-key selection menu; returns index or -1 on ESC."""
        while True:
            for i, opt in enumerate(options):
                if i == sel:
                    win.attron(curses.color_pair(CP_SEL) | curses.A_BOLD)
                    win.addstr(y + i, x, f'  {opt:<12}')
                    win.attroff(curses.color_pair(CP_SEL) | curses.A_BOLD)
                else:
                    win.addstr(y + i, x, f'  {opt:<12}')
            win.refresh()
            ch = win.getch()
            if   ch == curses.KEY_UP   and sel > 0:                sel -= 1
            elif ch == curses.KEY_DOWN and sel < len(options) - 1: sel += 1
            elif ch in (curses.KEY_ENTER, ord('\n'), ord('\r')):    return sel
            elif ch == 27:                                           return -1

    # ── action handlers ────────────────────────────────────────────────────────

    def _confirm(self, title, question):
        lines = [question, '', 'Press  Y  to confirm   N  to cancel']
        win, *_ = self._make_dialog(title, lines)
        win.refresh()
        while True:
            ch = win.getch()
            if ch in (ord('y'), ord('Y')):
                del win; return True
            if ch in (ord('n'), ord('N'), 27):
                del win; return False

    def toggle_rule(self):
        if not self.rules:
            return
        rule = self.rules[self.cursor]

        if rule['disabled']:
            # ── re-enable ──────────────────────────────────────────────────
            cmd = _rule_to_add_cmd(rule)
            rc, out, err = _run(*cmd)
            combined = (out + err).lower()
            success = rc == 0 or 'already exists' in combined

            if success:
                _, fresh = fetch_rules()
                active = {
                    (r['to'], r['action'], r['from'])
                    for r in fresh if not r['disabled']
                }
                new_disabled = [
                    d for d in _load_disabled()
                    if (d['to'], d['action'], d['from']) not in active
                ]
                _save_disabled(new_disabled)
                self.flash      = f'Rule enabled: ufw {" ".join(cmd[1:])}'
                self.flash_good = True
            else:
                self.flash      = (err.strip() or out.strip())[:120]
                self.flash_good = False
        else:
            # ── disable ────────────────────────────────────────────────────
            q = f'Disable rule {rule["num"]}: {rule["to"]}  {rule["action"]}  {rule["from"]}?'
            if not self._confirm('Disable Rule', q):
                return
            rc, out, err = _run('ufw', '--force', 'delete', str(rule['num']))
            if rc == 0:
                disabled = _load_disabled()
                disabled.append({
                    'to'     : rule['to'],
                    'action' : rule['action'],
                    'from'   : rule['from'],
                    'comment': rule.get('comment', ''),
                })
                _save_disabled(disabled)
                self.flash      = f'Rule {rule["num"]} disabled — Space to re-enable.'
                self.flash_good = True
            else:
                self.flash      = (err.strip() or out.strip())[:120]
                self.flash_good = False

        self._reload()

    def add_rule_dialog(self):
        actions = ['allow', 'deny', 'reject', 'limit']
        protos  = ['any', 'tcp', 'udp']
        _, W    = self.scr.getmaxyx()
        dw      = min(W - 4, 66)

        lines = [
            'Select action with ↑↓  then press Enter',
            '', '', '', '', '',
            'Enter port/service:',
            '  e.g.  22   443   8080/tcp   8080:8090',
            '',
            'Protocol (ignored if already in port):',
            '', '', '', '',
            'Source IP / subnet (blank = Anywhere):',
            '', '',
            'Comment (optional):',
            '', '',
            'Press Enter to confirm   ESC to cancel',
        ]
        win, dw, _dh = self._make_dialog('Add Firewall Rule', lines)

        act_i = self._arrow_menu(win, 4, 4, actions, 0)
        if act_i < 0:
            return

        port = self._read_text(win, 9, 4, dw - 8)
        if not port:
            self.flash = 'Cancelled — no port entered.'; self.flash_good = False; return

        win.addstr(11, 4, '  any         ')
        proto_i = self._arrow_menu(win, 11, 4, protos, 0)
        if proto_i < 0:
            return
        proto = protos[proto_i]

        src     = self._read_text(win, 16, 4, dw - 8) or ''
        comment = self._read_text(win, 19, 4, dw - 8) or ''

        del win
        self.scr.touchwin()
        self.scr.refresh()

        port_spec = port if ('/' in port or proto == 'any') else f'{port}/{proto}'
        cmd = (['ufw', actions[act_i], 'from', src, 'to', 'any', 'port', port_spec]
               if src else
               ['ufw', actions[act_i], port_spec])
        if comment:
            cmd += ['comment', comment]

        rc, out, err = _run(*cmd)
        if rc == 0:
            self.flash      = f'Added: ufw {" ".join(cmd[1:])}'
            self.flash_good = True
        else:
            self.flash      = (err.strip() or out.strip())[:120]
            self.flash_good = False
        self._reload()

    def edit_comment(self):
        """C — set or update the comment on the selected rule."""
        if not self.rules:
            return
        rule = self.rules[self.cursor]

        lines = [
            f'{rule["to"]}  {rule["action"]}  {rule["from"]}',
            '',
            'New comment (blank to clear):',
            '',
        ]
        win, dw, _ = self._make_dialog('Edit Comment', lines)
        new_comment = self._read_text(win, 5, 3, dw - 6, prefill=rule.get('comment', ''))
        del win
        self.scr.touchwin()
        self.scr.refresh()

        if new_comment is None:   # ESC — cancelled
            return

        if rule['disabled']:
            # Disabled rule: just update the JSON, no UFW interaction needed
            disabled = _load_disabled()
            disabled[rule['_di']]['comment'] = new_comment
            _save_disabled(disabled)
            self.flash      = 'Comment updated.'
            self.flash_good = True
        else:
            # Active rule: delete then re-add with updated comment
            rc, out, err = _run('ufw', '--force', 'delete', str(rule['num']))
            if rc != 0:
                self.flash      = (err.strip() or out.strip())[:120]
                self.flash_good = False
                self._reload()
                return

            updated = dict(rule, comment=new_comment)
            cmd = _rule_to_add_cmd(updated)
            rc, out, err = _run(*cmd)
            if rc == 0:
                self.flash      = 'Comment updated.'
                self.flash_good = True
            else:
                self.flash      = (err.strip() or out.strip())[:120]
                self.flash_good = False

        self._reload()

    def delete_selected(self):
        if not self.rules:
            self.flash = 'No rules to delete.'; self.flash_good = False; return
        rule = self.rules[self.cursor]

        if rule['disabled']:
            q = f'Permanently remove disabled rule: {rule["to"]}  {rule["action"]}  {rule["from"]}'
            if not self._confirm('Remove Disabled Rule', q):
                return
            disabled = _load_disabled()
            disabled.pop(rule['_di'])
            _save_disabled(disabled)
            self.flash      = 'Disabled rule removed.'
            self.flash_good = True
        else:
            q = f'Delete rule {rule["num"]}:  {rule["to"]}  {rule["action"]}  from {rule["from"]}'
            if not self._confirm('Delete Rule', q):
                return
            rc, out, err = _run('ufw', '--force', 'delete', str(rule['num']))
            if rc == 0:
                self.flash      = f'Deleted rule {rule["num"]}.'
                self.flash_good = True
            else:
                self.flash      = (err.strip() or out.strip())[:120]
                self.flash_good = False

        self._reload()

    def toggle_ufw(self, enable: bool):
        word = 'enable' if enable else 'disable'
        if not self._confirm(f'{word.capitalize()} UFW', f'Really {word} UFW firewall?'):
            return
        rc, out, err = _run('ufw', '--force', word)
        if rc == 0:
            self.flash      = f'UFW {word}d.'
            self.flash_good = True
        else:
            self.flash      = (err.strip() or out.strip())[:120]
            self.flash_good = False
        self._reload()

    # ── main loop ──────────────────────────────────────────────────────────────

    def run(self):
        while True:
            self.draw()
            key = self.scr.getch()

            if key in (ord('q'), ord('Q')):
                break
            elif key == curses.KEY_UP:
                if self.cursor > 0: self.cursor -= 1
                self.flash = ''
            elif key == curses.KEY_DOWN:
                if self.cursor < len(self.rules) - 1: self.cursor += 1
                self.flash = ''
            elif key == ord(' '):
                self.flash = ''; self.toggle_rule()
            elif key in (ord('a'), ord('A')):
                self.flash = ''; self.add_rule_dialog()
            elif key in (ord('c'), ord('C')):
                self.flash = ''; self.edit_comment()
            elif key in (ord('d'), ord('D'), curses.KEY_DC):
                self.flash = ''; self.delete_selected()
            elif key in (ord('e'), ord('E')):
                self.flash = ''; self.toggle_ufw(True)
            elif key in (ord('x'), ord('X')):
                self.flash = ''; self.toggle_ufw(False)
            elif key in (ord('r'), ord('R')):
                self._reload()
                self.flash = 'Rules refreshed.'; self.flash_good = True
            elif key == curses.KEY_RESIZE:
                self.scr.clear()


# ── entry point ────────────────────────────────────────────────────────────────

def main(stdscr):
    UFWManager(stdscr).run()


if __name__ == '__main__':
    if os.geteuid() != 0:
        print('Root required — re-launching with sudo...', flush=True)
        os.execvp('sudo', ['sudo', sys.executable] + sys.argv)
    curses.wrapper(main)
