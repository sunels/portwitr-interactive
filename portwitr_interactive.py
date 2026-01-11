#!/usr/bin/env python3
import sys
import curses
import subprocess
import re
import textwrap
import os
import time
import argparse
from shutil import which

KEY_SEP_UP = ord('+')
KEY_SEP_DOWN = ord('-')
KEY_TAB = 9

def check_python_version():
    if sys.version_info < (3, 6):
        print("Python 3.6 or newer is required.")
        sys.exit(1)

def check_witr_exists():
    if which("witr") is None:
        print("Error: 'witr' command not found. Please install 'witr' and ensure it is in your PATH.")
        sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Interactive port/process viewer for Linux (requires 'witr')."
    )
    parser.add_argument('--version', action='version', version='portwitr-interactive 1.0')
    return parser.parse_args()

def strip_ansi(line):
    return re.sub(r'\x1b\[[0-9;]*m', '', line)

def parse_ss():
    result = subprocess.run(
        ["ss", "-lntuHp"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )
    rows = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        port = local.split(":")[-1]
        pid = "-"
        prog = "-"
        m = re.search(r'pid=(\d+)', line)
        if m:
            pid = m.group(1)
        m = re.search(r'\("([^"]+)"', line)
        if m:
            prog = m.group(1)
        rows.append((port, proto, f"{pid}/{prog}", prog, pid))
    rows.sort(key=lambda r: (0 if r[1].lower() == "tcp" else 1, r[0]))
    return rows

def get_witr_output(port):
    if not port or not str(port).isdigit():
        return ["Invalid port."]
    try:
        result = subprocess.run(
            ["sudo", "witr", "--port", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3
        )
        lines = result.stdout.splitlines()
        lines = [strip_ansi(line) for line in lines if line.strip()]
        if result.returncode != 0 or not lines:
            err = result.stderr.strip()
            if err:
                lines.append(f"Failed to get witr output: {err}")
            else:
                lines.append("Failed to get witr output.")
        return lines
    except Exception as e:
        return [f"Failed to get witr output: {e}"]

def get_open_files(pid):
    files = []
    if not pid or not str(pid).isdigit():
        return files
    fd_dir = f"/proc/{pid}/fd"
    if not os.path.isdir(fd_dir):
        return files
    try:
        for fd in sorted(os.listdir(fd_dir), key=lambda x: int(x)):
            try:
                path = os.readlink(os.path.join(fd_dir, fd))
                files.append((fd, path))
            except Exception:
                continue
    except Exception:
        pass
    return files

def draw_table(win, rows, selected, offset):
    win.erase()
    h, w = win.getmaxyx()
    headers = ["PORT", "PROTOCOL", "PID/PROGRAM", "TARGET"]
    widths = [8, 12, 24, w - 46]
    x = 1
    for i, hdr in enumerate(headers):
        win.addstr(1, x, hdr.ljust(widths[i]), curses.A_BOLD)
        x += widths[i]
    win.hline(2, 1, curses.ACS_HLINE, w - 2)
    max_rows = h - 4
    for i in range(max_rows):
        idx = offset + i
        if idx >= len(rows):
            continue
        attr = curses.A_REVERSE if idx == selected else curses.A_NORMAL
        x = 1
        for col, width in zip(rows[idx][:4], widths):
            val = str(col)
            if len(val) > width:
                val = val[:width-1] + "…"
            win.addstr(i + 3, x, val.ljust(width), attr)
            x += width
    win.box()
    win.noutrefresh()

def draw_open_files(win, pid, prog, files, scroll=0):
    win.erase()
    h, w = win.getmaxyx()
    header = f"PID/PROGRAM: {pid}/{prog}   Number Of Open Files: {len(files)}"
    win.addstr(1, 2, header, curses.A_BOLD)
    win.hline(2, 1, curses.ACS_HLINE, w - 2)
    max_rows = h - 4
    for i in range(max_rows):
        idx = scroll + i
        if idx >= len(files):
            continue
        fd, path = files[idx]
        line = f"{idx+1:3d}. [{fd}] {path}"
        win.addstr(i + 3, 2, line)
    win.box()
    win.noutrefresh()

def draw_detail(win, wrapped_lines, scroll=0):
    win.erase()
    h, w = win.getmaxyx()
    total_lines = len(wrapped_lines)
    visible_lines = wrapped_lines[scroll:scroll + h - 2]
    for i, line in enumerate(visible_lines):
        if i + 1 < h - 1:
            win.addstr(i + 1, 2, line)
    win.box()
    win.noutrefresh()
    return total_lines

def draw_help_bar(stdscr, show_detail):
    h, w = stdscr.getmaxyx()
    if show_detail:
        help_text = " [↑/↓] Scroll   [Tab] Netstat Table   [q] Quit "
    else:
        help_text = " [↑/↓] Select   [+/-] Resize   [r] Refresh   [Tab] Switch View   [→/←] Open Files Scroll   [s] Stop Proc/Service   [q] Quit "
    bar_win = curses.newwin(3, w, h - 3, 0)
    bar_win.erase()
    bar_win.box()
    x = max(1, (w - len(help_text)) // 2)
    try:
        bar_win.addstr(1, x, help_text, curses.A_BOLD)
    except Exception:
        bar_win.addstr(1, x, help_text)
    bar_win.noutrefresh()

def confirm_dialog(stdscr, message):
    h, w = stdscr.getmaxyx()
    win_h, win_w = 5, min(60, w - 4)
    win = curses.newwin(win_h, win_w, (h - win_h) // 2, (w - win_w) // 2)
    win.box()
    win.addstr(1, 2, message)
    win.addstr(3, 2, "[y] Yes   [n] No")
    win.refresh()
    while True:
        k = win.getch()
        if k in (ord('y'), ord('Y')):
            return True
        elif k in (ord('n'), ord('N'), 27):
            return False

def stop_process_or_service(pid, prog, stdscr):
    service_name = None
    try:
        result = subprocess.run(
            ["systemctl", "status", prog],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if "Loaded: loaded" in result.stdout:
            service_name = prog
    except Exception:
        pass

    msg = ""
    if service_name:
        try:
            subprocess.run(["sudo", "systemctl", "stop", service_name], check=True)
            msg = f"Service {service_name} stopped."
        except Exception as e:
            msg = f"Failed to stop service: {e}"
    elif pid and pid.isdigit() and int(pid) > 1:
        try:
            subprocess.run(["sudo", "kill", "-15", pid])
            time.sleep(1)
            if os.path.exists(f"/proc/{pid}"):
                subprocess.run(["sudo", "kill", "-9", pid])
            msg = f"PID {pid} stopped."
        except Exception as e:
            msg = f"Failed to stop process: {e}"
    else:
        msg = "Invalid PID/service."

    h, w = stdscr.getmaxyx()
    win_h, win_w = 3, min(60, w - 4)
    win = curses.newwin(win_h, win_w, (h - win_h) // 2, (w - win_w) // 2)
    win.box()
    win.addstr(1, 2, msg)
    win.refresh()
    stdscr.timeout(1000)
    stdscr.getch()
    stdscr.timeout(-1)

def main(stdscr):
    curses.curs_set(0)
    stdscr.keypad(True)

    rows = parse_ss()
    selected = 0 if rows else -1
    offset = 0
    table_h = max(6, (curses.LINES - 3) // 2)
    show_detail = False
    detail_scroll = 0
    open_files_scroll = 0

    cached_port = None
    cached_wrapped_lines = []
    cached_total_lines = 0

    while True:
        h, w = stdscr.getmaxyx()
        max_h = h - 3 - 2
        min_h = 6

        max_rows = table_h - 4
        visible = max_rows

        if not show_detail and rows:
            table_panel = curses.newwin(table_h, w // 2, 0, 0)
            draw_table(table_panel, rows, selected, offset)
            open_files_panel = curses.newwin(table_h, w - w // 2, 0, w // 2)
            pid = rows[selected][4] if selected >= 0 else "-"
            prog = rows[selected][3] if selected >= 0 else "-"
            files = get_open_files(pid)
            draw_open_files(open_files_panel, pid, prog, files, scroll=open_files_scroll)
            detail = curses.newwin(h - table_h - 3, w, table_h, 0)
            if selected >= 0 and rows:
                port = rows[selected][0]
                if cached_port != port:
                    cached_port = port
                    lines = get_witr_output(port)
                    wrapped = []
                    for line in lines:
                        wrapped += textwrap.wrap(line, width=w-4) or [""]
                    cached_wrapped_lines = wrapped
                    cached_total_lines = len(wrapped)
                draw_detail(detail, cached_wrapped_lines, scroll=detail_scroll)
            else:
                draw_detail(detail, [], scroll=0)
            draw_help_bar(stdscr, show_detail)
            total_detail_lines = cached_total_lines
        elif show_detail:
            detail = curses.newwin(h - 3, w, 0, 0)
            draw_detail(detail, cached_wrapped_lines, scroll=detail_scroll)
            draw_help_bar(stdscr, show_detail)
            total_detail_lines = cached_total_lines
        curses.doupdate()

        k = stdscr.getch()

        if k == ord('q'):
            break
        elif show_detail:
            if k == curses.KEY_UP and detail_scroll > 0:
                detail_scroll -= 1
            elif k == curses.KEY_DOWN and total_detail_lines > 0 and detail_scroll < total_detail_lines - (h - 3 - 2):
                detail_scroll += 1
            elif k == KEY_TAB:
                show_detail = False
                detail_scroll = 0
        else:
            if k == curses.KEY_UP and selected > 0:
                selected -= 1
            elif k == curses.KEY_DOWN and selected < len(rows) - 1:
                selected += 1
            elif k == KEY_SEP_UP and table_h < max_h:
                table_h += 1
            elif k == KEY_SEP_DOWN and table_h > min_h:
                table_h -= 1
            elif k == ord('r'):
                rows = parse_ss()
                if rows:
                    selected = 0
                    offset = 0
            elif k == KEY_TAB:
                show_detail = True
                detail_scroll = 0
            elif k == curses.KEY_RIGHT and open_files_scroll < max(0, len(get_open_files(rows[selected][4])) - (table_h - 4)):
                open_files_scroll += 1
            elif k == curses.KEY_LEFT and open_files_scroll > 0:
                open_files_scroll -= 1
            elif k == ord('s') and selected >= 0 and rows:
                port, proto, pidprog, prog, pid = rows[selected]
                confirm = confirm_dialog(stdscr, f"{pidprog} ({port}) stop?")
                if confirm:
                    stop_process_or_service(pid, prog, stdscr)
                    rows = parse_ss()
                    if selected >= len(rows):
                        selected = len(rows) - 1
                    if selected < 0 and rows:
                        selected = 0
            if selected >= len(rows):
                selected = len(rows) - 1
            if selected < 0 and rows:
                selected = 0
            offset = min(max(selected - (visible // 2), 0), max(0, len(rows) - visible))

if __name__ == "__main__":
    check_python_version()
    check_witr_exists()
    parse_args()
    curses.wrapper(main)