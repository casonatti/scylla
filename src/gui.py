import gi
import os
import subprocess
import threading
import time
from datetime import datetime

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib

import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_gtk3agg import FigureCanvasGTK3Agg as FigureCanvas

from Log import Log
from scylla import Scylla


#Handles all file I/O operations for protected inodes.
class ProtectedFilesManager:
  def __init__(self, config_path="../config/protected_inodes"):
    self.config_path = config_path

  def load_files(self):
    prot_files = []
    if os.path.exists(self.config_path):
      with open(self.config_path, "r") as file:
        for line in file:
          temp = line.split()
          if len(temp) >= 2:
            prot_files.append([int(temp[0]), temp[1]])
    return prot_files

  def add_file(self, inode, filename):
    with open(self.config_path, "a") as file:
      file.write(f"{inode} {filename}\n")

  def sync_files(self, active_files_list):
    with open(self.config_path, "w") as file:
      for inode, filename in active_files_list:
        file.write(f"{inode} {filename}\n")


class ScyllaGUI(Gtk.Window):
  def __init__(self, clef_gpid, log_instance, textview_buffer):
    super().__init__(title="Scylla")

    # Context and State
    self.clef_gpid = clef_gpid
    self.log = log_instance
    self.textview_buffer = textview_buffer
    self.file_manager = ProtectedFilesManager()
    self.log_buffer_line_limit = 200

    # Main Window config
    self.set_border_width(5)
    self.set_default_size(1280, 720)
    self.connect("destroy", Gtk.main_quit)

    self._build_ui()
    self._load_initial_data()

    self.timeout_id = GLib.timeout_add(300, self.feed_log)
    self.show_all()

  def _build_ui(self):
    hpaned = Gtk.Paned()
    hpaned.set_position(320)

    # Build sub-sections
    sidebar = self._build_sidebar()
    main_area = self._build_main_area()

    hpaned.pack1(sidebar, False, False)
    hpaned.pack2(main_area, True, False)

    self.add(hpaned)

  def _build_sidebar(self):
    vpaned_status = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
    vpaned_status.set_position(80)

    vpaned_prot_files = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
    vpaned_prot_files.set_position(120)

    # Status section
    status_vbox = Gtk.Box(orientation="vertical")
    self.switch = Gtk.Switch()
    self.switch.connect("notify::active", self.on_switch_activated)
    self.switch.set_active(False)
    self.switch.set_halign(Gtk.Align.CENTER)
    self.switch.set_margin_bottom(10)

    status_label = Gtk.Label(label="Scylla Status")
    status_vbox.pack_start(status_label, True, True, 1)
    status_vbox.pack_start(self.switch, False, False, 1)
    vpaned_status.pack1(status_vbox, False, False)

    # PID Label
    pid_label = Gtk.Label(label=f"Clef PID:\n{self.clef_gpid}")
    vpaned_prot_files.pack1(pid_label, False, False)

    # Protected Files Section
    prot_files_vbox = Gtk.Box(orientation="vertical", spacing=10)
    prot_files_vbox.set_margin_top(5)

    self.prot_files_list = Gtk.ListStore(bool, int, str)
    self.prot_files_treeview = Gtk.TreeView(model=self.prot_files_list)

    for i, column_title in enumerate([None, "Inode", "File Name"]):
      if column_title is None:
        toggle_renderer = Gtk.CellRendererToggle()
        toggle_renderer.connect("toggled", self.on_button_toggled)
        tvcolumn = Gtk.TreeViewColumn(column_title, toggle_renderer, active=i)
      else:
        text_renderer = Gtk.CellRendererText()
        tvcolumn = Gtk.TreeViewColumn(column_title, text_renderer, text=i)
      self.prot_files_treeview.append_column(tvcolumn)

    scrollable_treelist = Gtk.ScrolledWindow()
    scrollable_treelist.set_vexpand(True)
    scrollable_treelist.add(self.prot_files_treeview)

    # Action Buttons
    grid_btn = Gtk.Grid(column_homogeneous=True)
    grid_btn.set_margin_right(5)
    self.add_file_btn = Gtk.Button(label="Add")
    self.remove_file_btn = Gtk.Button(label="Remove")
    self.add_file_btn.connect("clicked", self.add_files)
    self.remove_file_btn.connect("clicked", self.remove_files)

    grid_btn.add(self.add_file_btn)
    grid_btn.attach(self.remove_file_btn, 1, 0, 1, 1)

    prot_files_label = Gtk.Label(label="Protected Files")
    prot_files_vbox.pack_start(prot_files_label, False, False, 1)
    prot_files_vbox.pack_start(scrollable_treelist, True, True, 1)
    prot_files_vbox.pack_end(grid_btn, False, False, 1)

    vpaned_prot_files.pack2(prot_files_vbox, False, False)
    vpaned_status.pack2(vpaned_prot_files, True, True)

    return vpaned_status

  def _build_main_area(self):
    vpaned_info = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
    vpaned_info.set_position(650)

    notebook = Gtk.Notebook()

    # Log Page
    log_page = Gtk.ScrolledWindow()
    log_page.set_border_width(5)
    self.log_buffer = Gtk.TextBuffer()
    self.log_textview = Gtk.TextView(buffer=self.log_buffer)
    self.log_textview.set_editable(False)
    self.log_textview.set_cursor_visible(False)
    self.log_textview.set_wrap_mode(Gtk.WrapMode.WORD)
    log_page.add(self.log_textview)

    # Graph Page
    graph_page = Gtk.Box()
    canvas = self.plot_graph()
    graph_page.pack_start(canvas, True, True, 1)

    notebook.append_page(log_page, Gtk.Label(label="Log"))
    notebook.append_page(graph_page, Gtk.Label(label="Graphs"))

    vpaned_info.pack1(notebook, True, False)

    warnings_label = Gtk.Label(label="Warnings")
    vpaned_info.pack2(warnings_label, False, False)

    return vpaned_info

  def _load_initial_data(self):
    prot_files = self.file_manager.load_files()
    for item in prot_files:
      self.prot_files_list.append([False] + list(item))

    if len(self.prot_files_list) == 0:
      self.switch.set_sensitive(False)

  # Elements functions
  def on_switch_activated(self, switch, gparam):
    log_timestamp = datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M")

    if switch.get_active():
      self.add_file_btn.set_sensitive(False)
      self.remove_file_btn.set_sensitive(False)
      self.ebpf_thr = self.turn_on_scylla()
      state = f"[{log_timestamp}] [INFO] Scylla turned ON"
    else:
      self.add_file_btn.set_sensitive(True)
      self.remove_file_btn.set_sensitive(True)
      self.turn_off_scylla()
      state = f"[{log_timestamp}] [INFO] Scylla turned OFF"

    self.log.append(state)

  def on_button_toggled(self, cell_renderer, path):
    iter = self.prot_files_list.get_iter(path)
    if iter:
      self.prot_files_list[iter][0] = not self.prot_files_list[iter][0]

  def add_files(self, button):
    if self.switch.get_active():
      return

    dialog = Gtk.FileChooserDialog(
      title="Select a file to protect",
      parent=self,
      action=Gtk.FileChooserAction.OPEN,
    )
    dialog.add_buttons(
      Gtk.STOCK_CANCEL,
      Gtk.ResponseType.CANCEL,
      Gtk.STOCK_OPEN,
      Gtk.ResponseType.OK,
    )

    response = dialog.run()

    if response == Gtk.ResponseType.OK:
      filepath = dialog.get_filename()
      filename = filepath.split("/")[-1]
      inode = os.stat(filepath).st_ino

      repeated_inode = any(
        self.prot_files_list[row][1] == inode
        for row in range(len(self.prot_files_list))
      )

      if repeated_inode:
        print("Failed to add file. Repeated Inode.")
      else:
        self.file_manager.add_file(inode, filename)
        self.prot_files_list.append([False, inode, filename])

        log_timestamp = datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M")
        self.log.append(f"[{log_timestamp}] [INFO] Adding file [{filename}] to the list.")

    if len(self.prot_files_list) > 0:
      self.switch.set_sensitive(True)

    dialog.destroy()

  def remove_files(self, button):
    removed_any = False

    for path in reversed(range(len(self.prot_files_list))):
      iter = self.prot_files_list.get_iter(path)

      if self.prot_files_list[iter][0]:
        temp_name = self.prot_files_list[iter][2]
        self.prot_files_list.remove(iter)
        removed_any = True

        log_timestamp = datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M")
        self.log.append(f"[{log_timestamp}] [INFO] Removed file [{temp_name}] from the list.")

    if removed_any:
      # Re-sync file based on current TreeView status
      active_files = [(row[1], row[2]) for row in self.prot_files_list]
      self.file_manager.sync_files(active_files)

    if len(self.prot_files_list) == 0:
      self.switch.set_sensitive(False)

  def feed_log(self):
    while len(self.textview_buffer) > 0:
      iter_end = self.log_buffer.get_end_iter()
      self.log_buffer.insert(iter_end, self.textview_buffer.pop(0))

      line_count = self.log_buffer.get_line_count()

      if line_count >= self.log_buffer_line_limit:
        iter_start = self.log_buffer.get_start_iter()
        self.log_buffer.delete(
          iter_start,
          self.log_buffer.get_iter_at_line(
              line_count - self.log_buffer_line_limit
          ),
        )

      GLib.idle_add(self.scroll_to_end)
    return True

  def scroll_to_end(self):
    self.log_textview.scroll_to_mark(self.log_buffer.get_insert(), 0, False, 0, 0)
    return False

  def plot_graph(self):
    figure = Figure(figsize=(5, 4), dpi=100)
    ax = figure.add_subplot(111)
    ax.plot([1, 2, 3, 4], [10, 20, 25, 30], linestyle="-")
    return FigureCanvas(figure)

  def turn_on_scylla(self):
    self.ebpf_prog = Scylla(self.log)
    ebpf_thread = threading.Thread(
        target=self.ebpf_prog.run, name="Scylla_Thread", daemon=True
    )
    ebpf_thread.start()
    return ebpf_thread

  def turn_off_scylla(self):
    self.ebpf_prog.close()
    self.ebpf_thr.join()
    return True


def get_clef_gpid():
  try:
    clef_gpid_search = subprocess.run(
      ["ps", "-e", "-o", "pid,comm"],
      stdout=subprocess.PIPE,
      text=True,
      check=True,
    )
    lines = clef_gpid_search.stdout.strip().split("\n")

    # Safely extract PIDs
    clef_gpids = [
      int(line.split()[0]) for line in lines[1:] if line.split()[-1] == "clef"
    ]

    if not clef_gpids:
      print("Warning: Process 'clef' not found.")
      return 0

    with open("../config/permitted_pids", "w") as file:
      file.write(str(clef_gpids[0]))

    return clef_gpids[0]

  except (subprocess.CalledProcessError, FileNotFoundError):
    print("Error retrieving PIDs for 'clef'.")
    return 0


def main():
  textview_buffer = []
  log_instance = Log()

  clef_pid = get_clef_gpid()

  log_instance.config_initialization(textview_buffer)

  threads = []

  reading_thread = threading.Thread(
    target=log_instance.read_log_file,
    args=(textview_buffer,),
    name="Reading_Thread",
    daemon=True,
  )
  threads.append(reading_thread)

  writing_thread = threading.Thread(
    target=log_instance.write_log_file, name="Writing_Thread", daemon=True
  )
  threads.append(writing_thread)

  for thread in threads:
    thread.start()

  time.sleep(1)

  ScyllaGUI(clef_pid, log_instance, textview_buffer)
  Gtk.main()

  return 0


if __name__ == "__main__":
  main()