import tkinter as tk
import datetime
from tkinter import ttk, filedialog, messagebox
import os
import json

# Global mapping arrays for field names
arrFlowMap = [
    "UnixEpoch", "vnet", "nsg", "rule",
    "sourceIP", "destIP", "sourcePort",
    "destPort", "proto", "trafficFlow", 
    "flowState", "encryption", 
    "packetsSrcToDest", "bytesSrcToDest", 
    "packetsDstToSrc", "bytesDestToSrc"
]

# Fields used for mapping flow tuples
tuple_fields = [
    "Timestamp", 
    "sourceIP", 
    "destIP", 
    "sourcePort",
    "destPort", 
    "proto", 
    "trafficFlow", 
    "flowState",
    "encryption", 
    "packetsSrcToDest", 
    "bytesSrcToDest", 
    "packetsDstToSrc", 
    "bytesDestToSrc"
]

# Mapping dictionaries for protocol, traffic flow, encryption, and flow state
proto_map = {
    "6": "TCP",
    "17": "UDP"
}

traffic_flow_map = {
    "I": "Inbound",
    "O": "Outbound"
}

encryption_map = {
    "NX": "Not Encrypted",
    "E": "Encrypted"
}

flow_state_map = {
    "B": "Begin",
    "C": "Continuing",
    "E": "End",
    "D": "Deny"
}

# Column names for the final table
COLUMNS = [
    "Timestamp", "vnet", "nsg", "rule",
    "sourceIP", "destIP", "sourcePort",
    "destPort", "proto", "trafficFlow",
    "flowState", "encryption",
    "packetsSrcToDest", "bytesSrcToDest",
    "packetsDstToSrc", "bytesDestToSrc"
]

# Extract vnet name from targetResourceID
def extract_vnet(record):
    target_id = record.get("targetResourceID", "")
    if "/virtualNetworks/" in target_id:
        return target_id.split("/virtualNetworks/")[1].split("/")[0]
    return ""

# Extract NSG name from aclID
def extract_nsg(acl_id):
    if acl_id == "00000000-0000-0000-0000-000000000000":
        return "MSPlatformNSG"
    if "/networkSecurityGroups/" in acl_id:
        return acl_id.split("/networkSecurityGroups/")[1].split("/")[0]
    return ""

# Main application class
class JSONViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NSG Flow Log JSON Viewer")
        self.loaded_files = {}  # Maps full path to parsed data (list of records)

        # Set modern theme
        style = ttk.Style()
        style.theme_use('clam')  # 'clam' is a cleaner default theme

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill='both', expand=True)

        # -------------------------------------------------
        # Title 
        # -------------------------------------------------
        title_label = ttk.Label(main_frame,
                                text="NSG Flow Log JSON Viewer",
                                font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=(0, 10))

        # -----------------------------------------------------------------
        # OUTER frame that will contain the file list + search controls
        # -----------------------------------------------------------------
        search_outer = ttk.Frame(main_frame, relief='groove', borderwidth=2)
        search_outer.pack(fill='both', expand=True, padx=5, pady=5)

        # -----  “Files in current folder/subfolders” label -----
        files_label = ttk.Label(search_outer,
                               text="Files in current folder/subfolders",
                               font=('Helvetica', 10, 'bold'))
        files_label.pack(pady=(8, 2), anchor='w')   # small top margin

        # ----- Listbox + vertical scrollbar -----
        file_frame = ttk.Frame(search_outer)
        file_frame.pack(fill='both', expand=True, padx=5)

        self.file_listbox = tk.Listbox(file_frame, height=10, width=60)
        file_scrollbar = ttk.Scrollbar(file_frame,
                                      orient='vertical',
                                      command=self.file_listbox.yview)
        self.file_listbox.config(yscrollcommand=file_scrollbar.set)

        # double‑click → open selected file
        self.file_listbox.bind('<Double-Button-1>', self.on_file_double_click)

        self.file_listbox.pack(side='left', fill='both', expand=True)
        file_scrollbar.pack(side='right', fill='y')

        # ----- Search / Clear‑filter controls  -----
        search_section = ttk.Frame(search_outer)
        search_section.pack(fill='x', padx=5, pady=(8, 8))

        # Source entry
        ttk.Label(search_section, text="Source:").grid(row=0, column=0,
                                                     sticky='e', padx=2, pady=2)
        self.src_entry = ttk.Entry(search_section, width=20)
        self.src_entry.grid(row=0, column=1, sticky='w', padx=2, pady=2)

        # Destination entry
        ttk.Label(search_section, text="Destination:").grid(row=0,
                                                          column=2,
                                                          sticky='e',
                                                          padx=2, pady=2)
        self.dst_entry = ttk.Entry(search_section, width=20)
        self.dst_entry.grid(row=0, column=3, sticky='w', padx=2, pady=2)

        # Destination Port entry
        ttk.Label(search_section,
                  text="Destination Port:").grid(row=0, column=4,
                                                sticky='e',
                                                padx=2, pady=2)
        self.port_entry = ttk.Entry(search_section, width=10)
        self.port_entry.grid(row=0, column=5, sticky='w', padx=2, pady=2)

        # Search button
        self.search_files_btn = ttk.Button(
            search_section,
            text="Search in Files",
            command=self.search_in_files)
        self.search_files_btn.grid(row=0, column=6, padx=8, pady=2)

        # Clear Filter button (clears entries + restores full list)
        self.clear_filter_btn = ttk.Button(
            search_section,
            text="Clear Filter",
            command=self._clear_main_filters_and_restore)
        self.clear_filter_btn.grid(row=0, column=7, padx=8, pady=2)

        # -----------------------------------------------------------------
        # Control buttons (Open Selected / Refresh / Open Other) – unchanged
        # -----------------------------------------------------------------
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(pady=5, fill='x')

        self.open_selected_btn = ttk.Button(
            control_frame,
            text="Open Selected",
            command=self.open_selected_files)
        self.open_selected_btn.pack(side='left', padx=5)

        self.refresh_btn = ttk.Button(control_frame,
                                      text="Refresh File List",
                                      command=self.refresh_files)
        self.refresh_btn.pack(side='left', padx=5)

        self.open_btn = ttk.Button(control_frame,
                                   text="Open Other",
                                   command=self.open_files)
        self.open_btn.pack(side='left', padx=5)

        # -----------------------------------------------------------------
        # Load files, auto‑size window, status bar – unchanged
        # -----------------------------------------------------------------
        self.load_existing_json_files()
        self.auto_size_window()

        self.status_bar = ttk.Label(self.root,
                                    text="Ready",
                                    relief=tk.SUNKEN,
                                    anchor='w')
        self.status_bar.pack(side='bottom', fill='x')




    def on_file_double_click(self, event):
        """Handle double-click on a file in the listbox"""
        selection = self.file_listbox.curselection()
        if selection:
            # Simulate clicking the "Open Selected" button
            self.open_selected_files()

    def load_existing_json_files(self):
        """Load all JSON files in the current directory and subdirectories"""
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Clear existing loaded files (this prevents duplicate entries)
        self.loaded_files.clear()

        for root, dirs, files in os.walk(current_dir):
            for filename in files:
                if filename.lower().endswith('.json'):
                    # Insert full path to show file location
                    full_path = os.path.join(root, filename)
                    relative_path = os.path.relpath(full_path, current_dir)
                    self.file_listbox.insert(tk.END, relative_path)

    def auto_size_window(self):
        """Auto-size window based on the longest filename in the list"""
        if not self.file_listbox.size():
            return

        # Get all filenames and find the longest one
        longest_filename = ""
        for i in range(self.file_listbox.size()):
            filename = self.file_listbox.get(i)
            if len(filename) > len(longest_filename):
                longest_filename = filename

        # Calculate window width based on longest filename with reasonable padding
        if longest_filename:
            # Reduced character-to-pixel ratio and less padding
            window_width = max(300, len(longest_filename) * 8 + 100)

            # Set the minimum size to ensure we can see the full content
            self.root.minsize(window_width, 300)



    def _autosize_tree_columns(self, tree, columns, data):
        """
        Resize each Treeview column so that it is wide enough for:
          • the column heading text
          • the longest cell value in that column (across all rows)
        The width is expressed in pixels; a small buffer is added to avoid clipping.
        """
        if not data or not columns:
            return

        # Helper: get pixel width of a string using the default treeview font
        def text_width(txt):
            # Approximate 1 character ≈ 7‑8 pixels for the default Tk font.
            # Using 7.5 gives a good balance on most platforms.
            return int(len(txt) * 7.5)

        buffer_px = 12          # extra space so text never touches the edge
        min_width  = 80         # we never go smaller than this
        max_width  = 500        # optional hard cap to keep the UI sane

        for col in columns:
            # Start with header width
            best = text_width(col)

            # Scan every row for the longest value in this column
            for row in data:
                cell = str(row.get(col, ""))
                w = text_width(cell)
                if w > best:
                    best = w

            # Apply buffer and limits
            final_w = max(min_width, min(best + buffer_px, max_width))
            tree.column(col, width=final_w, anchor="center")







    # Function to map flow tuple fields to their proper names and values
    def map_flow_tuple(self, fields):
        if len(fields) != 13:
            return {}

        row = {}
        for i, key in enumerate(tuple_fields):  # Use the new tuple_fields list
            value = fields[i]

            if key == "proto":
                row[key] = f"{value} ({proto_map.get(value, value)})" if value in proto_map else value
            elif key == "trafficFlow": 
                row[key] = f"{value} ({traffic_flow_map.get(value, value)})" if value in traffic_flow_map else value
            elif key == "flowState": 
                row[key] = f"{value} ({flow_state_map.get(value, value)})" if value in flow_state_map else value
            elif key == "encryption":
                row[key] = f"{value} ({encryption_map.get(value, value)})" if value in encryption_map else value
            elif key == "Timestamp":  # handle the new column name here
                try:
                    timestamp = int(value)
                    dt = datetime.datetime.fromtimestamp(timestamp / 1000)  # assume milliseconds
                    row[key] = dt.strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, OverflowError):
                    row[key] = value  # fallback to original string on error
            else:
                row[key] = value

        return row

    # Process flow records from loaded files
    def process_flow_records(self):
        processed_data = []
        for record in self.loaded_files.values():
            vnet = extract_vnet(record)
            for r in record:
                if 'flowRecords' in r and 'flows' in r['flowRecords']:
                    for flow in r['flowRecords']['flows']:
                        acl_id = flow.get('aclID', '')
                        nsg = extract_nsg(acl_id)
                        for group in flow['flowGroups']:
                            rule_name = group.get('rule', '')
                            for tuple_str in group.get('flowTuples', []):
                                fields = tuple_str.split(',')
                                row = self.map_flow_tuple(fields)
                                if row:
                                    # Add vnet, nsg, and rule
                                    row['vnet'] = vnet
                                    row['nsg'] = nsg
                                    row['rule'] = rule_name
                                    processed_data.append(row)
        return processed_data

    def open_files(self):
        file_paths = filedialog.askopenfilenames(
            title="Select JSON Files",
            filetypes=[("JSON Files", "*.json")]
        )

        if not file_paths:
            return

        for path in file_paths:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Extract "records" array
                records = data.get("records", [])
                self.loaded_files[path] = records
                filename = os.path.basename(path)
                self.file_listbox.insert(tk.END, filename)

            except Exception as e:
                messagebox.showerror("Error", f"Failed to process {path}: {str(e)}")

    def open_selected_files(self):
        """Open the file that is currently selected in the listbox.
        Also copies any filter values from the main window into the
        result‑window’s filter panel and applies them."""
        # ------------------------------------------------------------------
        # 1️⃣ Get the selected relative path from the listbox
        # ------------------------------------------------------------------
        sel = self.file_listbox.curselection()
        if not sel:
            return

        rel_path = self.file_listbox.get(sel[0])          # e.g. "subdir/file.json"
        current_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(current_dir, rel_path)

        try:
            # ------------------------------------------------------------------
            # 2️⃣ Load the JSON and turn it into rows for the table
            # ------------------------------------------------------------------
            with open(full_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            records = data.get("records", [])
            processed = self._process_records_for_display(records, full_path)

            # ------------------------------------------------------------------
            # 3️⃣ Show the data window
            # ------------------------------------------------------------------
            self.display_data_window(processed, os.path.basename(rel_path))

            # ------------------------------------------------------------------
            # 4️⃣ Inject the main‑window filter values into the new window
            # ------------------------------------------------------------------
            # The most recently created Toplevel is our data window
            data_win = self.root.winfo_children()[-1]

            # Walk down to the "Filter rows" labelframe and grab its three Entry widgets
            for child in data_win.winfo_children():
                if isinstance(child, ttk.Frame):          # table_frame
                    for sub in child.winfo_children():
                        if (isinstance(sub, ttk.LabelFrame) and
                                sub.cget('text') == "Filter rows"):
                            entries = [w for w in sub.winfo_children()
                                       if isinstance(w, ttk.Entry)]
                            if len(entries) >= 3:
                                # Fill Source / Destination / Port from the main window
                                entries[0].delete(0, tk.END)
                                entries[0].insert(0, self.src_entry.get())

                                entries[1].delete(0, tk.END)
                                entries[1].insert(0, self.dst_entry.get())

                                entries[2].delete(0, tk.END)
                                entries[2].insert(0, self.port_entry.get())

                                # Click the "Apply Filter" button programmatically
                                for w in sub.winfo_children():
                                    if (isinstance(w, ttk.Button) and
                                            w.cget('text') == "Apply Filter"):
                                        w.invoke()
                                        break
                            break
            # ------------------------------------------------------------------
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open {rel_path}:\n{e}")



    def _process_records_for_display(self, records, full_path):
        """Convert raw `records` into the list of rows shown in the data window."""
        processed_data = []
        for r in records:
            if 'flowRecords' not in r or 'flows' not in r['flowRecords']:
                continue
            vnet_name = extract_vnet(r)
            for flow in r['flowRecords']['flows']:
                nsg_name = extract_nsg(flow.get('aclID', ''))
                for group in flow.get('flowGroups', []):
                    rule_name = group.get('rule', '')
                    for tup in group.get('flowTuples', []):
                        fields = tup.split(',')
                        row = self.map_flow_tuple(fields)
                        if row:
                            row['vnet'] = vnet_name
                            row['nsg']  = nsg_name
                            row['rule'] = rule_name
                            processed_data.append(row)
        return processed_data


    def refresh_files(self):
        """Refresh the list of JSON files in the file listbox"""
        # Clear current listbox
        self.file_listbox.delete(0, tk.END)

        # Reload existing JSON files
        self.load_existing_json_files()

        # Update status bar
        self.status_bar.config(text="File list refreshed")

    def _restore_full_file_list(self):
        """Populate the file‑listbox with every JSON file under the current folder."""
        self.file_listbox.delete(0, tk.END)
        self.load_existing_json_files()          # re‑uses your existing loader
        self.status_bar.config(text="Ready")

    def _clear_main_filters_and_restore(self):
        """Reset the Search‑in‑Files entries and show every JSON file again."""
        # 1️Clear the entry fields in the main window
        self.src_entry.delete(0, tk.END)
        self.dst_entry.delete(0, tk.END)
        self.port_entry.delete(0, tk.END)

        # 2️Repopulate the listbox with all files (the existing helper does that)
        self._restore_full_file_list()



    def search_in_files(self):
        """
        Filter the main file‑listbox to show only JSON files that contain the
        supplied Source / Destination / Port values.
        Empty fields are ignored (AND logic on the non‑empty ones).
        """
        src  = self.src_entry.get().strip()
        dst  = self.dst_entry.get().strip()
        port = self.port_entry.get().strip()

        # If nothing entered, just show everything again
        if not any([src, dst, port]):
            self._restore_full_file_list()
            return

        current_dir = os.path.dirname(os.path.abspath(__file__))
        matching_paths = []

        for root, _, files in os.walk(current_dir):
            for fname in files:
                if not fname.lower().endswith('.json'):
                    continue
                full_path = os.path.join(root, fname)

                try:
                    with open(full_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except Exception:
                    continue

                # AND‑logic on the non‑empty criteria
                if src and src not in content:
                    continue
                if dst and dst not in content:
                    continue
                if port and port not in content:
                    continue

                rel_path = os.path.relpath(full_path, current_dir)
                matching_paths.append(rel_path)

        # -------------------------------------------------
        # Update the listbox to show only the matches
        # -------------------------------------------------
        self.file_listbox.delete(0, tk.END)          # clear current view
        for p in sorted(matching_paths):
            self.file_listbox.insert(tk.END, p)

        # Show a short status message with the criteria used
        crit_parts = []
        if src:  crit_parts.append(f'Source="{src}"')
        if dst:  crit_parts.append(f'Destination="{dst}"')
        if port: crit_parts.append(f'Port="{port}"')
        crit_text = ", ".join(crit_parts) if crit_parts else "no criteria"
        self.status_bar.config(
            text=f"{len(matching_paths)} file(s) matching: {crit_text}"
        )




    def display_data_window(self, data, filename):
        data_window = tk.Toplevel(self.root)
        data_window.title(f"JSON Data - {filename}")

        # Calculate optimal window size based on content
        if data:
            # Get approximate width needed for all columns
            max_width = 0
            for row in data:
                row_width = sum(len(str(row.get(col, ''))) for col in COLUMNS)
                if row_width > max_width:
                    max_width = row_width

            # Calculate window dimensions (add some padding)
            window_width = min(max(800, max_width * 8), 2000)  # Min 800px, max 2000px
            window_height = min(600, len(data) * 25 + 150)  # Dynamic height based on rows

            data_window.geometry(f"{window_width}x{window_height}")
        else:
            data_window.geometry("800x400")


        # Create local copies for this window instance to avoid cross-window interference
        original_data = data.copy()
        filtered_data = data.copy()

        # Store original data for filtering (local to this function)
        self.original_data = None  # Remove class-level reference
        self.filtered_data = None  # Remove class-level reference

        # Create frame to hold Treeview and scrollbars
        table_frame = ttk.Frame(data_window)
        table_frame.pack(fill="both", expand=True)

        # -------------------------------------------------
        #   Filter panel inside the data‑window
        # -------------------------------------------------
        filter_panel = ttk.LabelFrame(table_frame, text="Filter rows")
        filter_panel.grid(row=0, column=0, columnspan=2,
                         sticky='ew', padx=5, pady=(0, 5))

        # Source entry
        ttk.Label(filter_panel, text="Source:").grid(row=0, column=0,
                                                    sticky='e', padx=2, pady=2)
        src_var = tk.StringVar()
        src_entry = ttk.Entry(filter_panel, width=20, textvariable=src_var)
        src_entry.grid(row=0, column=1, sticky='w', padx=2, pady=2)

        # Destination entry
        ttk.Label(filter_panel, text="Destination:").grid(row=0, column=2,
                                                         sticky='e',
                                                         padx=2, pady=2)
        dst_var = tk.StringVar()
        dst_entry = ttk.Entry(filter_panel, width=20, textvariable=dst_var)
        dst_entry.grid(row=0, column=3, sticky='w', padx=2, pady=2)

        # Destination Port entry
        ttk.Label(filter_panel, text="Destination Port:").grid(row=0,
                                                             column=4,
                                                             sticky='e',
                                                             padx=2,
                                                             pady=2)
        port_var = tk.StringVar()
        port_entry = ttk.Entry(filter_panel, width=10, textvariable=port_var)
        port_entry.grid(row=0, column=5, sticky='w', padx=2, pady=2)

        # Filter button
        filter_btn = ttk.Button(filter_panel,
                                text="Apply Filter")
        filter_btn.grid(row=0, column=6, padx=8, pady=2)

        clear_filter_btn = ttk.Button(filter_panel, text="Clear Filter")
        clear_filter_btn.grid(row=0, column=7, padx=8, pady=2)



        # Define columns for the Treeview
        columns = [
            "Timestamp", "vnet", "nsg", "rule", "sourceIP", "destIP", "sourcePort",
            "destPort", "proto", "trafficFlow", "flowState",
            "encryption", "packetsSrcToDest",
            "bytesSrcToDest", "packetsDstToSrc", "bytesDestToSrc"
        ]

        # Create Treeview inside the frame
        tree = ttk.Treeview(table_frame, columns=columns, show='headings')
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=100, anchor="center")

        # Auto-size columns based on content after initial display
        def autosize_after_fill():
            self._autosize_tree_columns(tree, columns, original_data)

        # Schedule it a moment later so the widget exists and has its rows
        data_window.after(150, autosize_after_fill)


        # Add scrollbars
        scrollbar_y = tk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        scrollbar_x = tk.Scrollbar(table_frame, orient="horizontal", command=tree.xview)

        # Link scrollbars to Treeview
        tree.config(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        scrollbar_y.config(command=tree.yview)
        scrollbar_x.config(command=tree.xview)

        # Pack the Treeview and scrollbars in a grid-like layout
        tree.grid(row=3, column=0, sticky="nsew")
        scrollbar_y.grid(row=3, column=1, sticky="ns")
        scrollbar_x.grid(row=4, column=0, sticky="ew")

        # Configure grid to expand properly
        table_frame.grid_rowconfigure(3, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # Store mapping from item ID to data index
        self.tree_item_to_data_index = {}

        def update_treeview_display(data_to_display):
            # Clear existing items
            for item in tree.get_children():
                tree.delete(item)

            # Populate with filtered data
            for idx, row in enumerate(data_to_display):
                values = [str(row[col]) for col in columns]
                item_id = tree.insert("", "end", values=values)
                self.tree_item_to_data_index[item_id] = idx

                # Apply deny tag if flow state is 'D (Deny)'
                if row.get('flowState', '') == 'D (Deny)':
                    tree.item(item_id, tags='deny')

                # Apply platform rule tag if rule is 'PlatformRule'
                if row.get('rule', '') == 'PlatformRule':
                    tree.item(item_id, tags='platform_rule')
        # -------------------------------------------------
        #   Row‑filter based on Source / Destination / Port
        # -------------------------------------------------
        def apply_row_filter(event=None):
            """Filter `original_data` using the three precise fields (AND logic)."""
            src_val = src_var.get().strip()
            dst_val = dst_var.get().strip()
            port_val = port_var.get().strip()

            # If all are empty just show original data
            if not any([src_val, dst_val, port_val]):
                update_treeview_display(original_data)
                return

            def row_matches(row):
                # All comparisons are case‑insensitive string contains
                if src_val and src_val.lower() not in str(row.get('sourceIP', '')).lower():
                    return False
                if dst_val and dst_val.lower() not in str(row.get('destIP', '')).lower():
                    return False
                if port_val and port_val.lower() not in str(row.get('destPort', '')).lower():
                    return False
                return True

            filtered = [r for r in original_data if row_matches(r)]
            update_treeview_display(filtered)
        
        def clear_filters():
            """Reset entry widgets, show all rows again."""
            src_var.set("")
            dst_var.set("")
            port_var.set("")
            update_treeview_display(original_data)

        # Bind the button to the helper
        clear_filter_btn.configure(command=clear_filters)


        # Bind button click and <Return> on any of the three entries
        filter_btn.configure(command=apply_row_filter)
        src_entry.bind('<Return>', apply_row_filter)
        dst_entry.bind('<Return>', apply_row_filter)
        port_entry.bind('<Return>', apply_row_filter)

        # Initial display
        update_treeview_display(original_data)

        # Precompute column index mapping once
        column_indices = {col: idx for idx, col in enumerate(columns)}


        self.data = data  # Assuming 'data' is the processed data

        # Configure tags for highlighting
        tree.tag_configure("deny", background="#ffcccc")  # Light red for deny flows
        tree.tag_configure("platform_rule", background="#add8e6")  # Light blue for PlatformRule



        def copy_to_clipboard():
            if not data:
                return

            csv_data = ','.join(columns) + '\n'
            for row in data:
                values = [str(row[col]) for col in columns]
                csv_data += ','.join(values) + '\n'

            self.root.clipboard_clear()
            self.root.clipboard_append(csv_data)

        def copy_to_excel(data):
            if not data:
                return

            # Use the correct columns for Excel
            columns = [
                "Timestamp", "vnet", "nsg", "rule", "sourceIP", "destIP", "sourcePort",
                "destPort", "proto", "trafficFlow", "flowState",
                "encryption", "packetsSrcToDest",
                "bytesSrcToDest", "packetsDstToSrc", "bytesDestToSrc"
            ]

            # Create tab-separated data
            tsv_data = '\t'.join(columns) + '\n'  # Use tab instead of comma

            for row in data:
                values = [str(row[col]) for col in columns]
                tsv_data += '\t'.join(values) + '\n'  # Use tab instead of comma

            # Copy directly to clipboard
            self.root.clipboard_clear()
            self.root.clipboard_append(tsv_data)

        # Create a frame for buttons
        button_frame = ttk.Frame(data_window)
        button_frame.pack(pady=5)

        copy_btn1 = ttk.Button(button_frame, text="Copy(CSV)", command=copy_to_clipboard)
        copy_btn1.pack(side='left', padx=5)

        copy_btn2 = ttk.Button(button_frame, text="Copy(Excel)", command=lambda: copy_to_excel(data))
        copy_btn2.pack(side='left', padx=5)

        close_btn = ttk.Button(button_frame, text="Close", command=data_window.destroy)
        close_btn.pack(side='left', padx=5)

        # Force window to update and calculate proper size
        data_window.update_idletasks()




if __name__ == "__main__":
    root = tk.Tk()
    app = JSONViewerApp(root)
    root.mainloop()
