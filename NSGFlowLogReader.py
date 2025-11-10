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

        # Title
        title_label = ttk.Label(main_frame, text="NSG Flow Log JSON Viewer", font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=(0, 10))

        # File listbox with scrollbar
        file_frame = ttk.Frame(main_frame)
        file_frame.pack(padx=10, pady=5, fill='both', expand=True)

        # Add description label above file list
        files_label = ttk.Label(file_frame, text="Files in current folder/subfolders", font=('Helvetica', 10, 'bold'))
        files_label.pack(pady=(0, 5), anchor='w')

        self.file_listbox = tk.Listbox(file_frame, height=10, width=60)
        file_scrollbar = ttk.Scrollbar(file_frame, orient='vertical', command=self.file_listbox.yview)
        self.file_listbox.config(yscrollcommand=file_scrollbar.set)

        # Bind double-click event to open selected file
        self.file_listbox.bind('<Double-Button-1>', self.on_file_double_click)

        self.file_listbox.pack(side='left', fill='both', expand=True)
        file_scrollbar.pack(side='right', fill='y')



        # Control frame for buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(pady=5, fill='x')

        self.open_selected_btn = ttk.Button(
            control_frame,
            text="Open Selected",
            command=self.open_selected_files
        )
        self.open_selected_btn.pack(side='left', padx=5)

        self.refresh_btn = ttk.Button(control_frame, text="Refresh File List", command=self.refresh_files)
        self.refresh_btn.pack(side='left', padx=5)

        self.open_btn = ttk.Button(control_frame, text="Open Other", command=self.open_files)
        self.open_btn.pack(side='left', padx=5)


        # Load existing JSON files
        self.load_existing_json_files()

        # Auto-size window based on longest filename
        self.auto_size_window()

        # Status bar (bottom of window)
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor='w')
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
        """Helper method to autosize treeview columns based on content"""
        if not data or not tree.get_children():
            return

        # Get the first item to check column widths
        try:
            first_item = tree.get_children()[0]
            values = tree.item(first_item)['values']

            for i, col in enumerate(columns):
                # Get header width
                header_width = len(col) * 8

                # Check data width for this column across all rows
                max_width = header_width
                for row in data:
                    cell_value = str(row.get(col, ''))
                    cell_width = len(cell_value) * 8
                    if cell_width > max_width:
                        max_width = cell_width

                # Add generous buffer space (25 pixels) to ensure no content is cut off
                buffer_space = 25
                final_width = max_width + buffer_space

                # Set column width with reasonable bounds - minimum 100px, maximum 500px
                tree.column(col, width=max(100, min(final_width, 500)))
        except Exception:
            pass  # If there's an error, just leave default sizing






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
        selected_indices = self.file_listbox.curselection()
        if not selected_indices:
            return

        current_dir = os.path.dirname(os.path.abspath(__file__))

        for idx in selected_indices:
            filename = self.file_listbox.get(idx)
            full_path = os.path.join(current_dir, filename)

            # Load and process the data
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                records = data.get("records", [])

                processed_data = []
                for r in records:
                    if 'flowRecords' in r and 'flows' in r['flowRecords']:
                        for flow in r['flowRecords']['flows']:
                            acl_id = flow.get('aclID', '')
                            nsg_name = extract_nsg(acl_id)
                            vnet_name = extract_vnet(r)  # Extract vNet from the record
                            for group in flow.get('flowGroups', []):
                                rule_name = group.get('rule', '')
                                for tuple_str in group.get('flowTuples', []):
                                    fields = tuple_str.split(',')
                                    row = self.map_flow_tuple(fields)
                                    if row:
                                        # Add vnet, nsg, and rule to the row
                                        row['vnet'] = vnet_name
                                        row['nsg'] = nsg_name
                                        row['rule'] = rule_name
                                        processed_data.append(row)

                # Show the processed data
                self.display_data_window(processed_data, filename)

            except Exception as e:
                messagebox.showerror("Error", f"Failed to load {filename}: {str(e)}")


    def refresh_files(self):
        """Refresh the list of JSON files in the file listbox"""
        # Clear current listbox
        self.file_listbox.delete(0, tk.END)

        # Reload existing JSON files
        self.load_existing_json_files()

        # Update status bar
        self.status_bar.config(text="File list refreshed")


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

        # Add instruction label above the table
        instruction_label = ttk.Label(table_frame, text="Search supports partial matches and exact matches using quotes (e.g., \"Exact Match\")", 
                                        font=('Helvetica', 10, 'italic'))
        instruction_label.grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 5))

        # Search frame
        search_frame = ttk.Frame(table_frame)
        search_frame.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(0, 5))

        search_label = ttk.Label(search_frame, text="Search:")
        search_label.pack(side='left', padx=(0, 5))

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side='left', padx=(0, 5))

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
        def autosize_columns():
            # Wait a bit for the tree to render
            data_window.after(100, lambda: self._autosize_tree_columns(tree, columns, data))

        # Trigger column autosizing
        autosize_columns()


        # Add scrollbars
        scrollbar_y = tk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        scrollbar_x = tk.Scrollbar(table_frame, orient="horizontal", command=tree.xview)

        # Link scrollbars to Treeview
        tree.config(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        scrollbar_y.config(command=tree.yview)
        scrollbar_x.config(command=tree.xview)

        # Pack the Treeview and scrollbars in a grid-like layout
        tree.grid(row=2, column=0, sticky="nsew")
        scrollbar_y.grid(row=2, column=1, sticky="ns")
        scrollbar_x.grid(row=3, column=0, sticky="ew")

        # Configure grid to expand properly
        table_frame.grid_rowconfigure(2, weight=1)
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


        def filter_data(event=None):
            search_term = self.search_var.get().strip()

            # Handle empty search
            if not search_term:
                update_treeview_display(original_data)
                return

            # Parse search terms - split by spaces but preserve quoted strings
            import re
            # This regex splits on spaces but keeps quoted strings together
            pattern = r'"[^"]*"|\S+'
            terms = re.findall(pattern, search_term)

            # Remove quotes from quoted terms
            clean_terms = [term.strip('"') for term in terms]

            def matches_row(row):
                # Get all values from the row
                row_values = [str(value).lower() for value in row.values()]

                # Check if all terms match (AND logic)
                for i, term in enumerate(clean_terms):
                    # If this is an exact match term (quoted)
                    if terms[i].startswith('"') and terms[i].endswith('"'):
                        # Exact match - check if any field exactly matches the term
                        if not any(term.lower() == value for value in row_values):
                            return False
                    else:
                        # Partial match - check if any field contains the term
                        if not any(term.lower() in value for value in row_values):
                            return False

                return True

            # Filter data using the new matching logic
            filtered_rows = [row for row in original_data if matches_row(row)]
            update_treeview_display(filtered_rows)


        search_entry.bind('<KeyRelease>', filter_data)

        search_btn = ttk.Button(search_frame, text="Search", command=filter_data)
        search_btn.pack(side='left', padx=(0, 5))

        clear_search_btn = ttk.Button(search_frame, text="Clear Search", command=lambda: 
            [self.search_var.set(""), filter_data()])
        clear_search_btn.pack(side='left')

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
