#!/usr/bin/env python3
"""
mDNS Network Database - Real-time GUI

Live dashboard showing discovered devices and services from the network database.
Updates in real-time as the database changes.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import json
from pathlib import Path
from datetime import datetime
import subprocess
import sys
import threading
from service_types import get_service_description

class NetworkDashboard:
    """Real-time GUI dashboard for network database."""
    
    def __init__(self, db_file: str = "network_db.json", run_collector: bool = True, 
                 active_mode: bool = True, update_interval: int = 30):
        self.db_file = Path(db_file)
        self.running = True
        self.refresh_interval = 2000  # milliseconds
        self.collector_process = None
        self.run_collector = run_collector
        self.collector_active_mode = active_mode
        self.collector_update_interval = update_interval
        
        # Create main window
        self.root = tk.Tk()
        self.root.title(f"mDNS Network Dashboard - {db_file}")
        self.root.geometry("1200x800")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        
        # Create UI
        self.create_widgets()
        
        # Start collector after UI is ready
        if run_collector:
            self.start_collector(active_mode, update_interval)
        
        # Start update loop
        self.update_display()
    
    def create_widgets(self):
        """Create all UI widgets."""
        
        # Top frame - Statistics
        stats_frame = ttk.LabelFrame(self.root, text="Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Statistics labels
        self.stats_labels = {}
        stats_info = [
            ('hosts', 'Hosts:'),
            ('services', 'Service Types:'),
            ('instances', 'Service Instances:'),
            ('packets', 'Packets:'),
            ('last_update', 'Last Update:')
        ]
        
        for i, (key, label) in enumerate(stats_info):
            ttk.Label(stats_frame, text=label, font=('Arial', 10, 'bold')).grid(
                row=0, column=i*2, padx=5, sticky=tk.W)
            self.stats_labels[key] = ttk.Label(stats_frame, text="0", font=('Arial', 10))
            self.stats_labels[key].grid(row=0, column=i*2+1, padx=5, sticky=tk.W)
        
        # Main content - Notebook with tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Tab 1: Hosts
        hosts_frame = ttk.Frame(notebook)
        notebook.add(hosts_frame, text="📱 Hosts")
        
        # Legend frame at top
        legend_frame = ttk.Frame(hosts_frame)
        legend_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(legend_frame, text="Status Legend:", font=('Arial', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        
        # Create legend labels with colored backgrounds
        legends = [
            ('🟢 Recent (< 10s)', '#e8f5e9', '#2e7d32'),
            ('⚪ Active (< 5m)', '#ffffff', '#000000'),
            ('🔵 Idle (< 1h)', '#f5f5f5', '#757575'),
            ('⚫ Offline (> 1h)', '#eeeeee', '#9e9e9e')
        ]
        
        for text, bg, fg in legends:
            lbl = tk.Label(legend_frame, text=text, bg=bg, fg=fg, padx=8, pady=2, relief=tk.RIDGE)
            lbl.pack(side=tk.LEFT, padx=2)
        
        # Hosts treeview
        hosts_scroll = ttk.Scrollbar(hosts_frame)
        hosts_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.hosts_tree = ttk.Treeview(
            hosts_frame,
            columns=('hostname', 'ips', 'first_seen', 'last_seen', 'count'),
            show='headings',
            yscrollcommand=hosts_scroll.set
        )
        hosts_scroll.config(command=self.hosts_tree.yview)
        
        self.hosts_tree.heading('hostname', text='Hostname')
        self.hosts_tree.heading('ips', text='IP Address(es)')
        self.hosts_tree.heading('first_seen', text='First Seen')
        self.hosts_tree.heading('last_seen', text='Last Seen')
        self.hosts_tree.heading('count', text='Count')
        
        self.hosts_tree.column('hostname', width=300)
        self.hosts_tree.column('ips', width=250)
        self.hosts_tree.column('first_seen', width=150)
        self.hosts_tree.column('last_seen', width=150)
        self.hosts_tree.column('count', width=80)
        
        self.hosts_tree.pack(fill=tk.BOTH, expand=True)
        
        # Tab 2: Services
        services_frame = ttk.Frame(notebook)
        notebook.add(services_frame, text="🔧 Services")
        
        # Services treeview
        services_scroll = ttk.Scrollbar(services_frame)
        services_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.services_tree = ttk.Treeview(
            services_frame,
            columns=('service', 'instance', 'hostname', 'ip', 'port', 'last_seen'),
            show='tree headings',
            yscrollcommand=services_scroll.set
        )
        services_scroll.config(command=self.services_tree.yview)
        
        self.services_tree.heading('#0', text='Service Type / Description')
        self.services_tree.heading('service', text='Instance Name')
        self.services_tree.heading('instance', text='Details')
        self.services_tree.heading('hostname', text='Hostname')
        self.services_tree.heading('ip', text='IP Address')
        self.services_tree.heading('port', text='Port')
        self.services_tree.heading('last_seen', text='Last Seen')
        
        self.services_tree.column('#0', width=350)
        self.services_tree.column('service', width=250)
        self.services_tree.column('instance', width=200)
        self.services_tree.column('hostname', width=150)
        self.services_tree.column('ip', width=120)
        self.services_tree.column('port', width=80)
        self.services_tree.column('last_seen', width=100)
        
        self.services_tree.pack(fill=tk.BOTH, expand=True)
        
        # Bind right-click context menu for services tree
        self.services_tree.bind('<Button-3>', self.show_services_context_menu)
        
        # Tab 3: Activity Log
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="📋 Activity Log")
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=('Courier', 9),
            bg='#1e1e1e',
            fg='#d4d4d4'
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Tab 4: Collector Output
        collector_frame = ttk.Frame(notebook)
        notebook.add(collector_frame, text="🔧 Collector Output")
        
        self.collector_text = scrolledtext.ScrolledText(
            collector_frame,
            wrap=tk.WORD,
            font=('Courier', 9),
            bg='#1e1e1e',
            fg='#00ff00'
        )
        self.collector_text.pack(fill=tk.BOTH, expand=True)
        
        # Tab 5: Raw Database
        raw_frame = ttk.Frame(notebook)
        notebook.add(raw_frame, text="📄 Raw Data")
        
        self.raw_text = scrolledtext.ScrolledText(
            raw_frame,
            wrap=tk.WORD,
            font=('Courier', 9)
        )
        self.raw_text.pack(fill=tk.BOTH, expand=True)
        
        # Bottom frame - Controls
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(control_frame, text="Refresh Rate:").pack(side=tk.LEFT, padx=5)
        
        self.refresh_var = tk.StringVar(value="2")
        refresh_combo = ttk.Combobox(
            control_frame,
            textvariable=self.refresh_var,
            values=["1", "2", "5", "10"],
            width=5,
            state='readonly'
        )
        refresh_combo.pack(side=tk.LEFT, padx=5)
        refresh_combo.bind('<<ComboboxSelected>>', self.on_refresh_change)
        
        ttk.Label(control_frame, text="seconds").pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Refresh Now", command=self.force_refresh).pack(
            side=tk.LEFT, padx=20)
        
        ttk.Button(control_frame, text="Clear Log", command=self.clear_log).pack(
            side=tk.LEFT, padx=5)
        
        self.status_label = ttk.Label(control_frame, text="Initializing...", foreground='blue')
        self.status_label.pack(side=tk.RIGHT, padx=10)
    
    def load_database(self):
        """Load data from the database file."""
        try:
            if not self.db_file.exists():
                return None
            
            # Get file modification time for debugging
            mtime = self.db_file.stat().st_mtime
            
            with open(self.db_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Store modification time for debugging
            if not hasattr(self, '_last_mtime'):
                self._last_mtime = 0
                self._update_count = 0
            
            if mtime != self._last_mtime:
                self._last_mtime = mtime
                self._update_count = getattr(self, '_update_count', 0) + 1
            
            return data
        except Exception as e:
            self.log(f"ERROR loading database: {e}", 'error')
            return None
    
    def update_display(self):
        """Update all displays with current database data."""
        if not self.running:
            return
        
        try:
            data = self.load_database()
            
            if data:
                self.update_statistics(data)
                self.update_hosts_table(data)
                self.update_services_table(data)
                self.update_raw_display(data)
                self.status_label.config(text="✓ Updated", foreground='green')
            else:
                self.status_label.config(
                    text=f"⚠ Database not found: {self.db_file}",
                    foreground='orange'
                )
        
        except Exception as e:
            self.log(f"ERROR updating display: {e}", 'error')
            self.status_label.config(text=f"✗ Error: {e}", foreground='red')
        
        # Schedule next update
        self.root.after(self.refresh_interval, self.update_display)
    
    def update_statistics(self, data):
        """Update statistics display."""
        hosts = data.get('hosts', {})
        services = data.get('services', {})
        stats = data.get('stats', {})
        
        total_instances = sum(
            len(svc.get('instances', {}))
            for svc in services.values()
        )
        
        self.stats_labels['hosts'].config(text=str(len(hosts)))
        self.stats_labels['services'].config(text=str(len(services)))
        self.stats_labels['instances'].config(text=str(total_instances))
        self.stats_labels['packets'].config(text=str(stats.get('packets_received', 0)))
        
        last_activity = stats.get('last_activity', 'Never')
        if last_activity != 'Never' and 'T' in last_activity:
            last_activity = last_activity.split('T')[1][:8]
        self.stats_labels['last_update'].config(text=last_activity)
    
    def update_hosts_table(self, data):
        """Update hosts table."""
        # Save selected item
        selected = self.hosts_tree.selection()
        selected_hostname = None
        if selected:
            try:
                values = self.hosts_tree.item(selected[0], 'values')
                if values:
                    selected_hostname = values[0]  # hostname is first column
            except:
                pass
        
        # Clear existing
        for item in self.hosts_tree.get_children():
            self.hosts_tree.delete(item)
        
        hosts = data.get('hosts', {})
        
        # Sort by last seen (most recent first)
        sorted_hosts = sorted(
            hosts.items(),
            key=lambda x: x[1].get('last_seen', ''),
            reverse=True
        )
        
        for hostname, host_data in sorted_hosts:
            ips = ', '.join(sorted(host_data.get('ips', [])))
            first_seen = host_data.get('first_seen', '')
            last_seen = host_data.get('last_seen', '')
            count = host_data.get('seen_count', 0)
            
            # Format timestamps
            if 'T' in first_seen:
                first_seen = first_seen.split('T')[1][:8]
            if 'T' in last_seen:
                last_seen = last_seen.split('T')[1][:8]
            
            # Determine device status based on age
            tag = ''
            if last_seen and host_data.get('last_seen'):
                try:
                    last_dt = datetime.fromisoformat(host_data['last_seen'])
                    age = (datetime.now() - last_dt).total_seconds()
                    if age < 10:
                        tag = 'recent'  # Green - seen in last 10 seconds
                    elif age < 300:
                        tag = 'active'  # Normal - seen in last 5 minutes
                    elif age < 3600:
                        tag = 'idle'    # Light gray - seen in last hour
                    else:
                        tag = 'offline' # Dark gray - not seen in over an hour
                except:
                    tag = 'unknown'
            
            item_id = self.hosts_tree.insert('', tk.END, values=(
                hostname, ips, first_seen, last_seen, count
            ), tags=(tag,))
            
            # Restore selection
            if selected_hostname and hostname == selected_hostname:
                self.hosts_tree.selection_set(item_id)
                self.hosts_tree.see(item_id)
        
        # Configure tags with colors
        self.hosts_tree.tag_configure('recent', background='#e8f5e9', foreground='#2e7d32')   # Green
        self.hosts_tree.tag_configure('active', background='#ffffff', foreground='#000000')   # Normal
        self.hosts_tree.tag_configure('idle', background='#f5f5f5', foreground='#757575')     # Light gray
        self.hosts_tree.tag_configure('offline', background='#eeeeee', foreground='#9e9e9e')  # Dark gray
        self.hosts_tree.tag_configure('unknown', background='#fff3e0', foreground='#e65100')  # Orange
    
    def update_services_table(self, data):
        """Update services table."""
        # Save expanded state and selection
        expanded_items = set()
        selected = self.services_tree.selection()
        selected_instance = None
        selected_parent = None
        
        for item in self.services_tree.get_children():
            if self.services_tree.item(item, 'open'):
                # Get the service type text
                service_type = self.services_tree.item(item, 'text')
                expanded_items.add(service_type)
        
        # Save selected item
        if selected:
            try:
                values = self.services_tree.item(selected[0], 'values')
                parent = self.services_tree.parent(selected[0])
                if values and values[0]:  # It's a service instance (child)
                    selected_instance = values[0]
                    if parent:
                        selected_parent = self.services_tree.item(parent, 'text')
                elif not parent:  # It's a service type (root)
                    selected_parent = self.services_tree.item(selected[0], 'text')
            except:
                pass
        
        # Clear existing
        for item in self.services_tree.get_children():
            self.services_tree.delete(item)
        
        services = data.get('services', {})
        hosts = data.get('hosts', {})
        
        # Sort service types
        for service_type in sorted(services.keys()):
            instances = services[service_type].get('instances', {})
            
            # Get service description
            description = get_service_description(service_type)
            
            # Insert service type as parent with description
            service_text = f"{description} ({len(instances)})"
            parent = self.services_tree.insert('', tk.END, text=service_text)
            
            # Restore expanded state
            if service_text in expanded_items or f"{service_type} " in str(expanded_items):
                self.services_tree.item(parent, open=True)
            
            # Restore selection if this is the selected parent (and no child was selected)
            if selected_parent and service_text == selected_parent and not selected_instance:
                self.services_tree.selection_set(parent)
                self.services_tree.see(parent)
            
            # Sort instances by last seen
            sorted_instances = sorted(
                instances.items(),
                key=lambda x: x[1].get('last_seen', ''),
                reverse=True
            )
            
            for instance_name, instance_data in sorted_instances:
                hostname = instance_data.get('hostname', '')
                port = instance_data.get('port', '')
                last_seen = instance_data.get('last_seen', '')
                txt = instance_data.get('txt', [])
                
                # Format last seen
                if 'T' in last_seen:
                    last_seen = last_seen.split('T')[1][:8]
                
                # Get IP if available
                ip_str = ''
                if hostname and hostname in hosts:
                    ips = list(hosts[hostname].get('ips', []))
                    if ips:
                        ip_str = ips[0]
                
                # Format details
                details = ''
                if txt:
                    details = ', '.join(txt[:3])
                    if len(txt) > 3:
                        details += '...'
                
                child_id = self.services_tree.insert(parent, tk.END, values=(
                    instance_name,
                    details,
                    hostname,
                    ip_str,
                    port,
                    last_seen
                ))
                
                # Restore selection
                if selected_instance and instance_name == selected_instance and service_text == selected_parent:
                    self.services_tree.selection_set(child_id)
                    self.services_tree.see(child_id)
    
    def update_raw_display(self, data):
        """Update raw database display."""
        self.raw_text.delete(1.0, tk.END)
        
        # Pretty print JSON
        json_str = json.dumps(data, indent=2, sort_keys=True)
        self.raw_text.insert(1.0, json_str)
    
    def log(self, message, level='info'):
        """Add message to activity log."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Color coding
        colors = {
            'info': '#4CAF50',
            'warning': '#FF9800',
            'error': '#F44336'
        }
        
        color = colors.get(level, '#FFFFFF')
        
        log_line = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_line)
        self.log_text.see(tk.END)
        
        # Limit log size
        lines = int(self.log_text.index('end-1c').split('.')[0])
        if lines > 1000:
            self.log_text.delete(1.0, '100.0')
    
    def clear_log(self):
        """Clear activity log."""
        self.log_text.delete(1.0, tk.END)
        self.log("Log cleared", 'info')
    
    def force_refresh(self):
        """Force immediate refresh."""
        self.status_label.config(text="Refreshing...", foreground='blue')
        self.log("Manual refresh triggered", 'info')
        self.root.after(100, self.update_display)
    
    def show_services_context_menu(self, event):
        """Show right-click context menu for services tree."""
        # Identify which row and column was clicked
        item = self.services_tree.identify_row(event.y)
        column = self.services_tree.identify_column(event.x)
        
        if not item:
            return
        
        # Select the item
        self.services_tree.selection_set(item)
        
        # Get the value to copy
        value = None
        if column == '#0':
            # Tree column (service type/description)
            value = self.services_tree.item(item, 'text')
        else:
            # Data column
            col_index = int(column.replace('#', '')) - 1
            values = self.services_tree.item(item, 'values')
            if values and 0 <= col_index < len(values):
                value = values[col_index]
        
        if value:
            # Create context menu
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(
                label=f"Copy: {value[:50]}..." if len(str(value)) > 50 else f"Copy: {value}",
                command=lambda: self.copy_to_clipboard(value)
            )
            menu.post(event.x_root, event.y_root)
    
    def copy_to_clipboard(self, value):
        """Copy value to clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(str(value))
        self.log(f"Copied to clipboard: {value}", 'info')
    
    def on_refresh_change(self, event):
        """Handle refresh rate change."""
        self.refresh_interval = int(self.refresh_var.get()) * 1000
        self.log(f"Refresh rate changed to {self.refresh_var.get()} seconds", 'info')
    
    def start_collector(self, active_mode: bool, update_interval: int):
        """Start the network database collector in a subprocess."""
        try:
            cmd = [
                sys.executable,
                '-u',  # Unbuffered output
                'network_db.py',
                '--db', str(self.db_file),
                '--save-interval', str(update_interval),  # How often to save database
                '--update-interval', str(update_interval)  # How often to show status
            ]
            
            if active_mode:
                cmd.append('--active')
            
            # Check if network_db.py exists
            if not Path('network_db.py').exists():
                self.log("ERROR: network_db.py not found in current directory", 'error')
                self.append_collector_output("ERROR: network_db.py not found\n")
                return
            
            self.collector_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.log(f"Started network collector (PID: {self.collector_process.pid})", 'info')
            self.log(f"Command: {' '.join(cmd)}", 'info')
            self.log(f"Active mode: {active_mode}, Update interval: {update_interval}s", 'info')
            
            # Add initial message to collector output
            self.append_collector_output(f"=== Collector Started (PID: {self.collector_process.pid}) ===\n")
            self.append_collector_output(f"Command: {' '.join(cmd)}\n")
            self.append_collector_output("=" * 60 + "\n\n")
            
            # Start thread to read collector output
            self.collector_reader_thread = threading.Thread(
                target=self.read_collector_output,
                daemon=True
            )
            self.collector_reader_thread.start()
            
            # Check if process is still running after a moment
            self.root.after(1000, self.check_collector_status)
            
        except Exception as e:
            self.log(f"ERROR starting collector: {e}", 'error')
            self.append_collector_output(f"ERROR starting collector: {e}\n")
    
    def check_collector_status(self):
        """Check if collector process is still running."""
        if self.collector_process and self.collector_process.poll() is not None:
            self.log(f"WARNING: Collector process exited with code {self.collector_process.returncode}", 'error')
            self.append_collector_output(f"\n=== Collector Exited (code: {self.collector_process.returncode}) ===\n")
    
    def read_collector_output(self):
        """Read and display output from the collector process."""
        if not self.collector_process:
            self.root.after(0, self.append_collector_output, "ERROR: No collector process\n")
            return
        
        try:
            while self.running:
                line = self.collector_process.stdout.readline()
                if not line:
                    # Process ended
                    if self.collector_process.poll() is not None:
                        break
                    continue
                
                # Update collector output tab
                self.root.after(0, self.append_collector_output, line)
            
            # Final message
            if self.collector_process.poll() is not None:
                self.root.after(0, self.append_collector_output, 
                    f"\n=== Collector process terminated (exit code: {self.collector_process.returncode}) ===\n")
                
        except Exception as e:
            self.root.after(0, self.append_collector_output, f"ERROR reading output: {e}\n")
    
    def append_collector_output(self, text: str):
        """Append text to collector output tab."""
        try:
            self.collector_text.insert(tk.END, text)
            self.collector_text.see(tk.END)
            
            # Limit output to last 10000 lines
            lines = int(self.collector_text.index('end-1c').split('.')[0])
            if lines > 10000:
                self.collector_text.delete('1.0', f'{lines-10000}.0')
        except:
            pass
    
    def stop_collector(self):
        """Stop the network database collector subprocess."""
        if self.collector_process:
            try:
                self.collector_process.terminate()
                self.collector_process.wait(timeout=5)
                self.log("Network collector stopped", 'info')
            except Exception as e:
                self.log(f"ERROR stopping collector: {e}", 'error')
                try:
                    self.collector_process.kill()
                except:
                    pass
    
    def on_closing(self):
        """Handle window close."""
        self.running = False
        if self.run_collector:
            self.stop_collector()
        self.root.destroy()
    
    def run(self):
        """Start the GUI."""
        self.log(f"Dashboard started - monitoring {self.db_file}", 'info')
        self.log("Waiting for database updates...", 'info')
        self.root.mainloop()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='mDNS Network Dashboard - Real-time GUI for network database',
        epilog='''
Examples:
  Default mode (collector runs automatically):
    python network_gui.py
  
  With active querying (recommended):
    python network_gui.py --active
  
  Custom database and refresh rate:
    python network_gui.py --db sallys.json --refresh 1 --active
  
  View existing database only (no collector):
    python network_gui.py --no-collector

Two-process mode (advanced):
  Terminal 1: python network_db.py --active
  Terminal 2: python network_gui.py --no-collector
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--db', default='network_db.json',
                       help='Database file to monitor (default: network_db.json)')
    parser.add_argument('--refresh', type=int, default=2,
                       help='GUI refresh interval in seconds (default: 2)')
    parser.add_argument('--no-collector', action='store_true',
                       help='Do NOT start collector (view existing database only)')
    parser.add_argument('--active', action='store_true',
                       help='Enable active querying mode in collector')
    parser.add_argument('--update-interval', type=int, default=30,
                       help='Collector update interval in seconds (default: 30)')
    
    args = parser.parse_args()
    
    # Create and run dashboard
    dashboard = NetworkDashboard(
        db_file=args.db,
        run_collector=not args.no_collector,
        active_mode=args.active,
        update_interval=args.update_interval
    )
    dashboard.refresh_interval = args.refresh * 1000
    dashboard.run()


if __name__ == '__main__':
    main()
