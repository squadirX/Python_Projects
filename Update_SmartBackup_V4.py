
from __future__ import annotations

import ast
import os
import shutil
import tempfile
from pathlib import Path

PROJECT_DIR = Path.home() / "Documents" / "SmartBackup"
SOURCE_FILE = PROJECT_DIR / "SmartBackup_Dashboard_Prototype_v3.py"
OUTPUT_FILE = PROJECT_DIR / "SmartBackup_Dashboard_Prototype_v4.py"


def replace_once(source, old, new, label):
    count = source.count(old)
    if count != 1:
        raise RuntimeError(
            f"Patch stopped: {label} expected 1 match, found {count}."
        )
    return source.replace(old, new, 1)


def build():
    if not SOURCE_FILE.is_file():
        raise FileNotFoundError(
            f"V3 source file not found: {SOURCE_FILE}"
        )

    if OUTPUT_FILE.exists():
        raise FileExistsError(
            f"V4 already exists; refusing to overwrite: {OUTPUT_FILE}"
        )

    source = SOURCE_FILE.read_text(encoding="utf-8")

    # 1. Add filesystem utilities.
    source = replace_once(
        source,
        "from pathlib import Path\n",
        "from pathlib import Path\nimport os\nimport shutil\nimport tempfile\n",
        "Add filesystem utilities",
    )

    # 2. Add Windows C and flexible destination roots.
    source = replace_once(
        source,
        '    "Windows D: ADATA": Path("/Volumes/Windows_D_ADATA/DATA/SmartBackup_Archives"),\n',
        '    "Windows C: Drive": Path("/Volumes/Windows_C_Drive"),\n'
        '    "Windows D: ADATA": Path("/Volumes/Windows_D_ADATA"),\n',
        "Add Windows C and D destinations",
    )

    source = replace_once(
        source,
        '    "Windows F: Transcend": Path("/Volumes/Windows_F_TRANSCEND/SmartBackup_Archives"),\n'
        '    "Local Mac": HOME / "Documents/SmartBackup/Archives",\n',
        '    "Windows F: Transcend": Path("/Volumes/Windows_F_TRANSCEND"),\n'
        '    "Local Mac": HOME / "Documents",\n',
        "Use destination roots for F and Local Mac",
    )

    source = replace_once(
        source,
        "WINDOWS_MOUNTS = {\n",
        'WINDOWS_MOUNTS = {\n'
        '    "Windows C: Drive": Path("/Volumes/Windows_C_Drive"),\n',
        "Add Windows C mount",
    )

    # 3. Improve sidebar navigation.
    source = replace_once(
        source,
        '            ("overview", "◈", "Overview"),\n'
        '            ("daily", "◷", "Daily Backup"),\n'
        '            ("manual", "▣", "Manual Archive"),\n'
        '            ("activity", "≋", "Activity & Reports"),\n',
        '            ("overview", "01", "Overview"),\n'
        '            ("daily", "02", "Daily Backup"),\n'
        '            ("manual", "03", "Manual Archive"),\n'
        '            ("activity", "04", "Activity & Reports"),\n',
        "Improve sidebar symbols",
    )

    source = replace_once(
        source,
        '                text=f"  {symbol}    {label}",\n',
        '                text=f"  {symbol}   |   {label}",\n',
        "Clarify sidebar labels",
    )

    # 4. Track selected destination folders.
    source = replace_once(
        source,
        '        self.destination_vars = {\n'
        '            name: tk.BooleanVar(value=(name == "OneDrive"))\n'
        '            for name in MANUAL_DESTINATIONS\n'
        '        }\n',
        '        self.destination_vars = {\n'
        '            name: tk.BooleanVar(value=(name == "OneDrive"))\n'
        '            for name in MANUAL_DESTINATIONS\n'
        '        }\n'
        '        self.manual_destination_paths = dict(MANUAL_DESTINATIONS)\n',
        "Track selected destination folders",
    )

    source = replace_once(
        source,
        '        self._metric_card(metrics, "07", "Manual destinations", "Local, iCloud, OneDrive, Google Drive, Dropbox, D: and F:", COLORS["accent"])\n',
        '        self._metric_card(metrics, "08", "Manual destinations", "Local, iCloud, OneDrive, Google Drive, Dropbox, C:, D: and F:", COLORS["accent"])\n',
        "Update destination count",
    )

    source = replace_once(
        source,
        '        tk.Label(daily, text="LOCAL   ·   iCLOUD   ·   ONEDRIVE", bg=COLORS["panel"], fg=COLORS["blue"], font=(FONT, 11, "bold")).pack(anchor="w", pady=(0, 13))\n',
        '        tk.Label(daily, text="LOCAL   ·   iCLOUD   ·   ONEDRIVE", bg=COLORS["panel"], fg=COLORS["text"], font=(FONT, 11, "bold")).pack(anchor="w", pady=(0, 13))\n',
        "Darken daily destination label",
    )

    source = replace_once(
        source,
        '        tk.Label(manual, text="ONEDRIVE   ·   ICLOUD   ·   GOOGLE DRIVE   ·   DROPBOX   ·   WINDOWS D:   ·   WINDOWS F:", bg=COLORS["panel"], fg=COLORS["accent"], font=(FONT, 11, "bold")).pack(anchor="w", pady=(0, 13))\n',
        '        tk.Label(manual, text="ONEDRIVE   ·   ICLOUD   ·   GOOGLE DRIVE   ·   DROPBOX   ·   WINDOWS C:   ·   WINDOWS D:   ·   WINDOWS F:", bg=COLORS["panel"], fg=COLORS["text"], font=(FONT, 10, "bold")).pack(anchor="w", pady=(0, 13))\n',
        "Update manual destination label",
    )

    # 5. Add storage capacity display.
    capacity_methods = '''    def _capacity_for_path(self, path):
        if path is None:
            return None

        candidate = path.expanduser()

        while not candidate.exists() and candidate != candidate.parent:
            candidate = candidate.parent

        try:
            if not candidate.exists():
                return None
            return shutil.disk_usage(candidate)
        except OSError:
            return None

    def _add_capacity_bar(self, parent, path):
        usage = self._capacity_for_path(path)

        if usage is None:
            tk.Label(
                parent,
                text="Capacity unavailable",
                bg=COLORS["panel"],
                fg=COLORS["subtle"],
                font=(FONT, 9),
            ).pack(anchor="w", pady=(7, 0))
            return

        total_gb = usage.total / (1024 ** 3)
        free_gb = usage.free / (1024 ** 3)
        percent = usage.used / usage.total * 100 if usage.total else 0

        bar_color = (
            COLORS["accent"] if percent < 70
            else COLORS["amber"] if percent < 90
            else COLORS["red"]
        )

        tk.Label(
            parent,
            text=f"{percent:.1f}% used  ·  {free_gb:.1f} GB free / {total_gb:.1f} GB",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=(FONT, 9, "bold"),
        ).pack(anchor="w", pady=(7, 4))

        bar = tk.Canvas(
            parent,
            height=10,
            bg=COLORS["panel_alt"],
            highlightthickness=0,
            bd=0,
        )
        bar.pack(fill="x")
        bar.update_idletasks()

        width = max(1, bar.winfo_width())

        bar.create_rectangle(
            0, 0, width, 10,
            fill=COLORS["panel_alt"],
            outline="",
        )

        bar.create_rectangle(
            0, 0,
            width * min(100, max(0, percent)) / 100,
            10,
            fill=bar_color,
            outline="",
        )

'''

    source = replace_once(
        source,
        "    def _destination_strip(self, parent: tk.Widget) -> None:\n",
        capacity_methods
        + "    def _destination_strip(self, parent: tk.Widget) -> None:\n",
        "Add capacity helper",
    )

    source = replace_once(
        source,
        '        entries = [\n'
        '            ("OneDrive", COLORS["accent"]),\n'
        '            ("iCloud Drive", COLORS["blue"]),\n'
        '            ("Google Drive", COLORS["blue"]),\n'
        '            ("Dropbox", COLORS["amber"]),\n'
        '            ("Windows D: ADATA", COLORS["blue"]),\n'
        '            ("Windows F: Transcend", COLORS["amber"]),\n'
        '            ("Local Mac", COLORS["accent"]),\n'
        '        ]\n',
        '        entries = [\n'
        '            ("OneDrive", COLORS["accent"]),\n'
        '            ("iCloud Drive", COLORS["blue"]),\n'
        '            ("Google Drive", COLORS["blue"]),\n'
        '            ("Dropbox", COLORS["amber"]),\n'
        '            ("Windows C: Drive", COLORS["blue"]),\n'
        '            ("Windows D: ADATA", COLORS["blue"]),\n'
        '            ("Windows F: Transcend", COLORS["amber"]),\n'
        '            ("Local Mac", COLORS["accent"]),\n'
        '        ]\n',
        "Show all eight destinations",
    )

    source = replace_once(
        source,
        '            tk.Label(card, text=self._destination_status(name), bg=COLORS["panel"], fg=COLORS["subtle"], font=(FONT, 10, "bold"), wraplength=300, justify="left").pack(anchor="w", pady=(8, 0))\n',
        '            tk.Label(card, text=self._destination_status(name), bg=COLORS["panel"], fg=COLORS["subtle"], font=(FONT, 10, "bold"), wraplength=300, justify="left").pack(anchor="w", pady=(8, 0))\n'
        '            self._add_capacity_bar(card, self.manual_destination_paths.get(name))\n',
        "Add capacity bars",
    )

    # 6. Allow a custom target folder for every destination.
    source = replace_once(
        source,
        '            tk.Label(tile, text=self._display_path(path), bg=COLORS["panel_alt"], fg=COLORS["muted"], font=(MONO, 8), wraplength=260, justify="left").pack(anchor="w", padx=(28, 0), pady=(5, 7))\n',
        '            path_label = tk.Label(tile, text=self._display_path(self.manual_destination_paths.get(name)), bg=COLORS["panel_alt"], fg=COLORS["muted"], font=(MONO, 8), wraplength=260, justify="left")\n'
        '            path_label.pack(anchor="w", padx=(28, 0), pady=(5, 7))\n'
        '            self.manual_path_labels = getattr(self, "manual_path_labels", {})\n'
        '            self.manual_path_labels[name] = path_label\n'
        '            self._action_button(tile, "CHOOSE TARGET FOLDER", lambda key=name: self._choose_destination_folder(key), False).pack(anchor="w", padx=(28, 0), pady=(5, 7))\n',
        "Add target folder chooser",
    )

    source = replace_once(
        source,
        "    def _selected_destinations(self) -> list[tuple[str, Path | None]]:\n",
        '''    def _choose_destination_folder(self, name):
        selected = filedialog.askdirectory(
            title=f"Choose target folder for {name}",
            mustexist=True,
        )

        if selected:
            self.manual_destination_paths[name] = Path(selected)

            label = getattr(self, "manual_path_labels", {}).get(name)
            if label:
                label.configure(text=selected)

            self._refresh_manual_status()

    def _selected_destinations(self) -> list[tuple[str, Path | None]]:
''',
        "Add destination folder selection handler",
    )

    source = replace_once(
        source,
        "            (name, path)\n            for name, path in MANUAL_DESTINATIONS.items()\n",
        "            (name, self.manual_destination_paths.get(name))\n"
        "            for name in MANUAL_DESTINATIONS\n",
        "Use selected target paths",
    )

    # 7. Perform a safe local write test and show inline results.
    source = replace_once(
        source,
        '    def _refresh_manual_status(self) -> None:\n'
        '        problem_states = {"SYNC FOLDER NOT DETECTED", "NETWORK VOLUME NOT MOUNTED", "SETUP REQUIRED - FOLDER NOT DETECTED", "LOCAL PARENT FOLDER NOT FOUND"}\n'
        '        for name, label in getattr(self, "manual_status_labels", {}).items():\n'
        '            status = self._destination_status(name)\n'
        '            label.configure(text=status, fg=COLORS["amber"] if status in problem_states else COLORS["blue"])\n'
        '        messagebox.showinfo(\n'
        '            "Path Status Updated",\n'
        '            "The local folder and network mount visibility check is complete. Cloud upload status and write permission have not been tested."\n'
        '        )\n',
        '''    def _refresh_manual_status(self):
        for name, label in getattr(self, "manual_status_labels", {}).items():
            target = self.manual_destination_paths.get(name)

            if target is None:
                label.configure(
                    text="FOLDER NOT DETECTED",
                    fg=COLORS["red"],
                )
                continue

            candidate = target.expanduser()

            while not candidate.exists() and candidate != candidate.parent:
                candidate = candidate.parent

            if not candidate.is_dir():
                label.configure(
                    text="PATH NOT AVAILABLE",
                    fg=COLORS["red"],
                )
                continue

            try:
                fd, test_path = tempfile.mkstemp(
                    prefix=".smartbackup_write_test_",
                    dir=str(candidate),
                )
                os.close(fd)
                os.remove(test_path)

                if name in {
                    "OneDrive",
                    "iCloud Drive",
                    "Google Drive",
                    "Dropbox",
                }:
                    label.configure(
                        text="LOCAL WRITE OK · CLOUD SYNC UNVERIFIED",
                        fg=COLORS["amber"],
                    )
                else:
                    label.configure(
                        text="LOCAL WRITE OK",
                        fg=COLORS["accent"],
                    )

            except OSError as exc:
                label.configure(
                    text=f"WRITE FAILED: {exc}",
                    fg=COLORS["red"],
                )
''',
        "Add safe local write test",
    )

    source = source.replace(
        'text="Select one or more destinations. A connection check will be added when the transfer engine is integrated.",',
        'text="Select destinations and choose the exact target folder on each drive. Local write checks do not prove remote cloud upload.",',
        1,
    )

    source = source.replace(
        'text="Read-only check only. Cloud sync and write permission are not verified.",',
        'text="Tests local folder write access only; remote cloud sync is not confirmed.",',
        1,
    )

    # Validate before writing. V3 and any existing V4 remain untouched.
    ast.parse(source, filename=str(OUTPUT_FILE))

    OUTPUT_FILE.write_text(source, encoding="utf-8")

    print("BUILD SUCCESS")
    print(f"SOURCE: {SOURCE_FILE}")
    print(f"OUTPUT: {OUTPUT_FILE}")
    print(f"OUTPUT SIZE: {OUTPUT_FILE.stat().st_size:,} bytes")
    print("VALIDATION: Python AST syntax check passed")
    print("V3 STATUS: Original V3 file was not modified")
    print(
        "NOTE: This build updates the interface and local destination checks. "
        "The real backup engine and remote cloud quota verification are separate next steps."
    )


if __name__ == "__main__":
    build()
