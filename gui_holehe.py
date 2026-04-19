import customtkinter as ctk
import csv
import json
import mimetypes
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from tkinter import filedialog, messagebox, simpledialog


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class HoleheApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("OSINT boite à outils - Holehe")
        self.geometry("1180x900")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.results_data = []
        self.filtered_data = []
        self.is_scanning = False
        self.sites_file_path = None
        self.wordlist_stats = None
        self.case_file_path = None
        self.case_attachments = []
        self.metadata_records = []
        self.analyst_id = ""
        self.last_run_summary = {}
        self.scan_failures = 0
        self.circuit_open_until = 0.0

        self.data_root = os.path.join(os.path.dirname(__file__), "investigations")
        self.cache_dir = os.path.join(self.data_root, "cache")
        os.makedirs(self.data_root, exist_ok=True)
        os.makedirs(self.cache_dir, exist_ok=True)

        self.setup_ui()
        self.show_authorization_warning()
        self.load_last_case_context()

    def setup_ui(self):
        self.grid_columnconfigure(0, weight=1)

        self.header_label = ctk.CTkLabel(
            self,
            text="HOLEHE OSINT WORKBENCH",
            font=("Segoe UI", 28, "bold"),
        )
        self.header_label.pack(pady=(16, 6))

        self.subtext = ctk.CTkLabel(
            self,
            text="Cadre autorise, investigation tracee, dashboard analyste",
            font=("Segoe UI", 12),
            text_color="gray",
        )
        self.subtext.pack(pady=(0, 10))

        self.case_frame = ctk.CTkFrame(self)
        self.case_frame.pack(pady=(0, 8), padx=16, fill="x")

        self.case_name_entry = ctk.CTkEntry(self.case_frame, placeholder_text="Dossier d'enquete", width=220, height=34)
        self.case_name_entry.grid(row=0, column=0, padx=6, pady=8)

        self.tags_entry = ctk.CTkEntry(self.case_frame, placeholder_text="Tags (fraude, vip)", width=220, height=34)
        self.tags_entry.grid(row=0, column=1, padx=6, pady=8)

        self.btn_save_case = ctk.CTkButton(self.case_frame, text="Sauver dossier", command=self.save_case, width=130)
        self.btn_save_case.grid(row=0, column=2, padx=6, pady=8)

        self.btn_load_case = ctk.CTkButton(self.case_frame, text="Charger dossier", command=self.load_case, width=130)
        self.btn_load_case.grid(row=0, column=3, padx=6, pady=8)

        self.btn_resume_run = ctk.CTkButton(self.case_frame, text="Reprendre dernier run", command=self.resume_last_run, width=170)
        self.btn_resume_run.grid(row=0, column=4, padx=6, pady=8)

        self.btn_attach = ctk.CTkButton(self.case_frame, text="Pieces jointes", command=self.attach_files, width=130)
        self.btn_attach.grid(row=0, column=5, padx=6, pady=8)

        self.btn_read_metadata = ctk.CTkButton(self.case_frame, text="Lire metadonnees", command=self.read_attachments_metadata, width=150)
        self.btn_read_metadata.grid(row=0, column=6, padx=6, pady=8)

        self.btn_export_metadata = ctk.CTkButton(self.case_frame, text="Exporter metadonnees", command=self.export_metadata, width=160)
        self.btn_export_metadata.grid(row=0, column=7, padx=6, pady=8)

        self.case_notes = ctk.CTkTextbox(self.case_frame, height=58)
        self.case_notes.grid(row=1, column=0, columnspan=8, sticky="ew", padx=6, pady=(0, 8))

        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.pack(pady=8, padx=16, fill="x")

        self.email_entry = ctk.CTkEntry(
            self.input_frame,
            placeholder_text="nom.cible@domaine.com",
            width=440,
            height=40,
        )
        self.email_entry.grid(row=0, column=0, padx=8, pady=10)
        self.email_entry.bind("<Return>", lambda e: self.start_scan())

        self.btn_scan = ctk.CTkButton(
            self.input_frame,
            text="LANCER LE SCAN",
            command=self.start_scan,
            font=("Segoe UI", 14, "bold"),
            height=40,
            fg_color="#2c3e50",
            hover_color="#34495e",
        )
        self.btn_scan.grid(row=0, column=1, padx=8)

        self.btn_diff_report = ctk.CTkButton(
            self.input_frame,
            text="Rapport diff runs",
            command=self.export_diff_report,
            fg_color="#4a235a",
            hover_color="#5b2c6f",
            height=40,
        )
        self.btn_diff_report.grid(row=0, column=2, padx=8)

        self.sites_entry = ctk.CTkEntry(
            self,
            placeholder_text="Limiter aux sites: google,github,spotify",
            width=1140,
            height=36,
        )
        self.sites_entry.pack(padx=16, pady=(0, 8))

        self.wordlist_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.wordlist_frame.pack(padx=16, pady=(0, 8), fill="x")

        self.btn_import_wordlist = ctk.CTkButton(
            self.wordlist_frame,
            text="Importer wordlist",
            command=self.import_wordlist,
            fg_color="#8e44ad",
            hover_color="#9b59b6",
            width=140,
        )
        self.btn_import_wordlist.pack(side="left")

        self.btn_export_valid = ctk.CTkButton(
            self.wordlist_frame,
            text="Exporter valides",
            command=self.export_valid_domains,
            state="disabled",
            fg_color="#1f8a70",
            hover_color="#2aa382",
            width=130,
        )
        self.btn_export_valid.pack(side="left", padx=8)

        self.btn_export_ignored = ctk.CTkButton(
            self.wordlist_frame,
            text="Exporter ignores",
            command=self.export_ignored_domains,
            state="disabled",
            fg_color="#d35400",
            hover_color="#e67e22",
            width=130,
        )
        self.btn_export_ignored.pack(side="left", padx=8)

        self.btn_export_parsing_errors = ctk.CTkButton(
            self.wordlist_frame,
            text="Exporter erreurs",
            command=self.export_parsing_errors,
            state="disabled",
            fg_color="#c0392b",
            hover_color="#e74c3c",
            width=130,
        )
        self.btn_export_parsing_errors.pack(side="left", padx=8)

        self.btn_export_bundle = ctk.CTkButton(
            self.wordlist_frame,
            text="Exporter bundle import",
            command=self.export_import_bundle,
            state="disabled",
            fg_color="#2980b9",
            hover_color="#3498db",
            width=170,
        )
        self.btn_export_bundle.pack(side="left", padx=8)

        self.wordlist_label = ctk.CTkLabel(
            self.wordlist_frame,
            text="Aucune wordlist chargee",
            text_color="gray",
        )
        self.wordlist_label.pack(side="left", padx=10)

        self.stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.stats_frame.pack(fill="x", padx=24)

        self.stat_confirmed = ctk.CTkLabel(self.stats_frame, text="Confirmes: 0", text_color="#2ecc71", font=("Segoe UI", 12, "bold"))
        self.stat_confirmed.pack(side="left", padx=6)

        self.stat_ambiguous = ctk.CTkLabel(self.stats_frame, text="Ambigus: 0", text_color="#f39c12", font=("Segoe UI", 12, "bold"))
        self.stat_ambiguous.pack(side="left", padx=6)

        self.stat_total = ctk.CTkLabel(self.stats_frame, text="Total: 0", font=("Segoe UI", 12))
        self.stat_total.pack(side="left", padx=6)

        self.show_only_found = ctk.CTkCheckBox(self.stats_frame, text="Seulement succes", font=("Segoe UI", 11), command=self.apply_filters)
        self.show_only_found.pack(side="right", padx=6)

        self.safe_mode = ctk.CTkCheckBox(self.stats_frame, text="Mode SAFE", font=("Segoe UI", 11))
        self.safe_mode.pack(side="right", padx=6)
        self.safe_mode.select()

        self.filter_frame = ctk.CTkFrame(self)
        self.filter_frame.pack(fill="x", padx=16, pady=(6, 6))

        self.status_filter = ctk.CTkOptionMenu(self.filter_frame, values=["all", "found", "warning", "not_found"], command=lambda _: self.apply_filters())
        self.status_filter.set("all")
        self.status_filter.grid(row=0, column=0, padx=6, pady=8)

        self.confidence_filter = ctk.CTkOptionMenu(self.filter_frame, values=["all", "high", "medium", "low"], command=lambda _: self.apply_filters())
        self.confidence_filter.set("all")
        self.confidence_filter.grid(row=0, column=1, padx=6, pady=8)

        self.date_filter = ctk.CTkOptionMenu(self.filter_frame, values=["all", "today"], command=lambda _: self.apply_filters())
        self.date_filter.set("all")
        self.date_filter.grid(row=0, column=2, padx=6, pady=8)

        self.source_filter_entry = ctk.CTkEntry(self.filter_frame, placeholder_text="Filtre source (ex: github)", width=240)
        self.source_filter_entry.grid(row=0, column=3, padx=6, pady=8)

        self.btn_apply_filters = ctk.CTkButton(self.filter_frame, text="Appliquer filtres", command=self.apply_filters, width=140)
        self.btn_apply_filters.grid(row=0, column=4, padx=6, pady=8)

        self.sort_field = ctk.CTkOptionMenu(self.filter_frame, values=["source", "status", "confidence", "ts"], width=120)
        self.sort_field.set("ts")
        self.sort_field.grid(row=0, column=5, padx=6, pady=8)

        self.sort_desc = ctk.CTkCheckBox(self.filter_frame, text="Desc", width=70)
        self.sort_desc.select()
        self.sort_desc.grid(row=0, column=6, padx=6, pady=8)

        self.btn_save_preset = ctk.CTkButton(self.filter_frame, text="Sauver preset", command=self.save_filter_preset, width=120)
        self.btn_save_preset.grid(row=0, column=7, padx=6, pady=8)

        self.btn_load_preset = ctk.CTkButton(self.filter_frame, text="Charger preset", command=self.load_filter_preset, width=120)
        self.btn_load_preset.grid(row=0, column=8, padx=6, pady=8)

        self.output_text = ctk.CTkTextbox(self, width=1140, height=360, font=("Courier New", 12))
        self.output_text.pack(pady=6, padx=16, fill="both", expand=True)

        self.setup_tags()

        self.progress_bar = ctk.CTkProgressBar(self, width=1120, mode="determinate")
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=8)

        self.action_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.action_frame.pack(pady=6, fill="x", padx=16)

        self.btn_export = ctk.CTkButton(
            self.action_frame,
            text="Exporter resultats",
            command=self.export_results,
            state="disabled",
            fg_color="#16a085",
        )
        self.btn_export.pack(side="left", padx=8)

        self.btn_report = ctk.CTkButton(
            self.action_frame,
            text="Rapport HTML",
            command=self.export_html_report,
            fg_color="#34495e",
        )
        self.btn_report.pack(side="left", padx=8)

        self.btn_report_pdf = ctk.CTkButton(
            self.action_frame,
            text="Rapport PDF",
            command=self.export_pdf_report,
            fg_color="#5d6d7e",
        )
        self.btn_report_pdf.pack(side="left", padx=8)

        self.btn_health = ctk.CTkButton(
            self.action_frame,
            text="Sante sources",
            command=self.show_sources_health,
            fg_color="#7d3c98",
        )
        self.btn_health.pack(side="left", padx=8)

        self.btn_clear = ctk.CTkButton(
            self.action_frame,
            text="Effacer",
            command=self.clear_logs,
            fg_color="#7f8c8d",
        )
        self.btn_clear.pack(side="right", padx=8)

    def setup_tags(self):
        self.output_text.tag_config("found", foreground="#2ecc71")
        self.output_text.tag_config("not_found", foreground="#e74c3c")
        self.output_text.tag_config("warning", foreground="#f1c40f")
        self.output_text.tag_config("header", foreground="#3498db")

    def show_authorization_warning(self):
        warning_text = (
            "Usage autorise uniquement.\n\n"
            "Vous confirmez disposer d'une autorisation explicite pour la cible "
            "et respecter les regles legales et internes."
        )
        accepted = messagebox.askyesno("Avertissement legal", warning_text)
        if not accepted:
            self.destroy()
            return

        analyst = simpledialog.askstring("Analyste", "Identifiant analyste:", parent=self)
        self.analyst_id = (analyst or "inconnu").strip() or "inconnu"

    def get_case_dir(self):
        case_name = self.case_name_entry.get().strip() or "default_case"
        safe_case = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in case_name)
        case_dir = os.path.join(self.data_root, safe_case)
        os.makedirs(case_dir, exist_ok=True)
        return case_dir

    def get_case_payload(self):
        return {
            "case_name": self.case_name_entry.get().strip(),
            "tags": self.tags_entry.get().strip(),
            "notes": self.case_notes.get("1.0", "end").strip(),
            "email": self.email_entry.get().strip(),
            "sites": self.sites_entry.get().strip(),
            "sites_file": self.sites_file_path,
            "attachments": self.case_attachments,
            "metadata_records": self.metadata_records,
            "safe_mode": bool(self.safe_mode.get()),
            "updated_at": utc_now_iso(),
            "analyst": self.analyst_id,
        }

    def save_case(self, silent=False):
        case_dir = self.get_case_dir()
        case_path = os.path.join(case_dir, "case.json")
        with open(case_path, "w", encoding="utf-8") as case_file:
            json.dump(self.get_case_payload(), case_file, ensure_ascii=False, indent=2)
        self.case_file_path = case_path
        self.save_last_case_context()
        if not silent:
            messagebox.showinfo("Dossier", "Dossier sauvegarde.")

    def load_case(self):
        case_path = filedialog.askopenfilename(
            title="Charger dossier",
            initialdir=self.data_root,
            filetypes=[("Case JSON", "*.json"), ("Tous les fichiers", "*")],
        )
        if not case_path:
            return
        self.apply_case_file(case_path, silent=False)

    def apply_case_file(self, case_path, silent=False):
        with open(case_path, "r", encoding="utf-8") as case_file:
            payload = json.load(case_file)

        self.case_name_entry.delete(0, "end")
        self.case_name_entry.insert(0, payload.get("case_name", ""))
        self.tags_entry.delete(0, "end")
        self.tags_entry.insert(0, payload.get("tags", ""))
        self.case_notes.delete("1.0", "end")
        self.case_notes.insert("1.0", payload.get("notes", ""))
        self.email_entry.delete(0, "end")
        self.email_entry.insert(0, payload.get("email", ""))
        self.sites_entry.delete(0, "end")
        self.sites_entry.insert(0, payload.get("sites", ""))

        self.case_attachments = payload.get("attachments", [])
        self.metadata_records = payload.get("metadata_records", [])
        self.sites_file_path = payload.get("sites_file")
        self.case_file_path = case_path

        if payload.get("safe_mode", True):
            self.safe_mode.select()
        else:
            self.safe_mode.deselect()

        if self.sites_file_path and os.path.exists(self.sites_file_path):
            try:
                self.wordlist_stats = self.inspect_wordlist(self.sites_file_path)
                self.update_wordlist_ui(self.wordlist_stats)
            except Exception:
                self.wordlist_stats = None

        self.save_last_case_context()
        if not silent:
            messagebox.showinfo("Dossier", "Dossier charge.")

    def save_last_case_context(self):
        path = os.path.join(self.data_root, "last_case.json")
        payload = {"case_file": self.case_file_path, "saved_at": utc_now_iso()}
        with open(path, "w", encoding="utf-8") as context_file:
            json.dump(payload, context_file, ensure_ascii=False, indent=2)

    def load_last_case_context(self):
        path = os.path.join(self.data_root, "last_case.json")
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as context_file:
                payload = json.load(context_file)
            case_file = payload.get("case_file")
            if case_file and os.path.exists(case_file):
                self.apply_case_file(case_file, silent=True)
        except Exception:
            return

    def attach_files(self):
        files = filedialog.askopenfilenames(title="Selectionner des pieces jointes")
        if not files:
            return
        for item in files:
            if item not in self.case_attachments:
                self.case_attachments.append(item)
        messagebox.showinfo("Pieces jointes", f"{len(self.case_attachments)} piece(s) rattachee(s) au dossier.")

    def sha256_file(self, file_path):
        import hashlib

        digest = hashlib.sha256()
        with open(file_path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def sha256_json(self, payload):
        import hashlib

        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def read_attachments_metadata(self):
        if not self.case_attachments:
            messagebox.showinfo("Metadonnees", "Aucune piece jointe dans le dossier.")
            return

        records = []
        errors = []
        for path in self.case_attachments:
            if not os.path.exists(path):
                errors.append({"path": path, "error": "file_not_found"})
                continue
            try:
                stat = os.stat(path)
                mime_type, _ = mimetypes.guess_type(path)
                record = {
                    "file_name": os.path.basename(path),
                    "file_path": path,
                    "extension": os.path.splitext(path)[1].lower(),
                    "mime_type": mime_type or "application/octet-stream",
                    "size_bytes": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                    "accessed_at": datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                    "sha256": self.sha256_file(path),
                }
                records.append(record)
            except Exception as exc:
                errors.append({"path": path, "error": str(exc)})

        self.metadata_records = records
        self.log_event("metadata_scan", {"records": len(records), "errors": errors})
        self.output_text.insert("end", f"[Metadata] fichiers analyses: {len(records)}, erreurs: {len(errors)}\n", "header")
        for rec in records[:10]:
            line = f"[Metadata] {rec['file_name']} | {rec['mime_type']} | {rec['size_bytes']} octets | {rec['sha256'][:16]}...\n"
            self.output_text.insert("end", line, "header")
        self.output_text.see("end")
        messagebox.showinfo("Metadonnees", f"Lecture terminee: {len(records)} fichier(s), {len(errors)} erreur(s).")

    def export_metadata(self):
        if not self.metadata_records:
            messagebox.showinfo("Export", "Aucune metadonnee disponible. Lance d'abord la lecture.")
            return

        export_format = simpledialog.askstring("Export metadonnees", "Format (json/csv):", parent=self)
        if not export_format:
            return
        export_format = export_format.strip().lower()
        if export_format not in {"json", "csv"}:
            messagebox.showwarning("Export", "Format invalide, utilise json ou csv.")
            return

        if export_format == "json":
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON", "*.json"), ("Tous les fichiers", "*")],
                initialfile="metadonnees_pieces_jointes.json",
            )
            if not file_path:
                return
            with open(file_path, "w", encoding="utf-8") as out:
                json.dump(self.metadata_records, out, ensure_ascii=False, indent=2)
        else:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV", "*.csv"), ("Tous les fichiers", "*")],
                initialfile="metadonnees_pieces_jointes.csv",
            )
            if not file_path:
                return
            headers = [
                "file_name",
                "file_path",
                "extension",
                "mime_type",
                "size_bytes",
                "created_at",
                "modified_at",
                "accessed_at",
                "sha256",
            ]
            with open(file_path, "w", encoding="utf-8", newline="") as out:
                writer = csv.DictWriter(out, fieldnames=headers)
                writer.writeheader()
                writer.writerows(self.metadata_records)

        self.log_event("metadata_export", {"format": export_format, "count": len(self.metadata_records)})
        messagebox.showinfo("Export", f"Metadonnees exportees ({len(self.metadata_records)} fichier(s)).")

    def log_event(self, event_type, payload):
        log_path = os.path.join(self.data_root, "activity_log.jsonl")
        data = {
            "ts": utc_now_iso(),
            "event": event_type,
            "analyst": self.analyst_id,
            "case": self.case_name_entry.get().strip() or "default_case",
            "scope": {
                "email": self.email_entry.get().strip(),
                "sites": self.sites_entry.get().strip(),
                "sites_file": self.sites_file_path,
            },
            "payload": payload,
        }
        with open(log_path, "a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(data, ensure_ascii=False) + "\n")

    def resolve_local_core_path(self):
        return os.path.join(os.path.dirname(__file__), "holehe", "holehe", "core.py")

    def build_holehe_command(self, extra_args):
        local_core = self.resolve_local_core_path()
        if os.path.exists(local_core):
            return [sys.executable, local_core, *extra_args]
        venv_path = os.path.join(os.path.dirname(sys.executable), "holehe")
        cmd = venv_path if os.path.exists(venv_path) else "holehe"
        return [cmd, *extra_args]

    def inspect_wordlist(self, file_path):
        command = self.build_holehe_command(["--inspect-sites-file", file_path])
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if process.returncode != 0:
            raise RuntimeError(process.stdout.strip() or "Analyse de wordlist impossible")
        return json.loads(process.stdout.strip())

    def score_confidence(self, status):
        if status == "found":
            return "high"
        if status == "warning":
            return "medium"
        return "low"

    def parse_output_line(self, line):
        raw = (line or "").rstrip("\n")
        if not raw.strip():
            return None

        # Defensive: strip ANSI escape sequences if any (some terminals/tools still inject them).
        cleaned = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw).strip()
        match = re.match(r"^\[(\+|-|\?|x|!)\]\s*(\S+)(.*)$", cleaned)
        if not match:
            return None

        marker = match.group(1)
        source = match.group(2).strip()
        details = match.group(3).strip()

        if marker == "+":
            return {
                "source": source,
                "status": "found",
                "confidence": "high",
                "reason": "exists_signal",
                "evidence_type": "account_match",
                "details": details,
                "raw": cleaned,
                "ts": utc_now_iso(),
            }
        if marker == "-":
            return {
                "source": source,
                "status": "not_found",
                "confidence": "low",
                "reason": "negative_signal",
                "evidence_type": "account_check",
                "details": details,
                "raw": cleaned,
                "ts": utc_now_iso(),
            }

        reason = "rate_limit" if marker == "x" else "module_error"
        return {
            "source": source,
            "status": "warning",
            "confidence": "medium",
            "reason": reason,
            "evidence_type": "execution_warning",
            "details": details,
            "raw": cleaned,
            "ts": utc_now_iso(),
        }

    def dedupe_results(self, data):
        seen = set()
        deduped = []
        for item in data:
            key = (item.get("source"), item.get("status"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    def build_cache_key(self, email, sites_raw, sites_file_path):
        file_hint = ""
        if sites_file_path and os.path.exists(sites_file_path):
            file_hint = f"{sites_file_path}:{int(os.path.getmtime(sites_file_path))}"
        payload = {
            "cache_version": 2,
            "email": email,
            "sites": sites_raw,
            "sites_file": file_hint,
            "safe_mode": bool(self.safe_mode.get()),
        }
        return self.sha256_json(payload)

    def cache_path_for_key(self, key):
        return os.path.join(self.cache_dir, f"{key}.json")

    def load_cached_run(self, key):
        path = self.cache_path_for_key(key)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as cache_file:
                data = json.load(cache_file)
            results = data.get("results") if isinstance(data, dict) else None
            if isinstance(results, list) and results:
                # Backward-compat: old parser bug produced empty sources; ignore those caches.
                if any((item.get("status") in {"found", "warning", "not_found"}) and not item.get("source") for item in results if isinstance(item, dict)):
                    return None
            return data
        except Exception:
            return None

    def save_cached_run(self, key, payload):
        path = self.cache_path_for_key(key)
        with open(path, "w", encoding="utf-8") as cache_file:
            json.dump(payload, cache_file, ensure_ascii=False, indent=2)

    def start_scan(self):
        now_ts = time.time()
        if now_ts < self.circuit_open_until:
            remaining = int(self.circuit_open_until - now_ts)
            messagebox.showwarning("Circuit breaker", f"Scan temporairement bloque ({remaining}s restantes) apres erreurs consecutives.")
            return

        email = self.email_entry.get().strip()
        if not email or "@" not in email:
            messagebox.showwarning("Erreur", "Veuillez entrer une adresse email valide.")
            return

        sites_raw = self.sites_entry.get().strip()
        if self.wordlist_stats and self.wordlist_stats.get("mapped_modules", 0) == 0:
            messagebox.showwarning("Wordlist vide pour Holehe", "Aucun domaine de la wordlist ne correspond aux modules disponibles.")
            return

        if self.safe_mode.get() and self.wordlist_stats and self.wordlist_stats.get("mapped_modules", 0) > 100:
            messagebox.showwarning("Mode SAFE", "Le mode SAFE limite le perimetre a 100 modules max.")
            return

        cache_key = self.build_cache_key(email, sites_raw, self.sites_file_path)
        cached = self.load_cached_run(cache_key)
        if cached:
            self.results_data = cached.get("results", [])
            self.last_run_summary = cached.get("summary", {})
            self.render_results_with_filters()
            self.update_dashboard_metrics()
            self.log_event("cache_hit", {"cache_key": cache_key, "items": len(self.results_data)})
            return

        self.is_scanning = True
        self.results_data = []
        self.filtered_data = []
        self.btn_scan.configure(state="disabled")
        self.btn_export.configure(state="disabled")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("end", f">>> DEBUT ANALYSE : {email}\n", "header")

        self.log_event(
            "scan_started",
            {
                "safe_mode": bool(self.safe_mode.get()),
                "wordlist_stats": self.wordlist_stats or {},
                "cache_key": cache_key,
            },
        )
        self.save_case(silent=True)

        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()

        threading.Thread(
            target=self.execute_holehe,
            args=(email, sites_raw, self.sites_file_path, cache_key),
            daemon=True,
        ).start()

    def execute_holehe(self, email, sites_raw, sites_file_path, cache_key):
        count_total = 0
        raw_output_lines = []
        started_at = utc_now_iso()

        try:
            command = self.build_holehe_command([email, "--no-color"])
            if sites_raw:
                command.extend(["--sites", sites_raw])
            if sites_file_path:
                command.extend(["--sites-file", sites_file_path])
            if self.safe_mode.get():
                command.extend(["--timeout", "6", "--no-password-recovery"])

            max_attempts = 2
            process = None
            for attempt in range(1, max_attempts + 1):
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )

                for line in process.stdout:
                    raw_output_lines.append(line.rstrip("\n"))
                    parsed = self.parse_output_line(line)
                    if not parsed:
                        continue
                    count_total += 1
                    self.results_data.append(parsed)
                    self.after(0, self.update_dashboard_metrics)

                process.wait()
                if process.returncode == 0:
                    break
                if attempt < max_attempts:
                    raw_output_lines.append(f"[!] retry {attempt}/{max_attempts - 1} apres echec code={process.returncode}")
                    time.sleep(1.5 * attempt)

            if process is None:
                raise RuntimeError("Execution impossible")
            self.results_data = self.dedupe_results(self.results_data)
            found_count = sum(1 for item in self.results_data if item.get("status") == "found")

            self.last_run_summary = {
                "return_code": process.returncode,
                "found": found_count,
                "tested": count_total,
                "safe_mode": bool(self.safe_mode.get()),
                "command": command,
                "output_lines": raw_output_lines,
                "started_at": started_at,
                "finished_at": utc_now_iso(),
            }

            self.save_cached_run(cache_key, {"results": self.results_data, "summary": self.last_run_summary})
            if process.returncode == 0:
                self.scan_failures = 0
            else:
                self.scan_failures += 1
                if self.scan_failures >= 3:
                    self.circuit_open_until = time.time() + 120
            self.after(0, self.finalize_scan)
        except Exception as exc:
            self.scan_failures += 1
            if self.scan_failures >= 3:
                self.circuit_open_until = time.time() + 120
            self.after(0, lambda: self.output_text.insert("end", f"\n[!] Erreur: {str(exc)}\n", "warning"))
        finally:
            self.after(0, self.progress_bar.stop)
            self.after(0, lambda: self.progress_bar.set(1))

    def finalize_scan(self):
        self.is_scanning = False
        self.btn_scan.configure(state="normal")
        self.btn_export.configure(state="normal")
        self.render_results_with_filters()
        self.persist_run_history()

    def update_dashboard_metrics(self):
        confirmed = sum(1 for item in self.results_data if item.get("status") == "found")
        ambiguous = sum(1 for item in self.results_data if item.get("status") == "warning")
        total = len(self.results_data)
        self.stat_confirmed.configure(text=f"Confirmes: {confirmed}")
        self.stat_ambiguous.configure(text=f"Ambigus: {ambiguous}")
        self.stat_total.configure(text=f"Total: {total}")

    def apply_filters(self):
        self.render_results_with_filters()

    def get_filter_preset_payload(self):
        return {
            "status_filter": self.status_filter.get(),
            "confidence_filter": self.confidence_filter.get(),
            "date_filter": self.date_filter.get(),
            "source_filter": self.source_filter_entry.get().strip(),
            "show_only_found": bool(self.show_only_found.get()),
            "sort_field": self.sort_field.get(),
            "sort_desc": bool(self.sort_desc.get()),
        }

    def apply_filter_preset_payload(self, payload):
        self.status_filter.set(payload.get("status_filter", "all"))
        self.confidence_filter.set(payload.get("confidence_filter", "all"))
        self.date_filter.set(payload.get("date_filter", "all"))

        self.source_filter_entry.delete(0, "end")
        self.source_filter_entry.insert(0, payload.get("source_filter", ""))

        if payload.get("show_only_found", False):
            self.show_only_found.select()
        else:
            self.show_only_found.deselect()

        self.sort_field.set(payload.get("sort_field", "ts"))
        if payload.get("sort_desc", True):
            self.sort_desc.select()
        else:
            self.sort_desc.deselect()

    def save_filter_preset(self):
        name = simpledialog.askstring("Preset", "Nom du preset:", parent=self)
        if not name:
            return
        case_dir = self.get_case_dir()
        preset_path = os.path.join(case_dir, "filter_presets.json")
        presets = {}
        if os.path.exists(preset_path):
            try:
                with open(preset_path, "r", encoding="utf-8") as stream:
                    presets = json.load(stream)
            except Exception:
                presets = {}
        presets[name.strip()] = self.get_filter_preset_payload()
        with open(preset_path, "w", encoding="utf-8") as stream:
            json.dump(presets, stream, ensure_ascii=False, indent=2)
        messagebox.showinfo("Preset", "Preset sauvegarde.")

    def load_filter_preset(self):
        case_dir = self.get_case_dir()
        preset_path = os.path.join(case_dir, "filter_presets.json")
        if not os.path.exists(preset_path):
            messagebox.showinfo("Preset", "Aucun preset dans ce dossier.")
            return
        with open(preset_path, "r", encoding="utf-8") as stream:
            presets = json.load(stream)
        names = sorted(presets.keys())
        if not names:
            messagebox.showinfo("Preset", "Aucun preset disponible.")
            return
        selected = simpledialog.askstring("Preset", f"Choisir preset:\n{', '.join(names)}", parent=self)
        if not selected or selected.strip() not in presets:
            return
        self.apply_filter_preset_payload(presets[selected.strip()])
        self.render_results_with_filters()

    def render_results_with_filters(self):
        status_filter = self.status_filter.get()
        conf_filter = self.confidence_filter.get()
        date_filter = self.date_filter.get()
        source_filter = self.source_filter_entry.get().strip().lower()

        today_prefix = datetime.now(timezone.utc).date().isoformat()

        filtered = []
        for item in self.results_data:
            if self.show_only_found.get() and item.get("status") != "found":
                continue
            if status_filter != "all" and item.get("status") != status_filter:
                continue
            if conf_filter != "all" and item.get("confidence") != conf_filter:
                continue
            if source_filter and source_filter not in item.get("source", "").lower():
                continue
            if date_filter == "today" and not item.get("ts", "").startswith(today_prefix):
                continue
            filtered.append(item)

        sort_field = self.sort_field.get()
        reverse = bool(self.sort_desc.get())
        filtered = sorted(filtered, key=lambda i: str(i.get(sort_field, "")), reverse=reverse)

        self.filtered_data = filtered

        self.output_text.delete("1.0", "end")
        self.output_text.insert("end", "=== DASHBOARD RESULTATS ===\n", "header")
        self.output_text.insert("end", f"Items affiches: {len(filtered)} / {len(self.results_data)}\n\n", "header")

        for item in filtered:
            status = item.get("status")
            conf = item.get("confidence")
            src = item.get("source")
            ts = item.get("ts")
            line = f"[{status}] {src:<30} | conf={conf:<6} | {ts}\n"
            tag = "found" if status == "found" else "warning" if status == "warning" else "not_found"
            self.output_text.insert("end", line, tag)

        self.output_text.see("end")
        self.update_dashboard_metrics()

    def persist_run_history(self):
        case_dir = self.get_case_dir()
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_path = os.path.join(case_dir, f"run_{run_id}.json")

        payload = {
            "run_id": run_id,
            "results": self.results_data,
            "summary": self.last_run_summary,
            "wordlist": self.wordlist_stats,
            "case": self.get_case_payload(),
            "metrics": {
                "confirmed": sum(1 for item in self.results_data if item.get("status") == "found"),
                "ambiguous": sum(1 for item in self.results_data if item.get("status") == "warning"),
                "total": len(self.results_data),
            },
        }
        with open(run_path, "w", encoding="utf-8") as run_file:
            json.dump(payload, run_file, ensure_ascii=False, indent=2)

        index_path = os.path.join(case_dir, "runs.jsonl")
        with open(index_path, "a", encoding="utf-8") as index_file:
            index_file.write(json.dumps({"run_id": run_id, "file": run_path, "ts": utc_now_iso()}, ensure_ascii=False) + "\n")

        metrics_path = os.path.join(self.data_root, "metrics.jsonl")
        with open(metrics_path, "a", encoding="utf-8") as metrics_file:
            metrics_file.write(
                json.dumps(
                    {
                        "ts": utc_now_iso(),
                        "case": self.case_name_entry.get().strip() or "default_case",
                        "return_code": self.last_run_summary.get("return_code"),
                        "tested": self.last_run_summary.get("tested", 0),
                        "found": self.last_run_summary.get("found", 0),
                        "safe_mode": self.last_run_summary.get("safe_mode", False),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

        self.detect_behavior_alert(case_dir)
        self.log_event(
            "scan_finished",
            {
                "run_id": run_id,
                "result_count": len(self.results_data),
                "found_count": sum(1 for item in self.results_data if item.get("status") == "found"),
                "return_code": self.last_run_summary.get("return_code"),
            },
        )

    def detect_behavior_alert(self, case_dir):
        runs = self.list_case_runs(case_dir)
        if len(runs) < 2:
            return
        latest = runs[-1]
        previous = runs[-2]
        latest_found = latest.get("metrics", {}).get("confirmed", 0)
        prev_found = previous.get("metrics", {}).get("confirmed", 0)
        if abs(latest_found - prev_found) >= 10:
            self.log_event(
                "alert_behavior_shift",
                {
                    "latest_run": latest.get("run_id"),
                    "previous_run": previous.get("run_id"),
                    "prev_found": prev_found,
                    "latest_found": latest_found,
                },
            )

    def list_case_runs(self, case_dir=None):
        directory = case_dir or self.get_case_dir()
        run_files = [
            os.path.join(directory, item)
            for item in os.listdir(directory)
            if item.startswith("run_") and item.endswith(".json")
        ]
        runs = []
        for path in sorted(run_files):
            try:
                with open(path, "r", encoding="utf-8") as run_file:
                    runs.append(json.load(run_file))
            except Exception:
                continue
        return runs

    def resume_last_run(self):
        runs = self.list_case_runs()
        if not runs:
            messagebox.showinfo("Reprise", "Aucun run precedent dans ce dossier.")
            return
        latest = runs[-1]
        self.results_data = latest.get("results", [])
        self.last_run_summary = latest.get("summary", {})
        self.render_results_with_filters()
        messagebox.showinfo("Reprise", "Dernier run recharge avec succes.")

    def update_wordlist_ui(self, stats):
        summary = (
            f"{os.path.basename(self.sites_file_path or '')} | total: {stats.get('total_input_lines', 0)} | "
            f"valides: {stats.get('valid_lines', 0)} | invalides: {stats.get('invalid_lines', 0)} | "
            f"ignores: {stats.get('ignored_lines', 0)} | doublons: {stats.get('duplicate_lines', 0)} | "
            f"mappes: {stats.get('mapped_modules', 0)}"
        )
        self.wordlist_label.configure(text=summary)

        self.output_text.insert("end", "[Wordlist] " + summary + "\n", "header")
        preview = ", ".join(stats.get("normalized_preview", [])[:10])
        if preview:
            self.output_text.insert("end", f"[Wordlist] Preview normalisee (10): {preview}\n", "header")

        if stats.get("ignored_sample"):
            sample = ", ".join(stats["ignored_sample"][:5])
            self.output_text.insert("end", f"[Wordlist] Exemples ignores: {sample}\n", "warning")

        if stats.get("parsing_errors"):
            first_error = stats["parsing_errors"][0]
            self.output_text.insert(
                "end",
                f"[Wordlist] Exemple erreur: ligne {first_error.get('line')} ({first_error.get('reason')}) -> {first_error.get('raw')}\n",
                "warning",
            )

        self.btn_export_ignored.configure(state="normal" if stats.get("ignored_list") else "disabled")
        self.btn_export_parsing_errors.configure(state="normal" if stats.get("parsing_errors") else "disabled")
        self.btn_export_valid.configure(state="normal" if stats.get("valid_list") else "disabled")
        self.btn_export_bundle.configure(state="normal")
        self.output_text.see("end")

    def import_wordlist(self):
        file_path = filedialog.askopenfilename(
            title="Choisir une wordlist de domaines",
            filetypes=[("Wordlists", "*.txt *.rtf"), ("Fichiers texte", "*.txt"), ("Rich Text Format", "*.rtf"), ("Tous les fichiers", "*")],
        )
        if not file_path:
            return

        try:
            stats = self.inspect_wordlist(file_path)
            self.sites_file_path = file_path
            self.wordlist_stats = stats
            self.update_wordlist_ui(stats)
        except Exception as exc:
            self.sites_file_path = None
            self.wordlist_stats = None
            self.wordlist_label.configure(text="Aucune wordlist chargee")
            self.btn_export_ignored.configure(state="disabled")
            self.btn_export_parsing_errors.configure(state="disabled")
            self.btn_export_valid.configure(state="disabled")
            self.btn_export_bundle.configure(state="disabled")
            messagebox.showerror("Erreur wordlist", str(exc))

    def export_valid_domains(self):
        if not self.wordlist_stats or not self.wordlist_stats.get("valid_list"):
            messagebox.showinfo("Export", "Aucune entree valide a exporter.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*")],
            initialfile="domaines_valides.txt",
        )
        if not file_path:
            return
        with open(file_path, "w", encoding="utf-8") as output_file:
            for entry in self.wordlist_stats.get("valid_list", []):
                output_file.write(entry + "\n")
        messagebox.showinfo("Export", f"{len(self.wordlist_stats.get('valid_list', []))} entrees valides exportees.")

    def export_ignored_domains(self):
        if not self.wordlist_stats or not self.wordlist_stats.get("ignored_list"):
            messagebox.showinfo("Export", "Aucun domaine ignore a exporter.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*")],
            initialfile="domaines_ignores.txt",
        )
        if not file_path:
            return
        with open(file_path, "w", encoding="utf-8") as output_file:
            for domain in self.wordlist_stats.get("ignored_list", []):
                output_file.write(domain + "\n")
        messagebox.showinfo("Export", f"{len(self.wordlist_stats.get('ignored_list', []))} domaines ignores exportes.")

    def export_parsing_errors(self):
        if not self.wordlist_stats or not self.wordlist_stats.get("parsing_errors"):
            messagebox.showinfo("Export", "Aucune erreur de parsing a exporter.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Fichiers CSV", "*.csv"), ("Fichiers texte", "*.txt"), ("Tous les fichiers", "*")],
            initialfile="erreurs_wordlist.csv",
        )
        if not file_path:
            return
        with open(file_path, "w", encoding="utf-8") as output_file:
            output_file.write("line,reason,raw,normalized\n")
            for error in self.wordlist_stats.get("parsing_errors", []):
                raw = str(error.get("raw", "")).replace('"', '""')
                normalized = str(error.get("normalized", "")).replace('"', '""')
                output_file.write(f"{error.get('line', '')},{error.get('reason', '')},\"{raw}\",\"{normalized}\"\n")
        messagebox.showinfo("Export", f"{len(self.wordlist_stats.get('parsing_errors', []))} erreurs exportees.")

    def export_import_bundle(self):
        if not self.wordlist_stats:
            messagebox.showinfo("Export", "Importe d'abord une wordlist.")
            return
        target_dir = filedialog.askdirectory(title="Choisir le dossier de sortie")
        if not target_dir:
            return

        valid_path = os.path.join(target_dir, "wordlist_valides.txt")
        ignored_path = os.path.join(target_dir, "wordlist_ignores.txt")
        errors_path = os.path.join(target_dir, "wordlist_erreurs.csv")

        with open(valid_path, "w", encoding="utf-8") as valid_file:
            for entry in self.wordlist_stats.get("valid_list", []):
                valid_file.write(entry + "\n")

        with open(ignored_path, "w", encoding="utf-8") as ignored_file:
            for entry in self.wordlist_stats.get("ignored_list", []):
                ignored_file.write(entry + "\n")

        with open(errors_path, "w", encoding="utf-8") as error_file:
            error_file.write("line,reason,raw,normalized\n")
            for error in self.wordlist_stats.get("parsing_errors", []):
                raw = str(error.get("raw", "")).replace('"', '""')
                normalized = str(error.get("normalized", "")).replace('"', '""')
                error_file.write(f"{error.get('line', '')},{error.get('reason', '')},\"{raw}\",\"{normalized}\"\n")

        messagebox.showinfo("Export", "Bundle import exporte: valides, ignores, erreurs.")

    def export_results(self):
        if not self.filtered_data:
            messagebox.showinfo("Export", "Aucun resultat filtre a exporter.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".json")
        if not file_path:
            return
        with open(file_path, "w", encoding="utf-8") as output_file:
            json.dump(self.filtered_data, output_file, ensure_ascii=False, indent=2)
        messagebox.showinfo("Export", "Resultats exportes.")

    def export_html_report(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("Rapport HTML", "*.html"), ("Tous les fichiers", "*")],
            initialfile="rapport_enquete.html",
        )
        if not file_path:
            return

        found_count = sum(1 for item in self.filtered_data if item.get("status") == "found")
        total_count = len(self.filtered_data)
        rows = "\n".join(
            f"<tr><td>{item.get('source', '')}</td><td>{item.get('status', '')}</td><td>{item.get('confidence', '')}</td><td>{item.get('ts', '')}</td></tr>"
            for item in self.filtered_data
        )

        import hashlib

        report_hash = hashlib.sha256(
            json.dumps(self.filtered_data, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()

        html = f"""
<!doctype html>
<html lang=\"fr\">
<head>
  <meta charset=\"utf-8\" />
  <title>Rapport Enquete</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #f6f8fb; color: #1e293b; }}
    .card {{ background: white; padding: 16px; border-radius: 10px; margin-bottom: 16px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; font-size: 12px; }}
    th {{ background: #eef2ff; }}
  </style>
</head>
<body>
  <div class=\"card\">
    <h2>Resume Executif</h2>
    <p><b>Dossier:</b> {self.case_name_entry.get().strip() or 'default_case'}</p>
    <p><b>Analyste:</b> {self.analyst_id}</p>
    <p><b>Cible:</b> {self.email_entry.get().strip()}</p>
    <p><b>Safe mode:</b> {'active' if self.safe_mode.get() else 'desactive'}</p>
    <p><b>Signaux confirmes:</b> {found_count} / {total_count}</p>
    <p><b>Horodatage:</b> {utc_now_iso()}</p>
  </div>
  <div class=\"card\">
    <h3>Traceabilite</h3>
    <p><b>Wordlist:</b> {self.sites_file_path or 'aucune'}</p>
    <p><b>Hash rapport:</b> {report_hash}</p>
  </div>
  <div class=\"card\">
    <h3>Annexe Technique</h3>
    <table>
      <thead><tr><th>Source</th><th>Status</th><th>Confiance</th><th>Horodatage</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
""".strip()

        with open(file_path, "w", encoding="utf-8") as report_file:
            report_file.write(html)

        messagebox.showinfo("Rapport", "Rapport HTML genere.")

    def export_pdf_report(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("Rapport PDF", "*.pdf"), ("Tous les fichiers", "*")],
            initialfile="rapport_enquete.pdf",
        )
        if not file_path:
            return

        try:
            import importlib
            pagesizes = importlib.import_module("reportlab.lib.pagesizes")
            canvas_module = importlib.import_module("reportlab.pdfgen.canvas")
            A4 = pagesizes.A4
            canvas = canvas_module
        except Exception:
            fallback = file_path.replace(".pdf", ".txt")
            with open(fallback, "w", encoding="utf-8") as stream:
                stream.write("reportlab non installe. Export fallback texte.\n")
                stream.write(json.dumps(self.filtered_data, ensure_ascii=False, indent=2))
            messagebox.showwarning("PDF", f"reportlab indisponible. Fallback cree: {os.path.basename(fallback)}")
            return

        found_count = sum(1 for item in self.filtered_data if item.get("status") == "found")
        pdf = canvas.Canvas(file_path, pagesize=A4)
        width, height = A4
        y = height - 40
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(40, y, "Rapport Enquete")
        y -= 24
        pdf.setFont("Helvetica", 10)
        pdf.drawString(40, y, f"Dossier: {self.case_name_entry.get().strip() or 'default_case'}")
        y -= 14
        pdf.drawString(40, y, f"Analyste: {self.analyst_id}")
        y -= 14
        pdf.drawString(40, y, f"Signaux confirmes: {found_count} / {len(self.filtered_data)}")
        y -= 20
        pdf.setFont("Helvetica-Bold", 10)
        pdf.drawString(40, y, "Source")
        pdf.drawString(220, y, "Status")
        pdf.drawString(300, y, "Confiance")
        pdf.drawString(390, y, "Raison")
        y -= 12
        pdf.setFont("Helvetica", 9)
        for item in self.filtered_data[:120]:
            if y < 40:
                pdf.showPage()
                y = height - 40
                pdf.setFont("Helvetica", 9)
            pdf.drawString(40, y, str(item.get("source", ""))[:28])
            pdf.drawString(220, y, str(item.get("status", "")))
            pdf.drawString(300, y, str(item.get("confidence", "")))
            pdf.drawString(390, y, str(item.get("reason", ""))[:28])
            y -= 11
        pdf.save()
        messagebox.showinfo("PDF", "Rapport PDF genere.")

    def pick_two_runs(self):
        first = filedialog.askopenfilename(
            title="Choisir run A",
            initialdir=self.get_case_dir(),
            filetypes=[("Run JSON", "run_*.json"), ("JSON", "*.json")],
        )
        if not first:
            return None, None
        second = filedialog.askopenfilename(
            title="Choisir run B",
            initialdir=self.get_case_dir(),
            filetypes=[("Run JSON", "run_*.json"), ("JSON", "*.json")],
        )
        if not second:
            return None, None
        return first, second

    def export_diff_report(self):
        run_a_path, run_b_path = self.pick_two_runs()
        if not run_a_path or not run_b_path:
            return

        with open(run_a_path, "r", encoding="utf-8") as file_a:
            run_a = json.load(file_a)
        with open(run_b_path, "r", encoding="utf-8") as file_b:
            run_b = json.load(file_b)

        map_a = {item.get("source"): item.get("status") for item in run_a.get("results", []) if item.get("source")}
        map_b = {item.get("source"): item.get("status") for item in run_b.get("results", []) if item.get("source")}

        set_a = set(map_a.keys())
        set_b = set(map_b.keys())
        added_sources = sorted(list(set_b - set_a))
        removed_sources = sorted(list(set_a - set_b))
        changed = sorted([
            (source, map_a[source], map_b[source])
            for source in (set_a & set_b)
            if map_a[source] != map_b[source]
        ])

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("Rapport HTML", "*.html"), ("Tous les fichiers", "*")],
            initialfile="rapport_diff_runs.html",
        )
        if not file_path:
            return

        added_rows = "\n".join(f"<tr><td>{src}</td><td>{map_b.get(src, '')}</td></tr>" for src in added_sources)
        removed_rows = "\n".join(f"<tr><td>{src}</td><td>{map_a.get(src, '')}</td></tr>" for src in removed_sources)
        changed_rows = "\n".join(f"<tr><td>{src}</td><td>{old}</td><td>{new}</td></tr>" for src, old, new in changed)

        html = f"""
<!doctype html>
<html lang=\"fr\">
<head>
  <meta charset=\"utf-8\" />
  <title>Diff Runs</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #f7f8fa; }}
    .card {{ background: white; padding: 16px; border-radius: 10px; margin-bottom: 16px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; font-size: 12px; }}
    th {{ background: #eef2ff; }}
  </style>
</head>
<body>
  <div class=\"card\">
    <h2>Diff Runs</h2>
    <p><b>Run A:</b> {os.path.basename(run_a_path)}</p>
    <p><b>Run B:</b> {os.path.basename(run_b_path)}</p>
    <p><b>Nouveaux signaux:</b> {len(added_sources)} | <b>Disparus:</b> {len(removed_sources)} | <b>Statut change:</b> {len(changed)}</p>
  </div>
  <div class=\"card\">
    <h3>Nouveaux signaux</h3>
    <table><thead><tr><th>Source</th><th>Status</th></tr></thead><tbody>{added_rows}</tbody></table>
  </div>
    <div class="card">
        <h3>Statut modifie</h3>
        <table><thead><tr><th>Source</th><th>Ancien</th><th>Nouveau</th></tr></thead><tbody>{changed_rows}</tbody></table>
    </div>
  <div class=\"card\">
    <h3>Signaux disparus</h3>
    <table><thead><tr><th>Source</th><th>Status</th></tr></thead><tbody>{removed_rows}</tbody></table>
  </div>
</body>
</html>
""".strip()

        with open(file_path, "w", encoding="utf-8") as report_file:
            report_file.write(html)

        messagebox.showinfo("Diff", "Rapport diff genere.")

    def show_sources_health(self):
        runs = self.list_case_runs()
        if not runs:
            messagebox.showinfo("Sante", "Aucun run disponible.")
            return

        stats = {}
        for run in runs:
            for item in run.get("results", []):
                src = item.get("source")
                if not src:
                    continue
                if src not in stats:
                    stats[src] = {"total": 0, "found": 0, "warning": 0, "not_found": 0}
                stats[src]["total"] += 1
                status = item.get("status", "not_found")
                stats[src][status] = stats[src].get(status, 0) + 1

        rows = []
        for src, values in stats.items():
            total = max(values.get("total", 1), 1)
            warning_rate = values.get("warning", 0) / total
            health = "stable"
            if warning_rate >= 0.5:
                health = "degrade"
            elif warning_rate >= 0.2:
                health = "flaky"
            rows.append((src, values.get("total", 0), values.get("found", 0), values.get("warning", 0), health))

        rows.sort(key=lambda item: (item[4], -item[3], item[0]))
        self.output_text.delete("1.0", "end")
        self.output_text.insert("end", "=== SANTE SOURCES ===\n", "header")
        for src, total, found, warning, health in rows[:120]:
            line = f"{src:<24} | total={total:<3} found={found:<3} warning={warning:<3} health={health}\n"
            tag = "warning" if health != "stable" else "header"
            self.output_text.insert("end", line, tag)
        self.output_text.see("end")

    def clear_logs(self):
        self.output_text.delete("1.0", "end")
        self.results_data = []
        self.filtered_data = []
        self.update_dashboard_metrics()


if __name__ == "__main__":
    app = HoleheApp()
    app.mainloop()
