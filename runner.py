#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import importlib
import shlex
import sys
import traceback

from aws_common import get_session, run_check

BANNER = r"""

██╗░░░░░░█████╗░███████╗██╗░░░██╗      ░█████╗░░██╗░░░░░░░██╗░██████╗
██║░░░░░██╔══██╗╚════██║╚██╗░██╔╝      ██╔══██╗░██║░░██╗░░██║██╔════╝
██║░░░░░███████║░░███╔═╝░╚████╔╝░      ███████║░╚██╗████╗██╔╝╚█████╗░
██║░░░░░██╔══██║██╔══╝░░░░╚██╔╝░░      ██╔══██║░░████╔═████║░░╚═══██╗
███████╗██║░░██║███████╗░░░██║░░░      ██║░░██║░░╚██╔╝░╚██╔╝░██████╔╝
╚══════╝╚═╝░░╚═╝╚══════╝░░░╚═╝░░░      ╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░╚═════╝░
              
              by LazyIT(https://www.youtube.com/@Lazy_IT)
                     type 'help' to get started
"""

PROMPT_BASE = "lazyaws"
PROMPT_FMT = "{base}{mod}> "

MODULES = {
    "s3":       "checks.check_s3",
    "lambda":   "checks.check_lambda",
    "iam":      "checks.check_iam",
    "ec2":      "checks.check_ec2",
    "report":   "checks.check_report",
    "exposure": "checks.check_exposure",   # NEW
}

HELP_TEXT = """
Commands:
  show modules             - list available modules
  use <module>             - switch active module (s3|lambda|iam|ec2|report|exposure)
  show options             - show current module options
  show globals             - show global options (profile/region)
  set <key> <value>        - set module option (e.g., set bucket my-bucket)
  setg <key> <value>       - set global option (e.g., setg profile pentest)
  run [k=v ...]            - run current module once (optional inline args)
  runall                   - run module across discovered scope (e.g., all buckets / all regions)
  back                     - return to main prompt
  help                     - this help
  exit | quit              - exit

Tips:
- S3:
    setg profile pentest
    use s3
    set bucket backstage-uat-s3
    run
    or: runall   # enumerates all buckets and runs checks for each
- EC2:
    use ec2
    set region eu-west-1
    run             # first instance in region (or set instance-id)
    set instance-id i-0123456789abcdef0
    run
    runall          # across all regions & all instances
- Lambda:
    use lambda
    set region eu-west-1
    set function-name my-func
    run
    runall          # all regions & all functions
- IAM:
    use iam
    run             # account-wide checks
- Report:
    use report
    run             # builds Excel from RawData/*.json
- Exposure:
    use exposure
    run | runall    # builds internet exposure inventory across regions
"""

EXIT_SENTINEL = "__EXIT__"

def _prompt(base: str, module: str | None) -> str:
    mod = f" ({module})" if module else ""
    return PROMPT_FMT.format(base=base, mod=mod)

class Shell:
    def __init__(self):
        self.current_module: str | None = None
        self.module_opts: dict[str, dict] = {}
        self.globals: dict[str, str] = {}
        self.globals.setdefault("profile", None)
        self.globals.setdefault("region", None)

    # ---------- main loop ----------
    def cmdloop(self):
        print(BANNER)
        while True:
            try:
                line = input(_prompt(PROMPT_BASE, self.current_module))
            except (EOFError, KeyboardInterrupt):
                print()
                break

            line = (line or "").strip()
            if not line:
                continue

            try:
                ret = self.dispatch(line)
                if ret == EXIT_SENTINEL:
                    break
            except Exception:
                traceback.print_exc()

    # ---------- dispatcher ----------
    def dispatch(self, line: str):
        parts = shlex.split(line)
        if not parts:
            return
        cmd, *args = parts

        if cmd in ("exit", "quit"):
            return EXIT_SENTINEL
        if cmd == "help":
            print(HELP_TEXT)
            return
        if cmd == "show":
            return self._do_show(args)
        if cmd == "use":
            return self._do_use(args)
        if cmd == "set":
            return self._do_set(args)
        if cmd == "setg":
            return self._do_setg(args)
        if cmd == "back":
            self.current_module = None
            return
        if cmd == "run":
            return self._do_run(args)
        if cmd == "runall":
            return self._do_runall(args)

        print(f"[!] Unknown command: {cmd}. Type 'help'.")

    # ---------- show ----------
    def _do_show(self, args: list[str]):
        if not args:
            print("[!] Usage: show modules|options|globals")
            return
        what = args[0]
        if what == "modules":
            print("\nAvailable modules:")
            for k, v in MODULES.items():
                print(f"  {k:<8} -> {v}")
            print()
        elif what == "options":
            if not self.current_module:
                print("[!] No module selected. Use 'use <module>'.")
                return
            opts = self.module_opts.get(self.current_module, {})
            if not opts:
                print("(no module options set)")
            else:
                for k, v in opts.items():
                    print(f"{self.current_module}::{k} = {v}")
        elif what == "globals":
            if not self.globals:
                print("(no globals)")
            else:
                for k, v in self.globals.items():
                    print(f"global {k} = {v}")
        else:
            print("[!] Usage: show modules|options|globals")

    # ---------- use / set ----------
    def _do_use(self, args: list[str]):
        if not args:
            print("[!] Usage: use <module>")
            return
        mod = args[0].lower()
        if mod not in MODULES:
            print(f"[!] Unknown module: {mod}")
            return
        self.current_module = mod
        self.module_opts.setdefault(mod, {})
        print(f"[+] Using module: {mod}")

    def _do_set(self, args: list[str]):
        if not self.current_module:
            print("[!] Select module first: use <module>")
            return
        if len(args) < 2:
            print("[!] Usage: set <key> <value>")
            return
        key = args[0].replace("-", "_")
        val = " ".join(args[1:])
        self.module_opts.setdefault(self.current_module, {})[key] = val
        print(f"[+] Set {self.current_module}::{key} = {val}")

    def _do_setg(self, args: list[str]):
        if len(args) < 2:
            print("[!] Usage: setg <key> <value>")
            return
        key = args[0].lower()
        val = " ".join(args[1:])
        self.globals[key] = val
        print(f"[+] Set global {key} = {val}")

    # ---------- helpers ----------
    def _build_namespace_for_module(self, mod: str, inline_args: dict[str, str]):
        """
        Compose argparse.Namespace expected by the module's analyze(...)
        Priority: inline args > module opts > globals
        """
        opts = dict(self.module_opts.get(mod, {}))
        opts.update(inline_args)
        profile = opts.get("profile", self.globals.get("profile"))
        region = opts.get("region", self.globals.get("region"))
        opts["profile"] = profile
        if region is not None:
            opts["region"] = region
        return argparse.Namespace(**opts)

    def _parse_kv(self, items: list[str]) -> dict[str, str]:
        kv = {}
        for it in items:
            if "=" in it:
                k, v = it.split("=", 1)
                kv[k.replace("-", "_")] = v
        return kv

    # ---------- run (single) ----------
    def _do_run(self, args: list[str]):
        if not self.current_module:
            print("[!] Select module first: use <module>")
            return
        modpath = MODULES[self.current_module]
        mod = importlib.import_module(modpath)
        inline = self._parse_kv(args)
        ns = self._build_namespace_for_module(self.current_module, inline)
        try:
            if hasattr(mod, "analyze"):
                run_check(mod.analyze, ns)
            else:
                print(f"[!] Module {self.current_module} has no analyze()")
        except SystemExit:
            # suppress argparse exits originating inside module code
            pass
        except Exception as e:
            print(f"[!] Error while running module: {e}")

    # ---------- runall helpers per module ----------
    def _runall_s3(self):
        """
        Enumerate all buckets and run S3 checks for each.
        """
        profile = self.globals.get("profile")
        region_hint = self.globals.get("region")
        sess = get_session(profile, None)  # S3 list is regionless
        s3 = sess.client("s3")
        try:
            resp = s3.list_buckets()
            buckets = [b["Name"] for b in resp.get("Buckets", [])]
        except Exception as e:
            print(f"[!] Failed to list buckets: {e}")
            return

        print(f"Found {len(buckets)} buckets. Resolving regions & running checks...\n")
        mod = importlib.import_module(MODULES["s3"])
        for name in buckets:
            # resolve region per bucket
            try:
                loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
                if loc == "EU":
                    loc = "eu-west-1"
                bucket_region = loc or "us-east-1"
            except Exception:
                bucket_region = region_hint
            print(f"\n=== Checking bucket: {name} [{bucket_region or '—'}] ===")
            ns = argparse.Namespace(bucket=name, profile=profile, region=bucket_region, sample_prefix=None)
            try:
                run_check(mod.analyze, ns)
            except SystemExit:
                pass
            except Exception as e:
                print(f"[!] Error running S3 checks for bucket {name}: {e}")
        print("\nDone.")

    def _runall_lambda(self):
        """
        All regions -> list functions -> run per function.
        """
        profile = self.globals.get("profile")
        sess = get_session(profile, None)
        regions = sess.get_available_regions("lambda") or []
        mod = importlib.import_module(MODULES["lambda"])
        total = 0
        for r in regions:
            try:
                lmb = sess.client("lambda", region_name=r)
                pager = lmb.get_paginator("list_functions")
                for page in pager.paginate():
                    for fn in page.get("Functions", []):
                        name = fn.get("FunctionName")
                        total += 1
                        print(f"\n=== Checking function: {name} [{r}] ===")
                        ns = argparse.Namespace(function_name=name, region=r, profile=profile)
                        try:
                            run_check(mod.analyze, ns)
                        except SystemExit:
                            pass
                        except Exception as e:
                            print(f"[!] Error on {name}@{r}: {e}")
            except Exception as e:
                print(f"[i] Skip region {r}: {e}")
        if total == 0:
            print("No Lambda functions found.")
        print("Done.")

    def _runall_ec2(self):
        """
        All regions -> list instances -> run per instance.
        """
        profile = self.globals.get("profile")
        sess = get_session(profile, None)
        regions = sess.get_available_regions("ec2") or []
        mod = importlib.import_module(MODULES["ec2"])
        discovered = []
        for r in regions:
            try:
                ec2 = sess.client("ec2", region_name=r)
                page = ec2.describe_instances()
                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        discovered.append((r, inst.get("InstanceId")))
            except Exception as e:
                print(f"[i] Skip region {r}: {e}")
        print(f"Found {len(discovered)} instances across {len(regions)} region(s). Running EC2 checks...\n")
        if not discovered:
            print("No instances found.")
            return
        mod = importlib.import_module(MODULES["ec2"])
        for r, iid in discovered:
            print(f"\n=== Checking instance: {iid} [{r}] ===")
            ns = argparse.Namespace(instance_id=iid, region=r, profile=profile, allowed_ami_owners=None)
            try:
                run_check(mod.analyze, ns)
            except SystemExit:
                pass
            except Exception as e:
                print(f"[!] Error on {iid}@{r}: {e}")
        print("Done.")

    def _runall_iam(self):
        """
        IAM is global; just run once.
        """
        profile = self.globals.get("profile")
        region = self.globals.get("region")  # header hint only
        mod = importlib.import_module(MODULES["iam"])
        ns = argparse.Namespace(profile=profile, region=region, stale_days=90)
        try:
            run_check(mod.analyze, ns)
        except SystemExit:
            pass
        except Exception as e:
            print(f"[!] Error while running IAM: {e}")

    def _runall_report(self):
        """
        Build Excel report from RawData/*.json once.
        """
        mod = importlib.import_module(MODULES["report"])
        out = "Reports/LazyAWS_Report.xlsx"
        ns = argparse.Namespace(out=out, profile=self.globals.get("profile"), region=self.globals.get("region"))
        try:
            run_check(mod.analyze, ns)
        except SystemExit:
            pass
        except Exception as e:
            print(f"[!] Error while building report: {e}")

    def _runall_exposure(self):
        """
        Exposure inventory: модуль сам проходить усі регіони (або заданий).
        """
        mod = importlib.import_module(MODULES["exposure"])
        ns = argparse.Namespace(
            profile=self.globals.get("profile"),
            region=(self.globals.get("region") or "all"),
        )
        try:
            run_check(mod.analyze, ns)
        except SystemExit:
            pass
        except Exception as e:
            print(f"[!] Error while running exposure inventory: {e}")

    # ---------- runall dispatcher ----------
    def _do_runall(self, args: list[str]):
        if not self.current_module:
            print("[!] Select module first: use <module>")
            return
        if self.current_module == "s3":
            return self._runall_s3()
        if self.current_module == "lambda":
            return self._runall_lambda()
        if self.current_module == "ec2":
            return self._runall_ec2()
        if self.current_module == "iam":
            return self._runall_iam()
        if self.current_module == "report":
            return self._runall_report()
        if self.current_module == "exposure":
            return self._runall_exposure()
        print(f"[!] runall not implemented for module: {self.current_module}")

def main():
    shell = Shell()
    shell.cmdloop()

if __name__ == "__main__":
    main()
