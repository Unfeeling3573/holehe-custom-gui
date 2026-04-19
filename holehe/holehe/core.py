from bs4 import BeautifulSoup
from termcolor import colored
import httpx
import trio

from subprocess import Popen, PIPE
import os
from argparse import ArgumentParser
import csv
from datetime import datetime
import time
import importlib
import pkgutil
import hashlib
import re
import sys
import string
import random
import json

from holehe.localuseragent import ua
from holehe.instruments import TrioProgress


import http.cookiejar as cookielib


DEBUG        = False
EMAIL_FORMAT = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

__version__ = "1.61"

SITE_DOMAINS = {'aboutme': 'about.me', 'adobe': 'adobe.com', 'amazon': 'amazon.com', 'anydo': 'any.do', 'archive': 'archive.org', 'armurerieauxerre': 'armurerie-auxerre.com', 'atlassian': 'atlassian.com', 'babeshows': 'babeshows.co.uk', 'badeggsonline': 'badeggsonline.com', 'biosmods': 'bios-mods.com', 'biotechnologyforums': 'biotechnologyforums.com', 'bitmoji': 'bitmoji.com', 'blablacar': 'blablacar.com', 'blackworldforum': 'blackworldforum.com', 'blip': 'blip.fm', 'blitzortung': 'forum.blitzortung.org', 'bluegrassrivals': 'bluegrassrivals.com', 'bodybuilding': 'bodybuilding.com', 'buymeacoffee': 'buymeacoffee.com', 'cambridgemt': 'discussion.cambridge-mt.com', 'caringbridge': 'caringbridge.org', 'chinaphonearena': 'chinaphonearena.com', 'clashfarmer': 'clashfarmer.com', 'codecademy': 'codecademy.com', 'codeigniter': 'forum.codeigniter.com', 'codepen': 'codepen.io', 'coroflot': 'coroflot.com', 'cpaelites': 'cpaelites.com', 'cpahero': 'cpahero.com', 'cracked_to': 'cracked.to', 'crevado': 'crevado.com', 'deliveroo': 'deliveroo.com', 'demonforums': 'demonforums.net', 'devrant': 'devrant.com', 'diigo': 'diigo.com', 'discord': 'discord.com', 'docker': 'docker.com', 'dominosfr': 'dominos.fr', 'ebay': 'ebay.com', 'ello': 'ello.co', 'envato': 'envato.com', 'eventbrite': 'eventbrite.com', 'evernote': 'evernote.com', 'fanpop': 'fanpop.com', 'firefox': 'firefox.com', 'flickr': 'flickr.com', 'freelancer': 'freelancer.com', 'freiberg': 'drachenhort.user.stunet.tu-freiberg.de', 'garmin': 'garmin.com', 'github': 'github.com', 'google': 'google.com', 'gravatar': 'gravatar.com', 'hubspot': 'hubspot.com', 'imgur': 'imgur.com', 'insightly': 'insightly.com', 'instagram': 'instagram.com', 'issuu': 'issuu.com', 'koditv': 'forum.kodi.tv', 'komoot': 'komoot.com', 'laposte': 'laposte.fr', 'lastfm': 'last.fm', 'lastpass': 'lastpass.com', 'mail_ru': 'mail.ru', 'mybb': 'community.mybb.com', 'myspace': 'myspace.com', 'nattyornot': 'nattyornotforum.nattyornot.com', 'naturabuy': 'naturabuy.fr', 'ndemiccreations': 'forum.ndemiccreations.com', 'nextpvr': 'forums.nextpvr.com', 'nike': 'nike.com', 'nimble': 'nimble.com', 'nocrm': 'nocrm.io', 'nutshell': 'nutshell.com', 'odnoklassniki': 'ok.ru', 'office365': 'office365.com', 'onlinesequencer': 'onlinesequencer.net', 'parler': 'parler.com', 'patreon': 'patreon.com', 'pinterest': 'pinterest.com', 'pipedrive': 'pipedrive.com', 'plurk': 'plurk.com', 'pornhub': 'pornhub.com', 'protonmail': 'protonmail.ch', 'quora': 'quora.com', 'rambler': 'rambler.ru', 'redtube': 'redtube.com', 'replit': 'replit.com', 'rocketreach': 'rocketreach.co', 'samsung': 'samsung.com', 'seoclerks': 'seoclerks.com', 'sevencups': '7cups.com', 'smule': 'smule.com', 'snapchat': 'snapchat.com', 'soundcloud': 'soundcloud.com', 'sporcle': 'sporcle.com', 'spotify': 'spotify.com', 'strava': 'strava.com', 'taringa': 'taringa.net', 'teamleader': 'teamleader.eu', 'teamtreehouse': 'teamtreehouse.com', 'tellonym': 'tellonym.me', 'thecardboard': 'thecardboard.org', 'therianguide': 'forums.therian-guide.com', 'thevapingforum': 'thevapingforum.com', 'tumblr': 'tumblr.com', 'tunefind': 'tunefind.com', 'twitter': 'twitter.com', 'venmo': 'venmo.com', 'vivino': 'vivino.com', 'voxmedia': 'voxmedia.com', 'vrbo': 'vrbo.com', 'vsco': 'vsco.co', 'wattpad': 'wattpad.com', 'wordpress': 'wordpress.com', 'xing': 'xing.com', 'xnxx': 'xnxx.com', 'xvideos': 'xvideos.com', 'yahoo': 'yahoo.com', 'zoho': 'zoho.com'}

ENTRY_PATTERN = re.compile(r"^[a-z0-9_][a-z0-9_.-]*$")


def import_submodules(package, recursive=True):
    """Get all the holehe submodules"""
    if isinstance(package, str):
        package = importlib.import_module(package)
    results = {}
    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__):
        full_name = package.__name__ + '.' + name
        results[full_name] = importlib.import_module(full_name)
        if recursive and is_pkg:
            results.update(import_submodules(full_name))
    return results


def load_sites_wordlist(file_path, return_stats=False):
    """Load site module names from a wordlist of domains or module names."""
    selected_sites = set()
    total_input_lines = 0
    candidate_lines = 0
    valid_lines = 0
    invalid_lines = 0
    ignored_lines = 0
    duplicate_lines = 0
    ignored_entries = set()
    seen_entries = set()
    parsing_errors = []

    with open(file_path, "rb") as wordlist_file:
        raw_content = wordlist_file.read()

    if raw_content.startswith(b"\xff\xfe") or raw_content.startswith(b"\xfe\xff"):
        content = raw_content.decode("utf-16", errors="ignore")
    elif raw_content.startswith(b"\xef\xbb\xbf"):
        content = raw_content.decode("utf-8-sig", errors="ignore")
    else:
        content = raw_content.decode("utf-8", errors="ignore")

    content = content.replace("\x00", "")

    if file_path.lower().endswith(".rtf"):
        content = content.replace("\\par", "\n").replace("\\line", "\n")
        content = re.sub(r"\\'[0-9a-fA-F]{2}", "", content)
        content = re.sub(r"\\[a-zA-Z]+-?\d* ?", "", content)
        content = content.replace("{", "").replace("}", "")

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
            total_input_lines += 1
            entry = raw_line.strip().lower()
            if not entry or entry.startswith("#"):
                continue
            candidate_lines += 1

            if "//" in entry:
                entry = entry.split("//", 1)[-1]
            entry = entry.split("/", 1)[0]
            entry = entry.split(":", 1)[0]
            entry = entry.lstrip("@")

            if not entry or not ENTRY_PATTERN.match(entry):
                invalid_lines += 1
                parsing_errors.append({
                    "line": line_number,
                    "raw": raw_line.strip(),
                    "normalized": entry,
                    "reason": "invalid_format",
                })
                continue

            if entry in seen_entries:
                duplicate_lines += 1
                parsing_errors.append({
                    "line": line_number,
                    "raw": raw_line.strip(),
                    "normalized": entry,
                    "reason": "duplicate",
                })
                continue
            seen_entries.add(entry)
            valid_lines += 1

            if entry in SITE_DOMAINS:
                selected_sites.add(entry)
                continue

            matched = False
            for site, domain in SITE_DOMAINS.items():
                if entry == domain or entry.endswith("." + domain):
                    selected_sites.add(site)
                    matched = True
                    break

            if not matched:
                ignored_lines += 1
                ignored_entries.add(entry)
                parsing_errors.append({
                    "line": line_number,
                    "raw": raw_line.strip(),
                    "normalized": entry,
                    "reason": "unsupported_domain",
                })

    if return_stats:
        ignored_list = sorted(list(ignored_entries))
        mapped_list = sorted(list(selected_sites))
        valid_list = sorted(list(seen_entries))
        stats = {
            "total_input_lines": total_input_lines,
            "candidate_lines": candidate_lines,
            "valid_lines": valid_lines,
            "invalid_lines": invalid_lines,
            "ignored_lines": ignored_lines,
            "duplicate_lines": duplicate_lines,
            "mapped_modules": len(selected_sites),
            "ignored_entries": len(ignored_entries),
            "ignored_sample": ignored_list[:10],
            "ignored_list": ignored_list,
            "mapped_list": mapped_list,
            "valid_list": valid_list,
            "normalized_preview": valid_list[:10],
            "parsing_errors": parsing_errors,
        }
        return selected_sites, stats

    return selected_sites


def get_functions(modules,args=None):
    """Transform the modules objects to functions"""
    websites = []
    selected_sites = set()
    filter_requested = False

    if args is not None and getattr(args, "sites_file", None):
        filter_requested = True
        selected_sites.update(load_sites_wordlist(args.sites_file))

    if args is not None and getattr(args, "sites", None):
        filter_requested = True
        selected_sites.update({
            site.strip().lower()
            for site in args.sites.split(",")
            if site.strip()
        })

    if not filter_requested:
        selected_sites = None

    for module in modules:
        if len(module.split(".")) > 3 :
            modu = modules[module]
            site = module.split(".")[-1]
            if selected_sites is not None and site.lower() not in selected_sites:
                continue
            if args is not None and args.nopasswordrecovery==True:
                if  "adobe" not in str(modu.__dict__[site]) and "mail_ru" not in str(modu.__dict__[site]) and "odnoklassniki" not in str(modu.__dict__[site]) and "samsung" not in str(modu.__dict__[site]):
                    websites.append(modu.__dict__[site])
            else:
                websites.append(modu.__dict__[site])
    return websites

def check_update():
    """Check and update holehe if not the last version"""
    check_version = httpx.get("https://pypi.org/pypi/holehe/json")
    if check_version.json()["info"]["version"] != __version__:
        if os.name != 'nt':
            p = Popen(["pip3",
                       "install",
                       "--upgrade",
                       "holehe"],
                      stdout=PIPE,
                      stderr=PIPE)
        else:
            p = Popen(["pip",
                       "install",
                       "--upgrade",
                       "holehe"],
                      stdout=PIPE,
                      stderr=PIPE)
        (output, err) = p.communicate()
        p_status = p.wait()
        print("Holehe has just been updated, you can restart it.")
        exit()

def credit():
    """Print Credit"""
    print('Twitter : @palenath')
    print('Github : https://github.com/megadose/holehe')
    print('For BTC Donations : 1FHDM49QfZX6pJmhjLE5tB2K6CaTLMZpXZ')

def is_email(email: str) -> bool:
    """Check if the input is a valid email address

    Keyword Arguments:
    email       -- String to be tested

    Return Value:
    Boolean     -- True if string is an email, False otherwise
    """

    return bool(re.fullmatch(EMAIL_FORMAT, email))

def print_result(data,args,email,start_time,websites):
    def print_color(text,color,args):
        if args.nocolor == False:
            return(colored(text,color))
        else:
            return(text)

    description = print_color("[+] Email used","green",args) + "," + print_color(" [-] Email not used", "magenta",args) + "," + print_color(" [x] Rate limit","yellow",args) + "," + print_color(" [!] Error","red",args)
    if args.noclear==False:
        print("\033[H\033[J")
    else:
        print("\n")
    print("*" * (len(email) + 6))
    print("   " + email)
    print("*" * (len(email) + 6))

    for results in data:
        if results["rateLimit"] and args.onlyused == False:
            websiteprint = print_color("[x] " + results["domain"], "yellow",args)
            print(websiteprint)
        elif "error" in results.keys() and results["error"] and args.onlyused == False:
            toprint = ""
            if results["others"] is not None and "Message" in str(results["others"].keys()):
                toprint = " Error message: " + results["others"]["errorMessage"]
            websiteprint = print_color("[!] " + results["domain"] + toprint, "red",args)
            print(websiteprint) 
        elif results["exists"] == False and args.onlyused == False:
            websiteprint = print_color("[-] " + results["domain"], "magenta",args)
            print(websiteprint)
        elif results["exists"] == True:
            toprint = ""
            if results["emailrecovery"] is not None:
                toprint += " " + results["emailrecovery"]
            if results["phoneNumber"] is not None:
                toprint += " / " + results["phoneNumber"]
            if results["others"] is not None and "FullName" in str(results["others"].keys()):
                toprint += " / FullName " + results["others"]["FullName"]
            if results["others"] is not None and "Date, time of the creation" in str(results["others"].keys()):
                toprint += " / Date, time of the creation " + results["others"]["Date, time of the creation"]

            websiteprint = print_color("[+] " + results["domain"] + toprint, "green",args)
            print(websiteprint)

    print("\n" + description)
    print(str(len(websites)) + " websites checked in " +
          str(round(time.time() - start_time, 2)) + " seconds")


def export_csv(data,args,email):
    """Export result to csv"""
    if args.csvoutput == True:
        now = datetime.now()
        timestamp = datetime.timestamp(now)
        name_file="holehe_"+str(round(timestamp))+"_"+email+"_results.csv"
        with open(name_file, 'w', encoding='utf8', newline='') as output_file:
            fc = csv.DictWriter(output_file,fieldnames=data[0].keys())
            fc.writeheader()
            fc.writerows(data)
        exit("All results have been exported to "+name_file)

async def launch_module(module,email, client, out):
    try:
        await module(email, client, out)
    except Exception:
        name=str(module).split('<function ')[1].split(' ')[0]
        out.append({"name": name,"domain":SITE_DOMAINS[name],
                    "rateLimit": False,
                    "error": True,
                    "exists": False,
                    "emailrecovery": None,
                    "phoneNumber": None,
                    "others": None})
async def maincore():
    parser= ArgumentParser(description=f"holehe v{__version__}")
    parser.add_argument("email",
                    nargs='*', metavar='EMAIL',
                    help="Target Email")
    parser.add_argument("--only-used", default=False, required=False,action="store_true",dest="onlyused",
                    help="Displays only the sites used by the target email address.")
    parser.add_argument("--no-color", default=False, required=False,action="store_true",dest="nocolor",
                    help="Don't color terminal output")
    parser.add_argument("--no-clear", default=False, required=False,action="store_true",dest="noclear",
                    help="Do not clear the terminal to display the results")
    parser.add_argument("-NP","--no-password-recovery", default=False, required=False,action="store_true",dest="nopasswordrecovery",
                    help="Do not try password recovery on the websites")
    parser.add_argument("--sites", default=None, required=False, dest="sites",
                    help="Comma-separated list of site modules to run, for example: google,github,spotify")
    parser.add_argument("--sites-file", default=None, required=False, dest="sites_file",
                    help="Path to a .txt/.rtf file containing domains or site module names")
    parser.add_argument("--inspect-sites-file", default=None, required=False, dest="inspect_sites_file",
                    help="Inspect a wordlist file and print mapping stats as JSON")
    parser.add_argument("-C","--csv", default=False, required=False,action="store_true",dest="csvoutput",
                    help="Create a CSV with the results")
    parser.add_argument("-T","--timeout", type=int , default=10, required=False,dest="timeout",
                    help="Set max timeout value (default 10)")

    args = parser.parse_args()

    if args.inspect_sites_file:
        selected_sites, stats = load_sites_wordlist(args.inspect_sites_file, return_stats=True)
        payload = {
            "file": args.inspect_sites_file,
            "total_input_lines": stats["total_input_lines"],
            "candidate_lines": stats["candidate_lines"],
            "valid_lines": stats["valid_lines"],
            "invalid_lines": stats["invalid_lines"],
            "ignored_lines": stats["ignored_lines"],
            "duplicate_lines": stats["duplicate_lines"],
            "mapped_modules": stats["mapped_modules"],
            "ignored_entries": stats["ignored_entries"],
            "ignored_sample": stats["ignored_sample"],
            "mapped_sample": stats["mapped_list"][:15],
            "ignored_list": stats["ignored_list"],
            "mapped_list": stats["mapped_list"],
            "valid_list": stats["valid_list"],
            "normalized_preview": stats["normalized_preview"],
            "parsing_errors": stats["parsing_errors"],
        }
        print(json.dumps(payload, ensure_ascii=False))
        return

    check_update()
    credit()
    if not args.email:
        exit("[-] Please enter a target email ! \nExample : holehe email@example.com")
    email=args.email[0]

    if not is_email(email):
        exit("[-] Please enter a target email ! \nExample : holehe email@example.com")

    # Import Modules
    modules = import_submodules("holehe.modules")
    websites = get_functions(modules,args)
    # Get timeout
    timeout=args.timeout
    # Start time
    start_time = time.time()
    # Def the async client
    client = httpx.AsyncClient(timeout=timeout)
    # Launching the modules
    out = []
    instrument = TrioProgress(len(websites))
    trio.lowlevel.add_instrument(instrument)
    async with trio.open_nursery() as nursery:
        for website in websites:
            nursery.start_soon(launch_module, website, email, client, out)
    trio.lowlevel.remove_instrument(instrument)
    # Sort by modules names
    out = sorted(out, key=lambda i: i['name'])
    # Close the client
    await client.aclose()
    # Print the result
    print_result(out,args,email,start_time,websites)
    credit()
    # Export results
    export_csv(out,args,email)

def main():
    trio.run(maincore)


if __name__ == "__main__":
    main()
