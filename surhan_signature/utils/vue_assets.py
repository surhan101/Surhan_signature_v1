import json
import frappe
import os


def get_vue_assets():

    manifest_path = frappe.get_app_path(
        "surhan_signature",
        "public",
        "frontend",
        "signature-center",
        ".vite",
        "manifest.json",
    )

    if not os.path.exists(manifest_path):
        return {}

    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    entry = list(manifest.values())[0]

    js = entry.get("file")

    css = entry.get("css", [])

    return {
        "js": f"/assets/surhan_signature/frontend/signature-center/{js}" if js else None,
        "css": [
            f"/assets/surhan_signature/frontend/signature-center/{c}"
            for c in css
        ],
    }
