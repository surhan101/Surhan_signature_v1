import frappe
from surhan_signature.utils.vue_assets import get_vue_assets


def get_context(context):

    context.vue_assets = get_vue_assets()
    context.no_cache = 1

    return context
