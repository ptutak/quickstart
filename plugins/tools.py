from Imp.plugins.base import plugin, Context

import hashlib

@plugin
def unique_file(prefix : "string", seed : "string", suffix : "string") -> "string":
    return prefix + hashlib.md5(seed.encode("utf-8")).hexdigest() + suffix
