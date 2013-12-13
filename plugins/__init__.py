"""
    Copyright 2013 KU Leuven Research and Development - iMinds - Distrinet

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    Administrative Contact: dnet-project-office@cs.kuleuven.be
    Technical Contact: bart.vanbrabant@cs.kuleuven.be
"""

from Imp.plugins.base import plugin, Context

import hashlib, os, random

@plugin
def unique_file(prefix : "string", seed : "string", suffix : "string") -> "string":
    return prefix + hashlib.md5(seed.encode("utf-8")).hexdigest() + suffix

@plugin
def generate_password(context : Context, pw_id : "string", length : "number" = 20) -> "string":
    """
    Generate a new random password and store it in the data directory of the
    project. On next invocations the stored password will be used.

    :param pw_id string The id of the password to identify it.
    :param length number The length of the password, default length is 20
    """
    data_dir = context.get_data_dir()
    pw_file = os.path.join(data_dir, "passwordfile.txt")

    if "=" in pw_id:
        raise Exception("The password id cannot contain =")
    
    records = {}
    if os.path.exists(pw_file):
        with open(pw_file, "r") as fd:
            
            for line in fd.readlines():
                line = line.strip()
                i = line.index("=")
                
                try:
                    records[line[:i]] = line[i+1:]
                except ValueError:
                    pass            

            if pw_id in records:
                return records[pw_id]

    rnd = random.SystemRandom()
    pw = "".join([chr(rnd.randint(33, 126)) for x in range(20)])

    # store the new value
    records[pw_id] = pw

    with open(pw_file, "w+") as fd:
        for key,value in records.items():
            fd.write("%s=%s\n" % (key, value))

        return pw

