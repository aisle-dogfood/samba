#!/usr/local/bin/python
# -*- coding: utf-8 -*-

# $Id$

# Copyright (c) 2004 Kungliga Tekniska Högskolan
# (Royal Institute of Technology, Stockholm, Sweden). 
# All rights reserved. 
# 
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions 
# are met: 
# 
# 1. Redistributions of source code must retain the above copyright 
#    notice, this list of conditions and the following disclaimer. 
# 
# 2. Redistributions in binary form must reproduce the above copyright 
#    notice, this list of conditions and the following disclaimer in the 
#    documentation and/or other materials provided with the distribution. 
# 
# 3. Neither the name of the Institute nor the names of its contributors 
#    may be used to endorse or promote products derived from this software 
#    without specific prior written permission. 
# 
# THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
# SUCH DAMAGE. 

import re
import string
import sys
import os

import generate
import rfc3454
import rfc4518
import stringprep

def validate_path(path, is_output_dir=False):
    """Validate path to prevent path traversal attacks"""
    # Normalize the path
    normalized_path = os.path.normpath(path)
    
    # Check for path traversal sequences
    if '..' in normalized_path.split(os.sep):
        raise ValueError("Path traversal detected in path: %s" % path)
    
    # For output directories, ensure they don't start with /
    if is_output_dir and os.path.isabs(normalized_path):
        raise ValueError("Absolute paths not allowed for output directory: %s" % path)
    
    return normalized_path

if len(sys.argv) != 3:
    print("usage: %s rfc3454.txt out-dir" % sys.argv[0])
    sys.exit(1)

# Validate input file path
input_file = validate_path(sys.argv[1])
# Validate output directory path  
output_dir = validate_path(sys.argv[2], is_output_dir=True)

tables = rfc3454.read(input_file)
t2 = rfc4518.read()

for x in t2.keys():
    tables[x] = t2[x]

error_list = stringprep.get_errorlist()

errorlist_h = generate.Header('%s/errorlist_table.h' % output_dir)

errorlist_c = generate.Implementation('%s/errorlist_table.c' % output_dir)

errorlist_h.file.write(
'''
#include "windlocl.h"

struct error_entry {
  uint32_t start;
  unsigned len;
  wind_profile_flags flags;
};

extern const struct error_entry _wind_errorlist_table[];

extern const size_t _wind_errorlist_table_size;

''')

errorlist_c.file.write(
'''
#include "errorlist_table.h"
#include <stdlib.h>

const struct error_entry _wind_errorlist_table[] = {
''')

trans=[]

for t in error_list.keys():
    for l in tables[t]:
        m = re.search('^ *([0-9A-F]+)-([0-9A-F]+); *(.*) *$', l)
        if m:
            start = int(m.group(1), 0x10)
            end   = int(m.group(2), 0x10)
            desc  = m.group(3)
            trans.append([start, end - start + 1, desc, [t]])
        else:
            m = re.search('^ *([0-9A-F]+); *(.*) *$', l)
            if m:
                trans.append([int(m.group(1), 0x10), 1, m.group(2), [t]])

trans = stringprep.sort_merge_trans(trans)

for x in trans:
    (start, length, description, tables) = x
    symbols = stringprep.symbols(error_list, tables)
    if len(symbols) == 0:
        print("no symbol for %s" % description)
        sys.exit(1)
    errorlist_c.file.write("  {0x%x, 0x%x, %s}, /* %s: %s */\n"
                % (start, length, symbols, ",".join(tables), description))

errorlist_c.file.write(
'''};

''')

errorlist_c.file.write(
    "const size_t _wind_errorlist_table_size = %u;\n" % len(trans))

errorlist_h.close()
errorlist_c.close()
