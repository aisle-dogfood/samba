#! /usr/bin/env python
# encoding: utf-8
# Thomas Nagy, 2016-2018 (ita)

import os, sys, traceback, base64, signal, json
try:
	import subprocess32 as subprocess
except ImportError:
	import subprocess

try:
	TimeoutExpired = subprocess.TimeoutExpired
except AttributeError:
	class TimeoutExpired(Exception):
		pass

def json_decode(data):
	"""Decode JSON data with support for bytes and subprocess constants"""
	def decode_obj(obj):
		if isinstance(obj, dict):
			if '__bytes__' in obj:
				return base64.b64decode(obj['__bytes__'].encode('utf-8'))
			elif '__subprocess_const__' in obj:
				const_name = obj['__subprocess_const__']
				return getattr(subprocess, const_name)
			return {k: decode_obj(v) for k, v in obj.items()}
		elif isinstance(obj, list):
			return [decode_obj(item) for item in obj]
		return obj
	return decode_obj(json.loads(data))

def json_encode(data):
	"""Encode data to JSON with support for bytes and subprocess constants"""
	def encode_obj(obj):
		if isinstance(obj, bytes):
			return {'__bytes__': base64.b64encode(obj).decode('utf-8')}
		elif isinstance(obj, int) and hasattr(subprocess, 'PIPE') and obj in (subprocess.PIPE, subprocess.STDOUT):
			if obj == subprocess.PIPE:
				return {'__subprocess_const__': 'PIPE'}
			elif obj == subprocess.STDOUT:
				return {'__subprocess_const__': 'STDOUT'}
		elif hasattr(subprocess, 'DEVNULL') and isinstance(obj, int) and obj == subprocess.DEVNULL:
			return {'__subprocess_const__': 'DEVNULL'}
		elif isinstance(obj, dict):
			return {k: encode_obj(v) for k, v in obj.items()}
		elif isinstance(obj, list):
			return [encode_obj(item) for item in obj]
		elif isinstance(obj, tuple):
			return [encode_obj(item) for item in obj]
		return obj
	return json.dumps(encode_obj(data))

def run():
	txt = sys.stdin.readline().strip()
	if not txt:
		# parent process probably ended
		sys.exit(18)
	[cmd, kwargs, cargs] = json_decode(base64.b64decode(txt).decode('utf-8'))
	cargs = cargs or {}

	if not 'close_fds' in kwargs:
		# workers have no fds
		kwargs['close_fds'] = False

	ret = 1
	out, err, ex, trace = (None, None, None, None)
	try:
		proc = subprocess.Popen(cmd, **kwargs)
		try:
			out, err = proc.communicate(**cargs)
		except TimeoutExpired:
			if kwargs.get('start_new_session') and hasattr(os, 'killpg'):
				os.killpg(proc.pid, signal.SIGKILL)
			else:
				proc.kill()
			out, err = proc.communicate()
			exc = TimeoutExpired(proc.args, timeout=cargs['timeout'], output=out)
			exc.stderr = err
			raise exc
		ret = proc.returncode
	except Exception as e:
		exc_type, exc_value, tb = sys.exc_info()
		exc_lines = traceback.format_exception(exc_type, exc_value, tb)
		trace = str(cmd) + '\n' + ''.join(exc_lines)
		ex = e.__class__.__name__

	# serialize using JSON instead of pickle for security
	tmp = [ret, out, err, ex, trace]
	obj = base64.b64encode(json_encode(tmp).encode('utf-8'))
	sys.stdout.write(obj.decode())
	sys.stdout.write('\n')
	sys.stdout.flush()

while 1:
	try:
		run()
	except KeyboardInterrupt:
		break
	except Exception:
		traceback.print_exc(file=sys.stderr)
		sys.exit(19)
