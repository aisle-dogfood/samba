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

def decode_special_values(obj):
	"""Decode special subprocess constants from their string representations"""
	if isinstance(obj, dict):
		result = {}
		for key, value in obj.items():
			if value == '__SUBPROCESS_PIPE__':
				result[key] = subprocess.PIPE
			elif value == '__SUBPROCESS_DEVNULL__':
				result[key] = subprocess.DEVNULL if hasattr(subprocess, 'DEVNULL') else None
			elif value == '__SUBPROCESS_STDOUT__':
				result[key] = subprocess.STDOUT
			elif isinstance(value, dict):
				result[key] = decode_special_values(value)
			else:
				result[key] = value
		return result
	return obj

def run():
	txt = sys.stdin.readline().strip()
	if not txt:
		# parent process probably ended
		sys.exit(18)
	[cmd, kwargs, cargs] = json.loads(base64.b64decode(txt).decode('utf-8'))
	kwargs = decode_special_values(kwargs)
	cargs = decode_special_values(cargs)
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

	# Encode bytes to base64 strings for JSON serialization
	if out is not None and isinstance(out, bytes):
		out = base64.b64encode(out).decode('utf-8')
		out = '__BASE64__' + out
	if err is not None and isinstance(err, bytes):
		err = base64.b64encode(err).decode('utf-8')
		err = '__BASE64__' + err
	
	tmp = [ret, out, err, ex, trace]
	obj = base64.b64encode(json.dumps(tmp).encode('utf-8'))
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
