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

def json_decode_subprocess_args(obj):
	"""
	Decode subprocess arguments from JSON serialization.
	Handles special types like subprocess.DEVNULL, subprocess.PIPE, etc.
	"""
	if obj is None or isinstance(obj, (bool, int, str, float)):
		return obj
	elif isinstance(obj, dict):
		if '__type__' in obj:
			if obj['__type__'] == 'bytes':
				return base64.b64decode(obj['value'])
			elif obj['__type__'] == 'DEVNULL':
				return subprocess.DEVNULL if hasattr(subprocess, 'DEVNULL') else None
			elif obj['__type__'] == 'PIPE':
				return subprocess.PIPE
			elif obj['__type__'] == 'STDOUT':
				return subprocess.STDOUT
		else:
			return {k: json_decode_subprocess_args(v) for k, v in obj.items()}
	elif isinstance(obj, list):
		return [json_decode_subprocess_args(item) for item in obj]
	return obj

def run():
	txt = sys.stdin.readline().strip()
	if not txt:
		# parent process probably ended
		sys.exit(18)
	data = json.loads(base64.b64decode(txt).decode('utf-8'))
	cmd = json_decode_subprocess_args(data[0])
	kwargs = json_decode_subprocess_args(data[1])
	cargs = json_decode_subprocess_args(data[2]) or {}

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

	# encode bytes as base64 strings for JSON serialization
	tmp = [
		ret,
		base64.b64encode(out).decode('ascii') if out else None,
		base64.b64encode(err).decode('ascii') if err else None,
		ex,
		trace
	]
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
