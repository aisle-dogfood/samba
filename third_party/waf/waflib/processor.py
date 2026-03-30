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

def _deserialize_kwargs_from_json(serialized):
	"""
	Restores kwargs dict from JSON-serialized form by converting special markers.
	"""
	kwargs = {}
	for key, value in serialized.items():
		if value == '__DEVNULL__':
			kwargs[key] = subprocess.DEVNULL if hasattr(subprocess, 'DEVNULL') else None
		elif value == '__PIPE__':
			kwargs[key] = subprocess.PIPE
		elif value == '__STDOUT__':
			kwargs[key] = subprocess.STDOUT
		else:
			kwargs[key] = value
	return kwargs

def run():
	txt = sys.stdin.readline().strip()
	if not txt:
		# parent process probably ended
		sys.exit(18)
	[cmd, serialized_kwargs, cargs] = json.loads(base64.b64decode(txt).decode('utf-8'))
	kwargs = _deserialize_kwargs_from_json(serialized_kwargs)
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

	# Encode binary data as base64 for JSON compatibility
	out_encoded = base64.b64encode(out).decode('utf-8') if out is not None else None
	err_encoded = base64.b64encode(err).decode('utf-8') if err is not None else None
	tmp = [ret, out_encoded, err_encoded, ex, trace]
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
