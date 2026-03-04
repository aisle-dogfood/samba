#! /usr/bin/env python
# encoding: utf-8
# Thomas Nagy, 2016-2018 (ita)

import os, sys, traceback, base64, signal, json
try:
	import cPickle
except ImportError:
	import pickle as cPickle

try:
	import subprocess32 as subprocess
except ImportError:
	import subprocess

try:
	TimeoutExpired = subprocess.TimeoutExpired
except AttributeError:
	class TimeoutExpired(Exception):
		pass

def encode_for_json(obj):
	"""Convert bytes to base64 string for JSON serialization"""
	if isinstance(obj, bytes):
		return {'__bytes__': base64.b64encode(obj).decode('ascii')}
	elif isinstance(obj, list):
		return [encode_for_json(item) for item in obj]
	elif isinstance(obj, dict):
		return {k: encode_for_json(v) for k, v in obj.items()}
	return obj

def run():
	txt = sys.stdin.readline().strip()
	if not txt:
		# parent process probably ended
		sys.exit(18)
	[cmd, kwargs, cargs] = json.loads(base64.b64decode(txt).decode('utf-8'))
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

	# it is just text so maybe we do not need to pickle()
	tmp = [ret, out, err, ex, trace]
	tmp = encode_for_json(tmp)
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
