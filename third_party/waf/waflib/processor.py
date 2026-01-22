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
	"""
	Recursively encode bytes objects to base64 strings for JSON serialization.
	
	:param obj: object to encode
	:return: JSON-safe version of the object
	"""
	if isinstance(obj, bytes):
		return {'__bytes__': base64.b64encode(obj).decode('ascii')}
	elif isinstance(obj, dict):
		return {k: encode_for_json(v) for k, v in obj.items()}
	elif isinstance(obj, (list, tuple)):
		return [encode_for_json(item) for item in obj]
	else:
		return obj

def decode_from_json(obj):
	"""
	Recursively decode base64 strings back to bytes objects after JSON deserialization.
	
	:param obj: JSON-deserialized object
	:return: object with bytes restored
	"""
	if isinstance(obj, dict):
		if '__bytes__' in obj:
			return base64.b64decode(obj['__bytes__'])
		return {k: decode_from_json(v) for k, v in obj.items()}
	elif isinstance(obj, list):
		return [decode_from_json(item) for item in obj]
	else:
		return obj

def run():
	txt = sys.stdin.readline().strip()
	if not txt:
		# parent process probably ended
		sys.exit(18)
	decoded_data = json.loads(txt)
	[cmd, kwargs, cargs] = decode_from_json(decoded_data)
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
	encoded_data = encode_for_json(tmp)
	obj = json.dumps(encoded_data)
	sys.stdout.write(obj)
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
