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

def _make_json_serializable(obj):
	"""
	Convert an object to be JSON-serializable by encoding bytes as base64 strings.
	Recursively handles lists and dictionaries.
	"""
	if isinstance(obj, bytes):
		return {'__bytes__': base64.b64encode(obj).decode('ascii')}
	elif isinstance(obj, list):
		return [_make_json_serializable(item) for item in obj]
	elif isinstance(obj, dict):
		return {key: _make_json_serializable(value) for key, value in obj.items()}
	elif obj is None or isinstance(obj, (str, int, float, bool)):
		return obj
	else:
		# For other types, try to convert to string representation
		return str(obj)

def _restore_from_json(obj):
	"""
	Restore objects from JSON-serializable format, decoding base64 strings back to bytes.
	Recursively handles lists and dictionaries.
	"""
	if isinstance(obj, dict):
		if '__bytes__' in obj:
			return base64.b64decode(obj['__bytes__'].encode('ascii'))
		else:
			return {key: _restore_from_json(value) for key, value in obj.items()}
	elif isinstance(obj, list):
		return [_restore_from_json(item) for item in obj]
	else:
		return obj

def run():
	txt = sys.stdin.readline().strip()
	if not txt:
		# parent process probably ended
		sys.exit(18)
	# Use JSON instead of pickle for secure deserialization
	json_str = txt
	serialized_data = json.loads(json_str)
	[cmd, kwargs, cargs] = _restore_from_json(serialized_data)
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

	# Use JSON instead of pickle for secure serialization
	tmp = [ret, out, err, ex, trace]
	serializable_tmp = _make_json_serializable(tmp)
	json_str = json.dumps(serializable_tmp)
	sys.stdout.write(json_str)
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
