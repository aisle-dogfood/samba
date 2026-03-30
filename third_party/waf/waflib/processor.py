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

def json_encode_data(obj):
	"""
	Encode data for JSON serialization, converting bytes to base64 strings
	"""
	if isinstance(obj, bytes):
		return {'__type__': 'bytes', 'data': base64.b64encode(obj).decode('ascii')}
	elif isinstance(obj, dict):
		return {k: json_encode_data(v) for k, v in obj.items()}
	elif isinstance(obj, (list, tuple)):
		return [json_encode_data(item) for item in obj]
	else:
		return obj

def json_decode_data(obj):
	"""
	Decode data from JSON deserialization, converting base64 strings back to bytes
	"""
	if isinstance(obj, dict):
		if '__type__' in obj and obj['__type__'] == 'bytes':
			return base64.b64decode(obj['data'].encode('ascii'))
		return {k: json_decode_data(v) for k, v in obj.items()}
	elif isinstance(obj, list):
		return [json_decode_data(item) for item in obj]
	else:
		return obj

def run():
	txt = sys.stdin.readline().strip()
	if not txt:
		# parent process probably ended
		sys.exit(18)
	data = json.loads(txt.decode('utf-8') if isinstance(txt, bytes) else txt)
	[cmd, kwargs, cargs] = json_decode_data(data)
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

	# serialize response as JSON
	tmp = [ret, out, err, ex, trace]
	data = json_encode_data(tmp)
	obj = json.dumps(data)
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
