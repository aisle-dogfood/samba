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

def decode_subprocess_value(value):
	"""Decode special subprocess constants from JSON-safe format"""
	if isinstance(value, dict) and value.get('__subprocess_const__'):
		const_name = value['name']
		if const_name == 'PIPE':
			return subprocess.PIPE
		elif const_name == 'STDOUT':
			return subprocess.STDOUT
		elif const_name == 'DEVNULL' and hasattr(subprocess, 'DEVNULL'):
			return subprocess.DEVNULL
	return value

def decode_kwargs(kwargs):
	"""Recursively decode subprocess constants in kwargs dict"""
	result = {}
	for key, value in kwargs.items():
		result[key] = decode_subprocess_value(value)
	return result

def run():
	txt = sys.stdin.readline().strip()
	if not txt:
		# parent process probably ended
		sys.exit(18)
	
	data = json.loads(base64.b64decode(txt).decode('utf-8'))
	cmd = data['cmd']
	kwargs = decode_kwargs(data.get('kwargs', {}))
	cargs = data.get('cargs', {})

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

	# Encode binary output as base64 for JSON compatibility
	if out is not None and isinstance(out, bytes):
		out = base64.b64encode(out).decode('ascii')
		out_encoded = True
	else:
		out_encoded = False
	
	if err is not None and isinstance(err, bytes):
		err = base64.b64encode(err).decode('ascii')
		err_encoded = True
	else:
		err_encoded = False

	tmp = {
		'ret': ret,
		'out': out,
		'out_encoded': out_encoded,
		'err': err,
		'err_encoded': err_encoded,
		'ex': ex,
		'trace': trace
	}
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
