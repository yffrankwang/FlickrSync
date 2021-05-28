import os

# needs win32all to work on Windows
if os.name == 'nt':
	import multiprocessing

	locks = {}
	def lock(file):
		lock = multiprocessing.Lock()
		lock.acquire()
		locks[file.fileno()] = lock

	def unlock(file):
		lock = locks.get(file.fileno())
		if lock:
			lock.release()

elif os.name == 'posix':
	import fcntl
	from fcntl import LOCK_EX, LOCK_SH, LOCK_NB

	def lock(file, flags=LOCK_EX | LOCK_NB):
		fcntl.flock(file.fileno(), flags)

	def unlock(file):
		fcntl.flock(file.fileno(), fcntl.LOCK_UN)

else:
	raise RuntimeError("FileLock only support for nt and posix platforms")
