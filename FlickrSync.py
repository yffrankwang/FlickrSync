#!/usr/bin/python
# -*- coding: utf_8 -*-  
'''
FlickrSync

Sync files in local directory to Flickr.
'''
import codecs
import cStringIO
import json
import math
import fnmatch
import sys
import os
import re
import shutil
import logging
import datetime
import time
import pytz, tzlocal
import mimetools
import mimetypes
import Queue
import threading
import traceback
import urllib2
import webbrowser
import unicodedata
from xml.dom import minidom
import exifread
import flickr
import FileLock

try:
	from ConfigParser import ConfigParser
except Exception:
	from configparser import ConfigParser

LTZ = tzlocal.get_localzone()
SENC = sys.getdefaultencoding()
FENC = sys.getfilesystemencoding()
DT1970 = datetime.datetime.fromtimestamp(0).replace(tzinfo=LTZ)
LOG = None


if sys.version_info >= (3, 0):
	def unicode(s):
		return str(s)
	def raw_input(s):
		return input(s)

def normpath(s):
	return unicodedata.normalize('NFC', s)

LOCK = threading.Lock()
def uprint(s):
	with LOCK:
		try:
			print(s)
		except Exception:
			try:
				print(s.encode(SENC))
			except Exception:
				print(s.encode('utf-8'))

def tprint(i, s):
	n = datetime.datetime.now().strftime('%H:%M:%S ')
	uprint(u'%s %s %s' % (i, n, s))

def udebug(s):
	return
	tprint('-', s)
	if LOG:
		LOG.debug(s)

def uinfo(s):
	tprint('>', s)
	if LOG:
		LOG.info(s)

def uwarn(s):
	tprint('+', s)
	if LOG:
		LOG.warn(s)

def uerror(s):
	tprint('!', s)
	if LOG:
		LOG.error(s)

def uexception(ex):
	traceback.print_exc()
	if LOG:
		LOG.exception(ex)


def szstr(n):
	return "{:,}".format(n)

def todate(s):
	return datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%S%z').astimezone(LTZ)

def tmstr(t):
	return t.strftime('%Y-%m-%dT%H:%M:%S%z')

def utime(d):
	return d.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')

def mtime(p):
	return datetime.datetime.fromtimestamp(os.path.getmtime(p)).replace(microsecond=0, tzinfo=LTZ)

def ftime(dt):
	return tseconds(dt - DT1970)

def tseconds(td):
	return (td.seconds + td.days * 24 * 3600)

def touch(p, d = None):
	atime = ftime(datetime.datetime.now().replace(tzinfo=LTZ))
	mtime = atime if d is None else ftime(d)
	os.utime(p, ( atime, mtime ))

def mkpdirs(p):
	d = os.path.dirname(p)
	if not os.path.exists(d):
		os.makedirs(d)

def trimdir(p):
	if p == '':
		return p

	if p[-1] == os.path.sep:
		p = p[:-1]
	return unicode(p)


class APIConstants:
	base = "https://flickr.com/services/"
	rest   = base + "rest/"
	auth   = base + "auth/"
	upload = "https://up.flickr.com/services/upload/"
	update = "https://up.flickr.com/services/replace/"

	token = "auth_token"
	secret = "secret"
	key = "api_key"
	sig = "api_sig"
	frob = "frob"
	perms = "perms"
	method = "method"

	def __init__( self ):
		pass

class Config:
	"""Singleton style/static initialisation wrapper thing"""
	def __init__(self):
		self.dict = ConfigParser()
		paths = (os.path.abspath('.flickrsync.ini'), os.path.expanduser('~/.flickrsync.ini'))
		for filename in paths:
			if os.path.exists(filename):
				uinfo('using flickrsync.ini file "%s"' % os.path.abspath(filename))
				fp = codecs.open(filename, "r", "utf-8")
				self.dict.readfp(fp)
				fp.close()
				break

		# debug
		self.debug_log = self.get('debug_log', '')
		
		# error
		self.error_log = self.get('error_log', '')
		
		# Location
		self.root_dir = trimdir(os.path.abspath(self.get('root_dir', '.')))

		# self.get('trash_dir', self.root_dir + '/.trash')
		self.trash_dir = self.get('trash_dir', '')
		if self.trash_dir:
			self.trash_dir = trimdir(os.path.abspath(self.trash_dir))

		# user webbrowser
		self.webbrowser = True if self.get('webbrowser', 'true') == 'true' else False 

		# max_file_size (1GB)
		self.max_file_size = int(self.get('max_file_size', '1073741824'))

		# max retry
		self.max_retry = int(self.get('max_retry', '3'))
		
		# Threads
		self.max_threads = int(self.get('num_threads', '4'))

		# includes
		self.includes = json.loads(self.get('includes', '[]'))
		self.excludes = json.loads(self.get('excludes', '[]'))
		self.fileexts = self.get('fileexts', 'jpeg jpg gif png tiff avi mov m4v mp4 wmv').split()

		# tag split
		self.tag_split_re = self.get('tag_split_re', r'[\\/ ]')

		#Kodak cam EXIF tag  keyword
		self.exif_tag_keywords = self.get('exif_tag_keywords', 'Image XPKeywords')

		# keys
		self.secret = self.get('secret', 'bba29b1d2de7b850')
		self.api_key = self.get('api_key', 'f061bc1174e85d8cebe458e817dc515b')

		# token
		self.token_file = self.get('token_file', '.flickrsync.token')

		if os.path.exists(self.token_file):
			self.last_sync = mtime(self.token_file)
		else:
			self.last_sync = DT1970

		# Flickr settings
		self.hidden = self.get('hidden', 2)
		self.public = self.get('public', 0)
		self.friend = self.get('friend', 0)
		self.family = self.get('family', 1)

	def get(self, configparam, default=None):
		"""get the value from the ini file's default section."""
		defaults = self.dict.defaults()
		if configparam in defaults:
			return defaults[configparam]
		if not default is None:
			return default
		raise KeyError(configparam)


# global config
config = Config()

# init
mimetypes.init()

# global api constats
api = APIConstants()

class FlickrService:
	def __init__(self):
		flickr.API_KEY = config.api_key
		flickr.API_SECRET = config.secret
		flickr.AUTH = True

		self.path = os.path.abspath(config.token_file)
		self.file = None
		self.token = None
		self.perms = ""
		uinfo('Check user token ...')
		
		self._load_token()
		if not self._check_token():
			self._authenticate()

		try:
			self._lock_token()
		except Exception, e:
			uerror(str(e))
			raise Exception('Failed to lock %s' % self.path)

		self.user = flickr.test_login()
		uinfo("User ID: %s" % self.user.id)
	
	"""
	Signs args via md5 per Section 8 of
	http://www.flickr.com/services/api/auth.spec.html
	"""
	def _sign_call(self, data):
		flickr._convert_params(data)
		return flickr._sign_call(data)

	"""
	Creates the url from the template
	base/?key=value...&api_key=key&api_sig=sig
	"""
	def _url_gen(self, base, data):
		flickr._convert_params(data)
		return flickr._url_gen(base, data)

	"""
	Returns True if the response was OK.
	"""
	def _is_good(self, res):
		return not res == "" and res.stat == "ok"

	"""
	logs the error from the xml result and prints it too
	"""
	def _report_error(self, res):
		try:
			err = "Error:", str( res.err.code + " " + res.err.msg )
		except AttributeError:
			err = "Error: " + str( res )
		uerror(err)

	"""
	Send the url and get a response.  Let errors float up
	"""
	def _get_data(self, url):
		cnt = 0
		while True:
			try:
				cnt += 1
				res = urllib2.urlopen(url)
				data = res.read()
				res.close()
				return data
			except Exception, e:
				if cnt <= config.max_retry:
					uwarn(str(e))
					uwarn("Failed to get %s, retry %d" % (url, cnt))
					time.sleep(3)
				else:
					uerror("Failed to get %s" % url)
					uexception(e)
					raise

	"""
	Send the url and get a xml.  Let errors float up
	"""
	def _get_xml(self, url):
		data = self._get_data(url)
		xml = flickr.unmarshal(minidom.parse(cStringIO.StringIO(data)))
		return xml.rsp

	#
	# buildRequest/encodeMultipartFormdata code is from
	# http://www.voidspace.org.uk/atlantibots/pythonutils.html
	#
	def _build_request(self, theurl, fields, files, txheaders=None):
		"""
		Given the fields to set and the files to encode it returns a fully formed urllib2.Request object.
		You can optionally pass in additional headers to encode into the opject. (Content-type and Content-length will be overridden if they are set).
		fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
		files is a sequence of (name, filename, value) elements for data to be uploaded as files.
		"""
		content_type, body = self._encodeMultipartFormdata(fields, files)
		if not txheaders: txheaders = {}
		txheaders['Content-type'] = content_type
		txheaders['Content-length'] = str(len(body))

		return urllib2.Request(theurl, body, txheaders)

	def _encodeMultipartFormdata(self, fields, files, boundary = '-----'+mimetools.choose_boundary()+'-----'):
		""" Encodes fields and files for uploading.
		fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
		files is a sequence of (name, filename, value) elements for data to be uploaded as files.
		Return (content_type, body) ready for urllib2.Request instance
		You can optionally pass in a boundary string to use or we'll let mimetools provide one.
		"""
		crlf = '\r\n'
		L = []
		if isinstance(fields, dict):
			fields = fields.items()
		for (key, value) in fields:
			L.append('--' + boundary)
			L.append('Content-Disposition: form-data; name="%s"' % key)
			L.append('')
			L.append(value)
		for (key, filename, value) in files:
			filetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
			L.append('--' + boundary)
			L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
			L.append('Content-Type: %s' % filetype)
			L.append('')
			L.append(value)
		L.append('--' + boundary + '--')
		L.append('')
		body = crlf.join(L)
		content_type = 'multipart/form-data; boundary=%s' % boundary
		return content_type, body


	"""
	flickr.auth.getFrob

	Returns a frob to be used during authentication. This method call must be
	signed.

	This method does not require authentication.
	Arguments

	api.key (Required)
	Your API application key. See here for more details.
	"""
	def _getFrob( self ):
		d = {
			api.method  : "flickr.auth.getFrob"
			}
		url = self._url_gen(api.rest, d)
		try:
			response = self._get_xml(url)
			if self._is_good(response):
				return str(response.frob.text)
			else:
				raise Exception("Failed to get frob")
		except Exception, e:
			uerror("Error getting frob: %s" % str(sys.exc_info()))
			uexception(e)
			raise

	"""
	Checks to see if the user has authenticated this application
	"""
	def _authByUser(self, frob):
		d =  {
			api.frob : frob,
			api.perms : "delete"
			}
		url = self._url_gen(api.auth, d)

		print("Please authenticate this app with this url: \n%s" % url)
		if config.webbrowser:
			webbrowser.open( url )

		ans = raw_input("Have you authenticated this application? (Y/N): ")
		if ( ans.lower() != "y" ):
			print "You need to allow this program to access your Flickr site."
			print "A web browser should pop open with instructions."
			print "After you have allowed access restart uploadr.py"
			sys.exit()

	"""
	http://www.flickr.com/services/api/flickr.auth.getToken.html

	flickr.auth.getToken

	Returns the auth token for the given frob, if one has been attached. This method call must be signed.
	Authentication

	This method does not require authentication.
	Arguments

	NTC: We need to store the token in a file so we can get it and then check it insted of
	getting a new on all the time.

	api.key (Required)
	   Your API application key. See here for more details.
	frob (Required)
	   The frob to check.
	"""
	def _authenticate( self ):
		frob = self._getFrob()
		self._authByUser(frob)
		d = {
			api.method : "flickr.auth.getToken",
			api.frob : frob
		}

		url = self._url_gen(api.rest, d)
		try:
			res = self._get_xml(url)
			if self._is_good(res):
				self.token = str(res.auth.token.text)
				flickr.USER_TOKEN = self.token
				self.perms = str(res.auth.perms.text)
				self._save_token()
			else:
				self._report_error(res)
		except Exception, e:
			uerror("Failed to get token")
			uexception(e)
			raise

	"""
	flickr.auth.checkToken

	Returns the credentials attached to an authentication token.
	Authentication

	This method does not require authentication.
	Arguments

	api.key (Required)
		Your API application key. See here for more details.
	auth_token (Required)
		The authentication token to check.
	"""
	def _check_token( self ):
		if self.token is None:
			return False
		
		d = {
			api.token  :  str(self.token) ,
			api.method :  "flickr.auth.checkToken"
		}
		url = self._url_gen(api.rest, d)
		try:
			res = self._get_xml(url)
			if self._is_good(res):
				self.token = str(res.auth.token.text)
				self.perms = str(res.auth.perms.text)
				return True

			self._report_error(res)
			return False
		except Exception, e:
			logging.error("Failed to checkToken");
			logging.exception(e)
			raise

	"""
	Attempts to get the flickr token from disk.
	"""
	def _load_token( self ):
		self.token = None
		if os.path.exists(config.token_file):
			self.file = open(config.token_file)
			self.token = self.file.read()
			flickr.USER_TOKEN = self.token

	def _save_token( self ):
		try:
			if self.file:
				self.file.close()
			self.file = open(config.token_file, 'w')
			self.file.write(str(self.token))
			touch(self.path, config.last_sync)
		except Exception, e:
			uerror("Failed to save token to local cache: %s" % self.token)
			uexception(e)
			raise

	def _lock_token(self):
		FileLock.lock(self.file)

	def _exea(self, api, msg):
		cnt = 0
		while True:
			try:
				cnt += 1
				return api.execute()
			except Exception as e:
				if cnt <= config.max_retry:
					uwarn(str(e))
					uwarn("Failed to %s, retry %d" % (msg, cnt))
					time.sleep(3)
				else:
					uerror("Failed to %s" % msg)
					uexception(e)
					raise

	def download(self, url, npath):
		data = self._get_data(url)
		with open(npath, "wb") as f:
			f.write(data)

	def upload(self, photo):
		with open(photo.npath, 'rb') as f:
			data = f.read()

		photo.ispublic = str(config.public)
		photo.isfriend = str(config.friend)
		photo.isfamily = str(config.family)

		meta = { 'fsize': photo.fsize, 'mdate': tmstr(photo.mdate) }
		photo.description = json.dumps(meta)

		p = ('photo', urllib2.quote(photo.title.encode('utf8')), data)
		d = {
			api.token    : self.token,
			api.perms    : self.perms,
			"title"      : photo.title,
			"description": photo.description,
			"tags"	     : photo.tags,
			"hidden"	 : str(config.hidden),
			"is_public"  : photo.ispublic,
			"is_friend"  : photo.isfriend,
			"is_family"  : photo.isfamily
		}
		sig = self._sign_call(d)
		d[ api.sig ] = sig
		d[ api.key ] = config.api_key

		req = self._build_request(api.upload, d, (p,))
		res = self._get_xml(req)
		if self._is_good(res):
			photoid = str(res.photoid.text)
			return photoid
		else:
			self._report_error(res)
			return None

	def update(self, photo):
		with open(photo.npath, 'rb') as f:
			data = f.read()

		meta = { 'fsize': photo.fsize, 'mdate': tmstr(photo.mdate) }
		photo.description = json.dumps(meta)

		p = ('photo', urllib2.quote(photo.title.encode('utf8')), data)
		d = {
			api.token    : self.token,
			api.perms    : self.perms
		}
		sig = self._sign_call(d)
		d[ api.sig ] = sig
		d[ api.key ] = config.api_key

		req = self._build_request(api.update, d, (p,))
		res = self._get_xml(req)
		if self._is_good(res):
			photoid = str(res.photoid.text)
			photo.setMeta()
			return photoid
		else:
			self._report_error(res)
			return None

class FlickrSync:
	def __init__(self, service):
		'''
		:param service: The service of flickr.test_login.
		'''
		self.service = service
		self.rfiles = {}
		self.rpaths = {}
		self.albums = {}

		self.abandon = False
		self.syncQueue = None
		self.syncCount = 0
		self.rnews = {}
		self.skips = []

	def print_albums(self, albums):
		uprint("--------------------------------------------------------------------------------")

		tz = 0
		lp = ''
		ks = list(albums.keys())
		ks.sort()
		for n in ks:
			a = albums[n]
			uprint(u"  [%4d] %s" % (len(a), a.title))

		uprint("--------------------------------------------------------------------------------")
		uprint("Total %d albums" % (len(albums)))


	def print_photos(self, photos, url = False):
		uprint("--------------------------------------------------------------------------------")

		tz = 0
		ks = list(photos.keys())
		ks.sort()
		for n in ks:
			p = photos[n]

			tz += p.fsize
			uprint(u"  %s [%s] (%s) %s" % (p.title, szstr(p.fsize), tmstr(p.mdate), ("" if (not url) or (not p.url) else p.url)))

		uprint("--------------------------------------------------------------------------------")
		uprint("Total %d photos [%s]" % (len(photos), szstr(tz)))


	def print_updates(self, photos):
		if photos:
			uprint("--------------------------------------------------------------------------------")
			uprint("Photos to be synchronized:")
			for f in photos:
				uprint(u"%s: %s [%s] (%s) %s" % (f.action, f.title, szstr(f.fsize), tmstr(f.mdate), f.reason))


	def print_skips(self, photos):
		if photos:
			uprint("--------------------------------------------------------------------------------")
			uprint("Skipped photos:")
			for f in photos:
				uprint(u"%s: %s [%s] (%s) %s" % (f.action, f.title, szstr(f.fsize), tmstr(f.mdate), f.reason))


	def get(self, fid):
		api = self.service.files().get(fileId=fid)
		r = self.exea(api, "get")
		uprint(str(r))
		
	def sets(self, verb = False):
		uinfo('Get remote albums ...')
		self._get_albums()
		if verb:
			self.print_albums(self.albums)

	def _get_albums(self):
		if self.albums:
			return
		
		self.albums = {}
		pss = self.service.user.getPhotosets()
		if pss:
			for s in pss:
				self.albums[s.title] = s


	def list(self, verb = False, url = False):
		uinfo('Get remote files ...')

		self.rfiles = {}
		self.rpaths = {}

		rphotos = self.service.user.getPhotos()
		if rphotos:
			for p in rphotos:
				if not p.title:
					p.title = p.id
				if p.title[0] != '/':
					p.title = '/' + p.title
				
				if not self.accept_path(p.title):
					continue
				
				p.mdate = DT1970
				p.fsize = -1
				if p.description:
					try:
						a = json.loads(p.description)
						p.fsize = a['fsize']
						p.mdate = todate(a['mdate'])
					except Exception, e:
						uwarn('Invalid description: %s - %s' % (p.description, str(e)))
				p.action = ''
				p.reason = ''
				p.npath = os.path.abspath(config.root_dir + p.title)

				self.rpaths[p.title] = p
				self.rfiles[p.id] = p

			if verb:
				self.print_photos(self.rpaths, url)

	def accept_path(self, path):
		"""
		Return if name matches any of the ignore patterns.
		"""
		if config.excludes:
			for pat in config.excludes:
				if fnmatch.fnmatch(path, pat):
					return False
		
		if config.includes:
			for pat in config.includes:
				if fnmatch.fnmatch(path, pat):
					return True
			return False

		return True

	"""
	get all files in folders and subfolders
	"""
	def scan(self, verbose = False):
		rootdir = config.root_dir

		uinfo('Scan local files %s ...' % rootdir)
		
		lpaths = {}
		for dirpath, dirnames, filenames in os.walk(rootdir, topdown=True, followlinks=True):
			# do not walk into unacceptable directory
			dirnames[:] = [d for d in dirnames if not d[0] == '.' and self.accept_path(os.path.normpath(os.path.join(dirpath, d))[len(rootdir):].replace('\\', '/'))]

			for f in filenames:
				if f[0] == '.':
					continue

				np = os.path.normpath(os.path.join(dirpath, f))
				rp = np[len(rootdir):].replace('\\', '/')
				if not self.accept_path(rp):
					continue

				ext = os.path.splitext(f)[1].lower()
				if not ext:
					continue
				ext = ext[1:]
				if not (ext in config.fileexts):
					continue

				fp = flickr.Photo(0)
				fp.action = ''
				fp.reason = ''
				fp.npath = np
				fp.title = normpath(rp)
				fp.fsize = os.path.getsize(np)
				fp.mdate = mtime(np)
				lpaths[fp.title] = fp

		self.lpaths = lpaths
		
		if verbose:
			self.print_photos(lpaths)

	"""
	find remote patch files
	"""
	def find_remote_patches(self):
		lps = []
		for lp,lf in self.lpaths.items():
			# check patchable
			rf = self.rpaths.get(lp)
			if rf and lf.fsize == rf.fsize and math.fabs(tseconds(rf.mdate - lf.mdate)) > 2:
				lf.action = '^~'
				lf.reason = '| <> R:' + tmstr(rf.mdate)
				lps.append(lp)

		lps.sort()
		ufiles = [ ]
		for lp in lps:
			ufiles.append(self.lpaths[lp])
		
		self.print_updates(ufiles)
		return ufiles

	"""
	find local touch files
	"""
	def find_local_touches(self):
		rps = []
		for rp,rf in self.rpaths.items():
			# check touchable
			lf = self.lpaths.get(rp)
			if lf and lf.fsize == rf.fsize and math.fabs(tseconds(rf.mdate - lf.mdate)) > 2:
				rf.action = '>~'
				rf.reason = '| <> L:' + tmstr(lf.mdate)
				rps.append(rp)

		rps.sort()
		ufiles = [ ]
		for rp in rps:
			ufiles.append(self.rpaths[rp])
		
		self.print_updates(ufiles)
		return ufiles

	"""
	find local updated files
	"""
	def find_local_updates(self, lastsync = None, force = False):
		lps = []
		for lp,lf in self.lpaths.items():
			# check updateable
			rf = self.rpaths.get(lp)
			if rf:
				if tseconds(lf.mdate - rf.mdate) <= 2:
					if not force or lf.fsize == rf.fsize:
						continue
				lf.action = '^*'
				lf.reason = '| > R:' + tmstr(rf.mdate)
			elif lastsync:
				if tseconds(lf.mdate - lastsync) > 2:
					lf.action = '^+'
				else:
					lf.action = '>-'
			else:
				lf.action = '^+'

			lps.append(lp)

		lps.sort()
		ufiles = [ ]
		for lp in lps:
			ufiles.append(self.lpaths[lp])
		
		# force to trash remote items that does not exist in local
		if force:
			# trash remote files
			for rp,rf in self.rpaths.items():
				if not rp in self.lpaths:
					rf.action = '^-'
					ufiles.append(rf)

		self.print_updates(ufiles)
		return ufiles

	"""
	find remote updated files
	"""
	def find_remote_updates(self, lastsync = None, force = False):
		rps = []
		for rp,rf in self.rpaths.items():
			# check updateable
			lf = self.lpaths.get(rp)
			if lf:
				if rf.mdate - lf.mdate <= 2:
					if not force or lf.fsize == rf.fsize:
						continue
				rf.action = '>*'
				rf.reason = '| > L:' + tmstr(lf.mdate)
			elif lastsync:
				if tseconds(rf.mdate - lastsync) > 2:
					rf.action = '>+'
				else:
					rf.action = '^-'
			else:
				rf.action = '>+'

			rps.append(rp)

		rps.sort()
		ufiles = [ ]
		for rp in rps:
			ufiles.append(self.rpaths[rp])
		
		
		# force to trash local items that does not exist in remote
		if force:
			# trash local files
			for lp,lf in self.lpaths.items():
				if not lp in self.rpaths:
					lf.action = '>-'
					ufiles.append(lf)

		self.print_updates(ufiles)
		return ufiles

	"""
	find synchronizeable files
	"""
	def find_sync_files(self):
		lfiles = self.find_local_updates(config.last_sync)
		rfiles = self.find_remote_updates(config.last_sync)

		sfiles = lfiles + rfiles
		spaths = {}
		for sf in sfiles:
			if sf.title in spaths:
				raise Exception('Duplicated sync file: %s' % sf.title)
			spaths[sf.title] = sf
			
		return sfiles

	def sync_file(self, sf):
		if sf.action == '^-':
			self.trash_remote_file(sf)
		elif sf.action == '^*':
			rf = self.rpaths[sf.title]
			self.update_remote_file(rf, sf)
		elif sf.action == '^+':
			self.insert_remote_file(sf)
		elif sf.action == '^~':
			rf = self.rpaths[sf.title]
			self.patch_remote_file(rf, sf.mdate, sf.fsize)
		elif sf.action in ('>*', '>+'):
			self.download_remote_file(sf)
		elif sf.action == '>/':
			self.create_local_dirs(sf)
		elif sf.action == '>-':
			self.trash_local_file(sf)
		elif sf.action == '>!':
			self.remove_local_file(sf)
		elif sf.action == '>~':
			lf = self.lpaths[sf.title]
			self.touch_local_file(lf, sf.mdate)

	def upload_files(self, lfiles):
		self.sync_files(lfiles)

	def dnload_files(self, rfiles):
		self.sync_files(rfiles)

	def touch_files(self, pfiles):
		self.sync_files(pfiles)

	def patch_files(self, pfiles):
		self.sync_files(pfiles)

	def patch(self, noprompt):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()

		pfiles = self.find_remote_patches()
		if pfiles:
			if not noprompt:
				ans = raw_input("Are you sure to patch %d remote files? (Y/N): " % (len(pfiles)))
				if ans.lower() != "y":
					return
			self.patch_files(pfiles)
			uprint("--------------------------------------------------------------------------------")
			uinfo("PATCH Completed!")
		else:
			uinfo('No files need to be patched.')

	def touch(self, noprompt):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()

		pfiles = self.find_local_touches()
		if pfiles:
			if not noprompt:
				ans = raw_input("Are you sure to touch %d local files? (Y/N): " % (len(pfiles)))
				if ans.lower() != "y":
					return
			self.touch_files(pfiles)
			uprint("--------------------------------------------------------------------------------")
			uinfo("TOUCH Completed!")
		else:
			uinfo('No files need to be touched.')

	def push(self, force = False, noprompt = False):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()
		
		# find files that are in folders and not in remote
		ufiles = self.find_local_updates(None, force)
		
		if ufiles:
			if not noprompt:
				ans = raw_input("Are you sure to push %d files to Flickr? (Y/N): " % len(ufiles))
				if ans.lower() != "y":
					return

			self.upload_files(ufiles)
			if force:
				self.up_to_date()
			uprint("--------------------------------------------------------------------------------")
			uinfo("PUSH %s Completed!" % ('(FORCE)' if force else ''))
		else:
			uprint("--------------------------------------------------------------------------------")
			uinfo('No files need to be uploaded to remote server.')

	def pull(self, force = False, noprompt = False):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()
		
		# find files that are in folders and not in remote
		dfiles = self.find_remote_updates(None, force)
		
		if dfiles:
			if not noprompt:
				ans = raw_input("Are you sure to pull %d files to local? (Y/N): " % len(dfiles))
				if ans.lower() != "y":
					return

			self.dnload_files(dfiles)
			if force:
				self.up_to_date()
			uprint("--------------------------------------------------------------------------------")
			uinfo("PULL %s Completed!" % ('(FORCE)' if force else ''))
		else:
			uprint("--------------------------------------------------------------------------------")
			uinfo('No files need to be downloaded to local.')

	def sync(self, noprompt):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()
		
		# find files that are need to be sync
		sfiles = self.find_sync_files()
		
		if sfiles:
			if not noprompt:
				ans = raw_input("Are you sure to sync %d files? (Y/N): " % len(sfiles))
				if ans.lower() != "y":
					return
			self.sync_files(sfiles)
			self.up_to_date()
			uprint("--------------------------------------------------------------------------------")
			uinfo("SYNC Completed!")
		else:
			self.up_to_date()
			uprint("--------------------------------------------------------------------------------")
			uinfo('No files need to be synchronized.')


	def up_to_date(self):
		touch(config.token_file)

	def trash_remote_file(self, file):
		"""
		Move a remote file to the trash.
		"""
		uinfo("%s ^TRASH^  %s [%s] (%s)" % (self.prog(), file.title, szstr(file.fsize), tmstr(file.mdate)))

		file.delete()
		with LOCK:
			self.rfiles.pop(file.id, file)
			self.rpaths.pop(file.title, file)

	def read_exif(self, lf):
		'''
		Insert a file to remote.
		'''
		udebug("Getting EXIF for %s" % lf.title)

		with open(lf.npath, 'rb') as f:
			try:
				exiftags = exifread.process_file(f)
			except:
				exiftags = {}
		
		# make one tag equal to original file path with spaces replaced by
		# # and start it with # (for easier recognition) since space is
		# used as TAG separator by flickr

		# split path to make tags
		tags = ''
		ts = re.split(config.tag_split_re, lf.title)
		for t in ts:
			if t:
				tags += t.replace(' ', '_') + ' '

		if exiftags == {}:
			udebug('NO_EXIF_HEADER for %s' % lf.title)
		else:
			# look for additional tags in EXIF to tag picture with
			if config.exif_tag_keywords in exiftags:
				printable = exiftags[config.exif_tag_keywords].printable
				if len(printable) > 4:
					exifstring = exifread.make_string(eval(printable))
					tags += exifstring.replace(';', ' ')

		lf.tags = tags.strip()
	
	def insert_remote_file(self, lf):
		if lf.fsize > config.max_file_size:
			self.skips.append(lf)
			uwarn("%s Unable to upload %s, File size [%s] exceed the limit" % (self.prog(), lf.title, szstr(lf.fsize)))
			return

		self.read_exif(lf)

		'''
		Upload a file to remote.
		'''
		uinfo("%s ^UPLOAD^ %s [%s] (%s) #(%s)" % (self.prog(), lf.title, szstr(lf.fsize), tmstr(lf.mdate), lf.tags))
		lf.id = self.service.upload(lf)
		if lf.id:
			with LOCK:
				# add to remote files
				self.rfiles[lf.id] = lf
				self.rpaths[lf.title] = lf
				self.rnews[lf.title] = lf

	def update_remote_file(self, rf, lf):
		if lf.fsize > config.max_file_size:
			self.skips.append(lf)
			uwarn("%s Unable to update %s, File size [%s] excceed the limit" % (self.prog(), lf.title, szstr(lf.fsize)))
			return

		self.read_exif(lf)

		'''
		Update a file to remote.
		'''
		uinfo("%s ^UPDATE^ %s [%s] (%s) #(%s)" % (self.prog(), lf.title, szstr(lf.fsize), tmstr(lf.mdate), lf.tags))

		lf.id = self.service.update(lf)
		if lf.id:
			rf.fsize = lf.fsize
			rf.mdate = lf.mdate
			rf.description = lf.description
			rf.tags = lf.tags

	def download_remote_file(self, rf):
		uinfo("%s >DNLOAD> %s [%s] (%s)" % (self.prog(), rf.title, szstr(rf.fsize), tmstr(rf.mdate)))
		
		mkpdirs(rf.npath)

		if rf.fsize == 0:
			with open(rf.npath, "wb") as f:
				pass
		else:
			url = rf.url
			if rf.media == 'video':
				url = rf.getURL('Video Original', 'source')
				uinfo("%s >>URL>>  %s" % (self.prog(), url))
			self.service.download(url, rf.npath)

		touch(rf.npath, rf.mdate)

	def patch_remote_file(self, rf, mdate, fsize):
		'''
		Patch a remote file.
		'''
		uinfo("%s ^PATCH^  %s [%s] (%s)" % (self.prog(), rf.title, szstr(fsize), tmstr(mdate)))

		meta = { 'fsize': fsize, 'mdate': tmstr(mdate) }
		desc = json.dumps(meta)
		
		rf.setMeta(rf.title, desc)

		rf.mdate = mdate
		rf.fsize = fsize
		return rf

	def touch_local_file(self, lf, mt):
		'''
		Touch a local file.
		'''
		uinfo("%s >TOUCH>  %s [%s] (%s)" % (self.prog(), lf.title, szstr(lf.fsize), tmstr(mt)))

		touch(lf.npath, mt)

		lf.mdate = mt
		return lf

	def create_local_dirs(self, lf):
		np = file.npath
		if os.path.exists(np):
			return

		uinfo("%s >CREATE> %s" % (self.prog(), lf.title))
		os.makedirs(np)

	def trash_local_file(self, lf):
		if config.trash_dir:
			uinfo("%s >TRASH>  %s" % (self.prog(), lf.title))
	
			np = config.trash_dir + lf.title
			mkpdirs(np)
			
			if os.path.exists(np):
				os.remove(np)
			
			shutil.move(lf.npath, np)
		else:
			uinfo("%s >REMOVE>  %s" % (self.prog(), lf.path))
			os.remove(lf.npath)

	def remove_local_file(self, lf):
		uinfo("%s >REMOVE> %s" % (self.prog(), lf.title))

		np = lf.npath
		if os.path.exists(np):
			os.rmdir(np)
		
	def prog(self):
		return ('[%d/%d]' % (self.syncCount - self.syncQueue.qsize(), self.syncCount))

	def sync_files(self, sfiles):
		self.syncCount = len(sfiles)
		self.syncQueue = Queue.Queue()
		for sf in sfiles:
			self.syncQueue.put_nowait(sf)

		# start sync threads
		threads = []
		for i in xrange( config.max_threads ):
			thread = SyncThread(i + 1, self)
			threads.append(thread)
			thread.start()
		
		# wait upload threads stop
		while threads:
			try:
				for thrd in threads:
					thrd.join(0.05)
					if not thrd.isAlive():
						threads.remove(thrd)
						break
			except KeyboardInterrupt:
				uinfo("Keyboard interrupt seen, abandon threads")
				uprint(">>>>>> Stopping threads...")
				self.abandon = True

		if not self.abandon and self.rnews:
			# start Album thread
			thrd = AlbumThread(self)
			thrd.start()
			
			while thrd.isAlive():
				try:
					thrd.join(0.05)
				except KeyboardInterrupt:
					uinfo("Keyboard interrupt seen, abandon threads")
					uprint(">>>>>> Stopping threads...")
					self.abandon = True
		
		self.print_skips(self.skips)

	def sync_run(self):
		while not self.abandon:
			try:
				sf = self.syncQueue.get_nowait()
				self.sync_file(sf)
			except Queue.Empty:
				break
			except Exception, e:
				uexception(e)


	def clear_albums(self, noprompt = False):
		if not noprompt:
			ans = raw_input("Are you sure to clear remote albums? (Don't worry, none of the photos will be deleted.) (Y/N): ")
			if ans.lower() != "y":
				return

		self.sets(True);
		if not self.albums:
			return
		
		t = len(self.albums)
		i = 0
		for k,a in self.albums.items():
			i += 1
			uinfo("[%d/%d] Delete album [%s]: %s" % (i, t, str(a.id), a.title))
			a.delete()

	def update_albums(self, ps):
		self.sets()

		uinfo("Updating albums ...")
		pns = list(ps.keys())
		pns.sort()
		
		lastSetName = ''
		aps = []  # album photos
		upd = False
		for pn in pns:
			if self.abandon:
				return

			setName = os.path.dirname(pn)
			if lastSetName == '':
				lastSetName = setName
			
			if lastSetName == setName:
				aps.append(ps[pn])
				if self.rnews.get(pn):
					upd = True
				continue
			
			if aps and upd:
				self.update_album(lastSetName, aps)
			lastSetName = setName
			aps = [ ps[pn] ]
			upd = True if self.rnews.get(pn) else False

		if aps and upd:
			self.update_album(lastSetName, aps)

	def build_albums(self, ps = None):
		self.sets()

		if ps is None:
			self.list()
			ps = self.rpaths

		uinfo("Building Albums ...")
		pns = list(ps.keys())
		pns.sort()
		
		lastSetName = ''
		aps = []  # album photos
		for pn in pns:
			if self.abandon:
				return

			setName = os.path.dirname(pn)
			if lastSetName == '':
				lastSetName = setName
			
			if lastSetName == setName:
				aps.append(ps[pn])
				continue
			
			self.update_album(lastSetName, aps)
			aps = [ ps[pn] ]
			lastSetName = setName

		if aps:
			self.update_album(lastSetName, aps)

	"""
	Creates or updates a album/set on flickr with the given photos.
	"""
	def update_album(self, setName, photos):
		fset = self.albums.get(setName, None)

		#check if set with the name exists already
		generate = 'Building'
		if not fset is None:
			udebug('Found existing set %s' % setName)
			generate = 'Updating'

		msg = "%s album [%s] with %d photos" % (generate, setName, len(photos))
		uinfo(msg)

		if fset is None:
			udebug("Create album [%s] with photo %s" % (setName, photos[0].title))
			fset = flickr.Photoset.create(photos[0], setName, "Auto-generated by FlickrSync")
			self.albums[fset.title] = fset

		if len(photos) > 1:
			udebug('Add %d photos to album/set [%s]' % (len(photos), setName))
			fset.editPhotos(photos)

	def list_album_photos(self, atitle):
		self.tree()

		a = self.albums.get(atitle)
		if a:
			uinfo("List photos of album [%s]:" % (atitle))
			ps = a.getPhotos()
			self.print_photos(ps)
		else:
			uinfo("Album [%s] not found" % (atitle))

	def delete_album(self, atitle, noprompt = False):
		self.tree()

		a = self.albums.get(atitle)
		if a:
			if not noprompt:
				ans = raw_input("Are you sure to delete remote album [%s]? (Don't worry, none of the contents will be deleted.) (Y/N): " % atitle)
				if ans.lower() != "y":
					return

			uinfo("Delete album [%s]: %s" % (str(a.id), a.title))
			a.delete()
		else:
			uinfo("Album [%s] not found" % (atitle))

	def drop_album(self, atitle, noprompt = False):
		self.tree()

		a = self.albums.get(atitle)
		if a:
			if not noprompt:
				ans = raw_input("Are you sure to delete remote album [%s] and it's photos? (Y/N): " % atitle)
				if ans.lower() != "y":
					return

			ps = a.getPhotos()
			t = len(ps)
			i = 0
			for p in ps:
				i += 1
				uinfo("[%d/%d] Delete photo [%s]: %s" % (i, t, str(p.id), p.title))
				p.delete()

			uinfo("Delete album [%s]: %s" % (str(a.id), a.title))
			a.delete()
		else:
			uinfo("Album [%s] not found" % (atitle))

	def drop(self, noprompt=False):
		self.list()
		pns = list(self.rpaths.keys())
		if not pns:
			return

		if not noprompt:
			ans = raw_input("Are you sure to delete all remote photos? (Y/N): ")
			if ans.lower() != "y":
				return

		sfiles = []
		pns.sort()
		for k in pns:
			p = self.rpaths[k]
			p.action = '^-'
			sfiles.append(p)

		self.sync_files(sfiles)
		self.up_to_date()
		uprint("--------------------------------------------------------------------------------")
		uinfo("DROP Completed!")


class SyncThread(threading.Thread):
	def __init__(self, threadID, syncFlickr):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.syncFlickr = syncFlickr

	def run(self):
		uinfo("Starting SyncThread %d " % self.threadID)

		self.syncFlickr.sync_run()

		uinfo("Exiting SyncThread %d " % self.threadID)

class AlbumThread(threading.Thread):
	def __init__(self, syncFlickr):
		threading.Thread.__init__(self)
		self.syncFlickr = syncFlickr

	def run(self):
		self.syncFlickr.update_albums(self.syncFlickr.rpaths)


def help():
	print("flickrsync.py <command> ...")
	print("  <command>: ")
	print("    help                print command usage")
	print("    get <id>            print remote file info")
	print("    tree                list remote albums")
	print("      [-?]              exclude file pattern")
	print("      [+?]              include file pattern")
	print("    sets [cmd]          list remote albums")
	print("      [cmd]:")
	print("        clear [go]      clear remote albums")
	print("        build [go]      build remote albums")
	print("    set [cmd] [album]")
	print("      [cmd]:");
	print("        list            list remote photos of the album")
	print("        delete [go]     delete remote album only")
	print("        drop   [go]     delete remote album and it's photos")
	print("    list                list remote files")
	print("      [url]             print remote file URL")
	print("      [-?]              exclude file pattern")
	print("      [+?]              include file pattern")
	print("    scan                scan local files")
	print("    pull [go] [force]   download remote files")
	print("      [force]           force to update file whose size is different")
	print("                        force to trash file that not exists in remote")
	print("      [go]              no confirm (always yes)")
	print("    push [go] [force]   upload local files")
	print("      [force]           force to update file whose size is different")
	print("                        force to trash file that not exists in local")
	print("    sync [go]           synchronize local <--> remote files")
	print("    touch [go]          set local file's modified date by remote")
	print("    patch [go]          set remote file's modified date by local")
	print("    drop                delete all remote files")
	print("")
	print("  <marks>: ")
	print("    ^-: trash remote file")
	print("    ^*: update remote file")
	print("    ^+: add remote file")
	print("    ^~: patch remote file timestamp")
	print("    >*: update local file")
	print("    >+: add local file")
	print("    >/: add local folder")
	print("    >-: trash local file")
	print("    >!: remove local file")
	print("    >~: touch local file timestamp")


"""
Initial entry point for the uploads
"""
def main(args):
	global LOG

	LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
	logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

	rlog = logging.getLogger('')
	rlog.handlers = [ logging.NullHandler() ]

	dbglog = config.debug_log
	if dbglog:
		debugs = logging.FileHandler(dbglog)
		debugs.setLevel(logging.DEBUG)
		debugs.setFormatter(logging.Formatter(LOG_FORMAT))
		rlog.addHandler(debugs)
		
	errlog = config.error_log
	if errlog:
		errors = logging.FileHandler(errlog)
		errors.setLevel(logging.ERROR)
		errors.setFormatter(logging.Formatter(LOG_FORMAT))
		rlog.addHandler(errors)

	LOG = logging.getLogger("flickrsync")
	LOG.setLevel(logging.INFO)
	#logh = logging.StreamHandler()
	#logh.setFormatter(logging.Formatter(LOG_FORMAT))
	#LOG.addHandler(logh)

	cmd = ''
	if len(args) > 0:
		cmd = args[0]
	if cmd == 'help':
		help()
		exit(0)

	uinfo('Start...')

	fc = FlickrService()
	fs = FlickrSync(fc)
	
	opt1 = '' if len(args) < 2 else args[1]
	opt2 = '' if len(args) < 3 else args[2]

	if cmd == 'get':
		fs.get(opt1)
	elif cmd == 'list':
		url = False
		idx = 1
		while (idx < len(args)):
			opt = args[idx]
			idx += 1
			if len(opt) < 1:
				continue
			if opt == 'url':
				url = True
				continue			
			ch = opt[0]
			if ch == '+':
				config.includes = opt[1:].split()
			elif ch == '-':
				config.excludes = opt[1:].split()
		fs.list(True, url)
	elif cmd == 'tree':
		idx = 1
		while (idx < len(args)):
			opt = args[idx]
			idx += 1
			if len(opt) < 1:
				continue
			ch = opt[0]
			if ch == '+':
				config.includes = opt[1:].split()
			elif ch == '-':
				config.excludes = opt[1:].split()
		fs.sets(True)
	elif cmd == 'sets':
		if opt1 == 'clear':
			fs.clear_albums(True if 'go' in args else False)
		elif opt1 == 'build':
			fs.build_albums()
		else:
			fs.sets(True)
	elif cmd == 'set':
		if opt1 == 'list':
			fs.list_album_photos(opt2)
		elif opt1 == 'delete':
			fs.delete_album(opt2, True if 'go' in args else False)
		elif opt1 == 'drop':
			fs.drop_album(opt2, True if 'go' in args else False)
	elif cmd == 'scan':
		fs.scan(True)
	elif cmd == 'drop':
		fs.drop(True if 'go' in args else False)
	elif cmd == 'push':
		fs.push(True if 'force' in args else False, True if 'go' in args else False)
	elif cmd == 'pull':
		fs.pull(True if 'force' in args else False, True if 'go' in args else False)
	elif cmd == 'sync':
		fs.sync(opt1)
	elif cmd == 'patch':
		fs.patch(True if 'go' in args else False)
	elif cmd == 'touch':
		fs.touch(True if 'go' in args else False)
	else:
		help()

if __name__ == "__main__":
	try:
		main(sys.argv[1:])
	except IOError, ex:
		print ex

