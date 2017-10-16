#!/usr/bin/python
# -*- coding: utf_8 -*-  
'''
FlickrSync

Sync files in local directory to Flickr.
'''
import codecs
import math
import fnmatch
import sys
import os
import re
import shutil
import logging
import datetime
import time
import tzlocal
import dateutil.parser
import random
import mimetypes
import threading
import traceback
import urllib
import webbrowser
import unicodedata
import json
import FileLock
from io import BytesIO
import httplib2
import oauth2 as oauth

try:
	from urlparse import parse_qsl
except ImportError:
	from cgi import parse_qsl

try:
	from ConfigParser import ConfigParser
except Exception:
	from configparser import ConfigParser

# We need to import a XML Parser because Flickr doesn't return JSON for photo uploads -_-
try:
	from lxml import etree
except ImportError:
	try:
		# Python 2.5
		import xml.etree.cElementTree as etree
	except ImportError:
		try:
			# Python 2.5
			import xml.etree.ElementTree as etree
		except ImportError:
			try:
				#normal cElementTree install
				import cElementTree as etree
			except ImportError:
				try:
					# normal ElementTree install
					import elementtree.ElementTree as etree
				except ImportError:
					raise ImportError('Failed to import ElementTree from any known place')

if sys.version_info >= (3, 0):
	import queue
	def urlopen(u):
		return urllib.request.urlopen(u)
	def urlquote(u):
		return urllib.parse.quote(u)
	def urlencode(u):
		return urllib.parse.urlencode(u)
	def unicode(s):
		return str(s)
	def raw_input(s):
		return input(s)
else:
	import Queue
	queue = Queue
	
	import urllib2
	def urlopen(u):
		return urllib2.urlopen(u)
	def urlquote(u):
		return urllib.quote(u)
	def urlencode(u):
		return urllib.urlencode(u)

try:
	# Python 2.6-2.7 
	from HTMLParser import HTMLParser
except ImportError:
	# Python 3
	from html.parser import HTMLParser

#------------------------------------------------
LOG = None
HP = HTMLParser()
UTF8 = codecs.lookup('utf-8')[3]
LTZ = tzlocal.get_localzone()
SENC = sys.getdefaultencoding()
FENC = sys.getfilesystemencoding()
DT1970 = datetime.datetime.fromtimestamp(0)
LOCK = threading.Lock()

# init
mimetypes.init()


#------------------------------------------------
def normpath(s):
	return unicodedata.normalize('NFC', s)

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
	return dateutil.parser.parse(s).replace(microsecond=0).astimezone(LTZ).replace(tzinfo=None)

def tmstr(t):
	return t.strftime('%Y-%m-%d %H:%M:%S')

def mtstr(t):
	return LTZ.localize(t).strftime('%Y-%m-%dT%H:%M:%S%z')

def mtime(p):
	return datetime.datetime.fromtimestamp(os.path.getmtime(p)).replace(microsecond=0)

def ftime(dt):
	return tseconds(dt - DT1970)

def tseconds(td):
	return (td.seconds + td.days * 24 * 3600)

def touch(p, d = None):
	atime = ftime(datetime.datetime.now())
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


def get_content_type(filename):
	return mimetypes.guess_type(filename)[0] or 'application/octet-stream'


def iter_fields(fields):
	"""Iterate over fields.
		Supports list of (k, v) tuples and dicts.
	"""
	if isinstance(fields, dict):
		return ((k, v) for k, v in fields.iteritems())
	return ((k, v) for k, v in fields)


def get_json_item(o):
	if o:
		if isinstance(o, dict):
			o = o.get('_content');
		if o:
			o = HP.unescape(o)
	return o


def print_progress(page, pages):
	if pages == 0:
		page = 0
	sys.stdout.write("\b\b\b\b\b\b\b%3d/%-3d" % (page, pages))
	sys.stdout.flush()


#---------------------------------------------------------------
class Config:
	"""Singleton style/static initialization wrapper thing"""
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

		# user web browser
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
		self.tag_split_re = self.get('tag_split_re', r'[\\/ ,\_\-.;:]')

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

#-------------------------------------------------------------------
class FlickrAPIError(Exception):
	""" Generic error class, catch-all for most Tumblpy issues.
		from Tumblpy import FlickrAPIError, FlickrAuthError
	"""
	def __init__(self, msg, error_code=None):
		self.msg = msg
		self.code = error_code
		if error_code is not None and error_code < 100:
			raise FlickrAuthError(msg, error_code)

	def __str__(self):
		return repr(self.msg)


class FlickrAuthError(FlickrAPIError):
	""" Raised when you try to access a protected resource and it fails due to some issue with your authentication. """
	def __init__(self, msg, error_code=None):
		self.msg = msg
		self.code = error_code

	def __str__(self):
		return repr(self.msg)


class FlickrAPI(object):
	def __init__(self, api_key=None, api_secret=None, oauth_token=None, oauth_token_secret=None, callback_url=None, headers=None, client_args=None):
		if not api_key or not api_secret:
			raise FlickrAPIError('Please supply an api_key and api_secret.')

		self.api_key = api_key
		self.api_secret = api_secret
		self.callback_url = callback_url

		self.api_base = 'https://api.flickr.com/services'
		self.up_api_base = 'https://up.flickr.com/services'
		self.rest_api_url = '%s/rest' % self.api_base
		self.upload_api_url = '%s/upload/' % self.up_api_base
		self.replace_api_url = '%s/replace/' % self.up_api_base
		self.request_token_url = 'https://www.flickr.com/services/oauth/request_token'
		self.access_token_url = 'https://www.flickr.com/services/oauth/access_token'
		self.authorize_url = 'https://www.flickr.com/services/oauth/authorize'

		self.headers = headers
		if self.headers is None:
			self.headers = {'User-agent': 'PythonFlickrSync'}

		self.oauth_token = None
		self.oauth_token_secret = None
		self.consumer = None
		self.token = None
		
		self.set_oauth_token(oauth_token, oauth_token_secret, client_args)


	def set_oauth_token(self, oauth_token, oauth_token_secret, client_args=None):
		self.oauth_token = oauth_token
		self.oauth_token_secret = oauth_token_secret
		self.client_args = client_args or {}

		if self.api_key is not None and self.api_secret is not None:
			self.consumer = oauth.Consumer(self.api_key, self.api_secret)

		if self.oauth_token is not None and self.oauth_token_secret is not None:
			self.token = oauth.Token(oauth_token, oauth_token_secret)

	def get_http(self):
		# Filter down through the possibilities here - if they have a token, if they're first stage, etc.
		if self.consumer is not None and self.token is not None:
			return oauth.Client(self.consumer, self.token, **self.client_args)
		elif self.consumer is not None:
			return oauth.Client(self.consumer, **self.client_args)
		else:
			# If they don't do authentication, but still want to request unprotected resources, we need an opener.
			return httplib2.Http(**self.client_args)
		
	def get_authentication_tokens(self, perms=None):
		""" Returns an authorization url to give to your user.

			Parameters:
			perms - If None, this is ignored and uses your applications default perms. If set, will overwrite applications perms; acceptable perms (read, write, delete)
						* read - permission to read private information
						* write - permission to add, edit and delete photo metadata (includes 'read')
						* delete - permission to delete photos (includes 'write' and 'read')
		"""

		request_args = {}
		resp, content = self.get_http().request('%s?oauth_callback=%s' % (self.request_token_url, self.callback_url), 'GET', **request_args)

		if resp['status'] != '200':
			raise FlickrAuthError('There was a problem retrieving an authentication url.')

		request_tokens = parse_qsl(content)
		request_tokens = dict(request_tokens)

		auth_url_params = {
			'oauth_token': request_tokens[b'oauth_token']
		}

		accepted_perms = ('read', 'write', 'delete')
		if perms and perms in accepted_perms:
			auth_url_params['perms'] = perms

		request_tokens['auth_url'] = '%s?%s' % (self.authorize_url, urlencode(auth_url_params))
		return request_tokens

	def get_auth_tokens(self, oauth_verifier):
		""" Returns 'final' tokens to store and used to make authorized calls to Flickr.

			Parameters:
				oauth_token - oauth_token returned from when the user is redirected after hitting the get_auth_url() function
				verifier - oauth_verifier returned from when the user is redirected after hitting the get_auth_url() function
		"""

		params = {
			'oauth_verifier': oauth_verifier,
		}

		resp, content = self.get_http().request('%s?%s' % (self.access_token_url, urlencode(params)), 'GET')
		if resp['status'] != '200':
			raise FlickrAuthError('Getting access tokens failed: %s Response Status' % resp['status'])

		return dict(parse_qsl(content))

	def _convert_params(self, params):
		"""Convert lists to strings with ',' between items."""
		for (key, value) in params.items():
			if isinstance(value, (int, long)):
				params[key] = str(value)
			elif urllib._is_unicode(value):
				params[key] = value.encode('UTF-8')
			elif isinstance(value, list):
				params[key] = ','.join([item for item in value])

	def api_request(self, endpoint=None, method='GET', params={}, files=None, replace=False):
		headers = {}
		headers.update(self.headers)
		headers.update({'Content-Type': 'application/json'})
		headers.update({'Content-Length': '0'})

		if endpoint is None and files is None:
			raise FlickrAPIError('Please supply an API endpoint to hit.')

		qs = {
			'format': 'json',
			'nojsoncallback': 1,
			'method': endpoint,
			'api_key': self.api_key
		}
		self._convert_params(params)
		
		if method == 'POST':
			if files is not None:
				# To upload/replace file, we need to create a fake request
				# to sign parameters that are not multipart before we add
				# the multipart file to the parameters...
				# OAuth is not meant to sign multipart post data
				http_url = self.replace_api_url if replace else self.upload_api_url
				faux_req = oauth.Request.from_consumer_and_token(self.consumer,
																 token=self.token,
																 http_method="POST",
																 http_url=http_url,
																 parameters=params)

				faux_req.sign_request(oauth.SignatureMethod_HMAC_SHA1(),
									  self.consumer,
									  self.token)

				all_upload_params = dict(parse_qsl(faux_req.to_postdata()))

				# For Tumblr, all media (photos, videos)
				# are sent with the 'data' parameter
				all_upload_params['photo'] = (files.name, files.read())
				body, content_type = self.encode_multipart_formdata(all_upload_params)

				headers.update({
					'Content-Type': content_type,
					'Content-Length': str(len(body))
				})

				req = urllib2.Request(http_url, body, headers)
				try:
					req = urlopen(req)
				except Exception as e:
					# Making a fake resp var because urllib2.urlopen doesn't
					# return a tuple like OAuth2 client.request does
					resp = {'status': e.code}
					content = e.read()

				# If no error, assume response was 200
				resp = {'status': 200}

				content = req.read()
				content = etree.XML(content)

				stat = content.get('stat') or 'ok'

				if stat == 'fail':
					if content.find('.//err') is not None:
						code = content.findall('.//err[@code]')
						msg = content.findall('.//err[@msg]')

						if len(code) > 0:
							if len(msg) == 0:
								msg = 'An error occurred making your Flickr API request.'
							else:
								msg = msg[0].get('msg')

							code = int(code[0].get('code'))

							content = {
								'stat': 'fail',
								'code': code,
								'message': msg
							}
				else:
					photoid = content.find('.//photoid')
					if photoid is not None:
						photoid = photoid.text

					content = {
						'stat': 'ok',
						'photoid': photoid
					}

			else:
				url = self.rest_api_url + '?' + urlencode(qs) + '&' + urlencode(params)
				resp, content = self.get_http().request(url, 'POST', headers=headers)
		else:
			params.update(qs)
			url = '%s?%s' % (self.rest_api_url, urlencode(params))
			resp, content = self.get_http().request(url, 'GET', headers=headers)

		status = int(resp['status'])
		if status < 200 or status >= 300:
			raise FlickrAPIError('Flickr returned a Non-200 response.', error_code=status)

		#try except for if content is able to be decoded
		try:
			if type(content) != dict:
				content = json.loads(content)
		except ValueError:
			raise FlickrAPIError('Content is not valid JSON, unable to be decoded.')

		if content.get('stat') and content['stat'] == 'fail':
			raise FlickrAPIError('Flickr returned error code: %d. Message: %s' % \
								(content['code'], content['message']),
								error_code=content['code'])

		return dict(content)

	def get(self, endpoint=None, params=None):
		params = params or {}
		return self.api_request(endpoint, method='GET', params=params)

	def post(self, endpoint=None, params=None, files=None, replace=False):
		params = params or {}
		return self.api_request(endpoint, method='POST', params=params, files=files, replace=replace)

	# Thanks urllib3 <3
	def encode_multipart_formdata(self, fields, boundary=None):
		"""
		Encode a dictionary of ``fields`` using the multipart/form-data mime format.

		:param fields:
			Dictionary of fields or list of (key, value) field tuples.  The key is
			treated as the field name, and the value as the body of the form-data
			bytes. If the value is a tuple of two elements, then the first element
			is treated as the filename of the form-data section.

			Field names and filenames must be unicode.

		:param boundary:
			If not specified, then a random boundary will be generated using
			:func:`mimetools.choose_boundary`.
		"""
		body = BytesIO()
		if boundary is None:
			boundary = str(random.random()) + '_' + str(random.random())

		for fieldname, value in iter_fields(fields):
			body.write('--%s\r\n' % (boundary))

			if isinstance(value, tuple):
				filename, data = value
				UTF8(body).write('Content-Disposition: form-data; name="%s"; '
								   'filename="%s"\r\n' % (fieldname, filename))
				body.write('Content-Type: %s\r\n\r\n' %
						   (get_content_type(filename)))
			else:
				data = value
				UTF8(body).write('Content-Disposition: form-data; name="%s"\r\n'
								   % (fieldname))
				body.write(b'Content-Type: text/plain\r\n\r\n')

			if isinstance(data, int):
				data = str(data)  # Backwards compatibility

			if isinstance(data, unicode):
				UTF8(body).write(data)
			else:
				body.write(data)

			body.write(b'\r\n')

		body.write('--%s--\r\n' % (boundary))

		content_type = 'multipart/form-data; boundary=%s' % boundary

		return body.getvalue(), content_type


#------------------------------------------------------
class FAlbum:
	def __init__(self, a):
		self.id = a.get('id')
		self.title = get_json_item(a.get('title'))
		self.description= get_json_item(a.get('description'))
		self.items = int(a.get('photos', '0')) + int(a.get('videos', 0))

class FPhoto:
	def __init__(self, p=None):
		self.id = None
		self.title = None
		self.url = None
		self.path = None
		self.npath = None
		self.fsize = None
		self.mdate = DT1970
		self.fsize = -1
		self.parent = None
		self.action = ''
		self.reason = ''
		self.description = ''
		self.tags = ''
		self.video = False

		if p:
			self.id = p['id']
			self.title = p['title']
			self.url = p.get('url_o')
			self.tags = p.get('tags', '')
			self.description = get_json_item(p.get('description'))

			m = p.get('media_o', '')
			if m == "video":
				self.video = True

			if not self.title:
				self.title = self.id
			if self.title and self.title[0] != '/':
				self.title = '/' + self.title
			self.npath = os.path.abspath(config.root_dir + self.title)
	
			if self.description:
				try:
					a = json.loads(self.description)
					self.fsize = a['fsize']
					self.mdate = todate(a['mdate'])
				except Exception as e:
					uwarn('Invalid description: %s - %s' % (self.description, str(e)))


class FlickrClient:
	def __init__(self):
		self.path = os.path.abspath(config.token_file)
		self.cred = None
		self.fapi = None
		self.user = None
		self.perms = ""
		
		uinfo('Check user token ...')
		
		self._load_credentials()
		if not self.user:
			uinfo("Credentials not found, begin the OAuth process.")
			self._init_credentials()

		try:
			self._lock_credentials()
		except Exception as e:
			uerror(str(e))
			raise Exception('Failed to lock %s' % self.path)

		uinfo("User ID: %s" % self.user['id'])
	
	def _load_credentials(self):
		if os.path.exists(self.path):
			with open(self.path) as f:
				try:
					self.cred = f.read()
					self.cred = json.loads(self.cred)
				except Exception as e:
					self.cred = None
					uwarn("Failed to load credentials: " + str(e));
					return
			
			self.fapi = FlickrAPI(api_key=config.api_key, 
								api_secret=config.secret, 
								oauth_token=self.cred['oauth_token'], 
								oauth_token_secret=self.cred['oauth_token_secret'])
			self._test_login()

	def _save_credentials(self):
		with open(self.path, 'w') as f:
			cred = json.dumps(self.cred)
			f.write(cred)

		touch(self.path, config.last_sync)

	def _lock_credentials(self):
		FileLock.lock(open(self.path))

	def _init_credentials(self):
		self.fapi = FlickrAPI(api_key=config.api_key, api_secret=config.secret, callback_url="https://localhost")

		self.cred = self.fapi.get_authentication_tokens(perms='delete')
		auth_url = self.cred['auth_url']

		uprint('Paste this URL into your browser, approve the app\'s access.')
		uprint('Copy everything in the address bar after "oauth_verifier=", and paste it below.')
		uprint(auth_url)
		if config.webbrowser:
			webbrowser.open(auth_url)
		
		code = raw_input('Paste oauth_verifier here: ')
		if not code:
			print("You need to allow this program to access your Flickr site.")
			print("A web browser should pop open with instructions.")
			print("After you have allowed access restart FlickrSync.py")
			sys.exit()

		self.fapi.set_oauth_token(self.cred['oauth_token'], self.cred['oauth_token_secret'])

		self.cred = self.fapi.get_auth_tokens(code)
		
		self._save_credentials()
		
		self.fapi.set_oauth_token(self.cred['oauth_token'], self.cred['oauth_token_secret'])
		
		self._test_login()

	def _test_login(self):
		self.user = self.fapi.get('flickr.test.login')['user']

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
		return err

	"""
	Send the url and get a response.  Let errors float up
	"""
	def _get_data(self, url):
		cnt = 0
		while True:
			try:
				cnt += 1
				res = urlopen(url)
				data = res.read()
				res.close()
				return data
			except Exception as e:
				if cnt <= config.max_retry:
					uwarn(str(e))
					uwarn("Failed to get %s, retry %d" % (url, cnt))
					time.sleep(3)
				else:
					uerror("Failed to get %s" % url)
					uexception(e)
					raise


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

	def setPhotoMeta(self, photo, title=None, description=None):
		method = 'flickr.photos.setMeta'
		
		d = { 'photo_id': photo.id }
		if title:
			d['title'] = title
		if description:
			d['description'] = description

		self.fapi.post(method, params=d)
		return True

	def setPhotoTags(self, photo, tags):
		method = 'flickr.photos.setTags'
		d = { 'photo_id': photo.id, 'tags': tags }
		self.fapi.post(method, params=d)
		return True
	
	def deletePhoto(self, photo):
		method = 'flickr.photos.delete'
		self.fapi.post(method, params={ 'photo_id': photo.id })
	
	def getPhotoURL(self, photo, item, prop):
		method = 'flickr.photos.getSizes'
		data = self.fapi.post(method, params={ 'photo_id': photo.id })
		sizes = data.get('sizes')
		if sizes:
			size = sizes.get('size')
			if size:
				for psize in data.sizes.size:
					if psize.label == item:
						return getattr(psize, prop)
		return None

	def addAlbumPhotos(self, album, photos):
		method = 'flickr.photosets.editPhotos'

		ids = [photo.id for photo in photos]

		self.fapi.post(method, params={ 
				'photoset_id': album.id,
				'primary_photo_id': ids[0],
				'photo_ids': ids })

		album.items = len(photos)
	
	def newAlbum(self, photo, title, description):
		method = 'flickr.photosets.create'
		data = self.fapi.post(method, params={ 
				'title': title,
				'description': description,
				'primary_photo_id': photo.id })

		a = data.get('photoset')
		if not a:
			return None
		
		return FAlbum(a)
	
	def deleteAlbum(self, album):
		method = 'flickr.photosets.delete'
		self.fapi.post(method, params={ 'photoset_id': album.id })

	def getAlbums(self, page=1):
		method = 'flickr.photosets.getList'

		sets = []
		params = { 'user_id': self.user['id'], 'page': page, 'per_page': 500 }
			
		data = self.fapi.post(method, params=params)

		photosets = data['photosets']
		pages = int(photosets['pages'])

		photoset = photosets['photoset']
		if not photoset:
			return (sets, 0)
		
		if isinstance(photoset, list):
			for ps in photoset:
				sets.append(FAlbum(ps))
		else:
			ps = photoset
			sets.append(FAlbum(ps))

		return (sets, pages)

	def getPhotos(self, sid=None, page=1):
		method = 'flickr.photosets.getPhotos' if sid else 'flickr.people.getPhotos'

		sets = []
		params = { 'user_id': self.user['id'], 
					'extras': "description, media, tags, url_o", 
					'page': page, 'per_page': 500 }
		if sid:
			params['photoset_id'] = sid
			
		data = self.fapi.post(method, params=params)

		photos = data[ 'photoset' if sid else 'photos' ]
		pages = int(photos['pages'])

		photol = photos['photo']
		if not photol:
			return (sets, pages)
		
		if isinstance(photol, list):
			for photo in photol:
				sets.append(FPhoto(photo))
		else:
			photo = photol
			sets.append(FPhoto(photo))

		return (sets, pages)

	def download(self, url, npath):
		data = self._get_data(url)
		with open(npath, "wb") as f:
			f.write(data)

	def uploadPhoto(self, photo):
		photo.ispublic = str(config.public)
		photo.isfriend = str(config.friend)
		photo.isfamily = str(config.family)
		photo.ishidden = str(config.hidden)

		meta = { 'fsize': photo.fsize, 'mdate': mtstr(photo.mdate) }
		photo.description = json.dumps(meta)

		with open(photo.npath, 'rb') as f:
			d = {
				"title"      : photo.title,
				"description": photo.description,
				"tags"       : photo.tags,
				"hidden"     : photo.ishidden,
				"is_public"  : photo.ispublic,
				"is_friend"  : photo.isfriend,
				"is_family"  : photo.isfamily
			}
	
			r = self.fapi.post(params=d, files=f)
			return r['photoid']

	def updatePhoto(self, rf, lf):
		with open(lf.npath, 'rb') as f:
			pid = self.fapi.post(params={ 'photo_id': rf.id }, files=f, replace=True)
			if pid:
				meta = { 'fsize': lf.fsize, 'mdate': mtstr(lf.mdate) }
				lf.description = json.dumps(meta)
				self.setPhotoMeta(rf, description=lf.description)
				if lf.tags and lf.tags != rf.tags:
					self.setPhotoTags(rf, lf.tags)
				return pid
		return None

class FlickrSync:
	def __init__(self, client):
		self.client = client
		self.rfiles = {}
		self.rpaths = {}
		self.albums = {}
		self.photos = [] #used by threads

		self.abandon = False
		self.syncQueue = None
		self.syncCount = 0
		self.rnews = {}
		self.skips = []

	def print_albums(self, albums):
		uprint("--------------------------------------------------------------------------------")

		p = 0
		ks = list(albums.keys())
		ks.sort()
		for n in ks:
			a = albums[n]
			p += a.items
			uprint(u"  [%4d] %s" % (a.items, a.title))

		uprint("--------------------------------------------------------------------------------")
		uprint("Total %s albums, %s photos" % (szstr(len(albums)), szstr(p)))

	def print_photos(self, photos, url = False):
		uprint("--------------------------------------------------------------------------------")

		tz = 0
		if isinstance(photos, dict):
			ks = list(photos.keys())
			ks.sort()
			for n in ks:
				p = photos[n]
				tz += p.fsize
				uprint(u"  %-40s [%11s] (%s) %s" % (p.title, szstr(p.fsize), tmstr(p.mdate), ("" if (not url) or (not p.url) else p.url)))
		else:
			for p in photos:
				tz += p.fsize
				uprint(u"  %-40s [%11s] (%s) %s" % (p.title, szstr(p.fsize), tmstr(p.mdate), ("" if (not url) or (not p.url) else p.url)))

		uprint("--------------------------------------------------------------------------------")
		uprint("Total %s photos [%s]" % (szstr(len(photos)), szstr(tz)))


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
		api = self.client.files().get(fileId=fid)
		r = self.exea(api, "get")
		uprint(str(r))
		
	def sets(self, verb = False):
		if self.albums:
			return
		
		sys.stdout.write('  Get remote albums ......          ')
		sys.stdout.flush()

		self.albums = {}
		pages = self.list_albums()
		if pages > 1:
			self.syncCount = pages
			self.syncQueue = queue.Queue()
			for i in xrange(2, pages + 1):
				self.syncQueue.put_nowait((i, pages))
	
			# start sync threads
			threads = []
			for i in xrange(config.max_threads):
				thread = AlbumListThread(self)
				threads.append(thread)
				thread.start()
			
			# wait upload threads stop
			self.join_threads(threads)
		
		sys.stdout.write("\n")
		sys.stdout.flush()

		if verb:
			self.print_albums(self.albums)

	def sets_run(self):
		while not self.abandon:
			try:
				(page, pages) = self.syncQueue.get_nowait()
				print_progress(page, pages)
				self.list_albums(page)
			except queue.Empty:
				break
			except Exception as e:
				uexception(e)

	def list_albums(self, page=1):
		pss, pages = self.client.getAlbums(page)
		if pss:
			for s in pss:
				self.albums[s.title] = s
		return pages

	def list(self, sid=None, verb=False, url=False):
		self.rfiles = {}
		self.rpaths = {}

		ps = self.get_photos(sid)
		
		for p in ps:
			self.rpaths[p.title] = p
			self.rfiles[p.id] = p

		if verb:
			self.print_photos(self.rpaths, url)

	def get_photos(self, sid=None):
		sys.stdout.write('  Get remote photos ......          ')
		sys.stdout.flush()

		self.photos = []
		pages = self.list_photos(sid=sid)
		if pages > 1:
			self.syncCount = pages
			self.syncQueue = queue.Queue()
			for i in xrange(2, pages + 1):
				self.syncQueue.put_nowait((i, pages))
	
			# start sync threads
			threads = []
			for i in xrange(config.max_threads):
				thread = PhotoListThread(self, sid)
				threads.append(thread)
				thread.start()
			
			# wait upload threads stop
			self.join_threads(threads)

		sys.stdout.write("\n")
		sys.stdout.flush()
		
		return self.photos

	def list_photos(self, sid=None, page=1):
		rphotos, pages = self.client.getPhotos(sid=sid, page=page)
		if rphotos:
			for p in rphotos:
				if not self.accept_path(p.title):
					continue
				self.photos.append(p)
		return pages

	def list_run(self, sid=None):
		while not self.abandon:
			try:
				(page, pages) = self.syncQueue.get_nowait()
				print_progress(page, pages)
				self.list_photos(sid=sid, page=page)
			except queue.Empty:
				break
			except Exception as e:
				uexception(e)

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

				fp = FPhoto()
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
				if tseconds(rf.mdate - lf.mdate) <= 2:
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

	def trash_remote_file(self, rf):
		"""
		Move a remote file to the trash.
		"""
		uinfo("%s ^TRASH^  %s [%s] (%s)" % (self.prog(), rf.title, szstr(rf.fsize), tmstr(rf.mdate)))

		self.client.deletePhoto(rf)
		with LOCK:
			self.rfiles.pop(rf.id, rf)
			self.rpaths.pop(rf.title, rf)

	def _make_tags(self, lf):
		# make one tag equal to original file path with spaces replaced by
		# # and start it with # (for easier recognition) since space is
		# used as TAG separator by flickr

		# split path to make tags
		tags = ''
		ts = re.split(config.tag_split_re, lf.title)
		for t in ts:
			if t and len(t) > 1:
				tags += t.replace(' ', '_') + ' '

		lf.tags = tags.strip()
	
	def insert_remote_file(self, lf):
		if lf.fsize > config.max_file_size:
			self.skips.append(lf)
			uwarn("%s Unable to upload %s, File size [%s] exceed the limit" % (self.prog(), lf.title, szstr(lf.fsize)))
			return

		self._make_tags(lf)

		'''
		Upload a file to remote.
		'''
		uinfo("%s ^UPLOAD^ %s [%s] (%s) #(%s)" % (self.prog(), lf.title, szstr(lf.fsize), tmstr(lf.mdate), lf.tags))
		lf.id = self.client.uploadPhoto(lf)
		if lf.id:
			with LOCK:
				# add to remote files
				self.rfiles[lf.id] = lf
				self.rpaths[lf.title] = lf
				self.rnews[lf.title] = lf

	def update_remote_file(self, rf, lf):
		self.trash_remote_file(rf)
		self.insert_remote_file(lf)

	def download_remote_file(self, rf):
		uinfo("%s >DNLOAD> %s [%s] (%s)" % (self.prog(), rf.title, szstr(rf.fsize), tmstr(rf.mdate)))
		
		mkpdirs(rf.npath)

		if rf.fsize == 0:
			open(rf.npath, "wb").close()
		else:
			url = rf.url
			if rf.video:
				url = self.client.getPhotoURL(rf, 'Video Original', 'source')
				uinfo("%s >>URL>>  %s" % (self.prog(), url))
			self.client.download(url, rf.npath)

		touch(rf.npath, rf.mdate)

	def patch_remote_file(self, rf, mdate, fsize):
		'''
		Patch a remote file.
		'''
		uinfo("%s ^PATCH^  %s [%s] (%s)" % (self.prog(), rf.title, szstr(fsize), tmstr(mdate)))

		meta = { 'fsize': fsize, 'mdate': mtstr(mdate) }
		desc = json.dumps(meta)
		
		self.client.setPhotoMeta(rf, rf.title, desc)

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
		if os.path.exists(lf.npath):
			return

		uinfo("%s >CREATE> %s" % (self.prog(), lf.title))
		os.makedirs(lf.npath)

	def trash_local_file(self, lf):
		if config.trash_dir:
			uinfo("%s >TRASH>  %s" % (self.prog(), lf.title))
	
			np = config.trash_dir + lf.title
			mkpdirs(np)
			
			if os.path.exists(np):
				os.remove(np)
			
			shutil.move(lf.npath, np)
		else:
			uinfo("%s >REMOVE> %s" % (self.prog(), lf.path))
			os.remove(lf.npath)

	def remove_local_file(self, lf):
		uinfo("%s >REMOVE> %s" % (self.prog(), lf.title))

		np = lf.npath
		if os.path.exists(np):
			os.rmdir(np)
		
	def prog(self):
		return ('[%d/%d]' % (self.syncCount - self.syncQueue.qsize(), self.syncCount))

	def join_threads(self, threads):
		# wait threads stop
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
		
	def sync_files(self, sfiles):
		self.syncCount = len(sfiles)
		self.syncQueue = queue.Queue()
		for sf in sfiles:
			self.syncQueue.put_nowait(sf)

		# start sync threads
		threads = []
		for i in xrange(config.max_threads):
			thread = PhotoSyncThread(i + 1, self)
			threads.append(thread)
			thread.start()
		
		# wait upload threads stop
		self.join_threads(threads)

		if not self.abandon and self.rnews:
			# start Album thread
			thrd = AlbumUpdateThread(self)
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
			except queue.Empty:
				break
			except Exception as e:
				uexception(e)


	def clear_albums(self, noprompt = False):
		if not noprompt:
			ans = raw_input("Are you sure to clear remote albums? (Don't worry, none of the photos will be deleted.) (Y/N): ")
			if ans.lower() != "y":
				return

		self.sets(True);
		if not self.albums:
			return
		
		self._clear_albums()

	def _clear_albums(self):
		t = len(self.albums)
		i = 0
		for a in self.albums.values():
			i += 1
			uinfo("[%d/%d] Delete album [%s]: %s" % (i, t, str(a.id), a.title))
			self.client.deleteAlbum(a)
		self.albums = {}

	def build_albums(self, ps = None):
		self.sets()

		if ps is None:
			self.list()
			ps = self.rpaths
	
		self._clear_albums()

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
			fset = self.client.newAlbum(photos[0], setName, "Auto-generated by FlickrSync")
			self.albums[fset.title] = fset

		if len(photos) > 1:
			udebug('Add %d photos to album/set [%s]' % (len(photos), setName))
			self.client.addAlbumPhotos(fset, photos)

	def list_album_photos(self, atitle):
		self.sets()

		a = self.albums.get(atitle)
		if not a:
			uinfo("Album [%s] not found" % (atitle))
			return

		uinfo("List photos of album [%s]:" % (atitle))
		ps = self.get_photos(a.id)
		self.print_photos(ps)

	def delete_album(self, atitle, noprompt = False):
		self.sets()

		a = self.albums.get(atitle)
		if a:
			if not noprompt:
				ans = raw_input("Are you sure to delete remote album [%s]? (Don't worry, none of the contents will be deleted.) (Y/N): " % atitle)
				if ans.lower() != "y":
					return

			uinfo("Delete album [%s]: %s" % (str(a.id), a.title))
			self.client.deleteAlbum(a)
		else:
			uinfo("Album [%s] not found" % (atitle))

	def drop_album(self, atitle, noprompt = False):
		self.sets()

		a = self.albums.get(atitle)
		if a:
			if not noprompt:
				ans = raw_input("Are you sure to delete remote album [%s] and it's photos? (Y/N): " % atitle)
				if ans.lower() != "y":
					return

			ps = self.get_photos(a.id)
			t = len(ps)
			i = 0
			for p in ps:
				i += 1
				uinfo("[%d/%d] Delete photo [%s]: %s" % (i, t, str(p.id), p.title))
				p.delete()

			uinfo("Delete album [%s]: %s" % (str(a.id), a.title))
			self.client.deleteAlbum(a)
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


class PhotoSyncThread(threading.Thread):
	def __init__(self, threadID, syncFlickr):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.syncFlickr = syncFlickr

	def run(self):
		uinfo("Starting PhotoSyncThread %d " % self.threadID)

		self.syncFlickr.sync_run()

		uinfo("Exiting PhotoSyncThread %d " % self.threadID)

class PhotoListThread(threading.Thread):
	def __init__(self, syncFlickr, sid):
		threading.Thread.__init__(self)
		self.syncFlickr = syncFlickr
		self.sid = sid

	def run(self):
		self.syncFlickr.list_run(self.sid)

class AlbumListThread(threading.Thread):
	def __init__(self, syncFlickr):
		threading.Thread.__init__(self)
		self.syncFlickr = syncFlickr

	def run(self):
		self.syncFlickr.sets_run()

class AlbumUpdateThread(threading.Thread):
	def __init__(self, syncFlickr):
		threading.Thread.__init__(self)
		self.syncFlickr = syncFlickr

	def run(self):
		self.syncFlickr.update_albums(self.syncFlickr.rpaths)


def showUsage():
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
		showUsage()
		exit(0)

	uinfo('Start...')

	fc = FlickrClient()
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
		fs.list(verb=True, url=url)
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
		showUsage()

if __name__ == "__main__":
	try:
		main(sys.argv[1:])
	except IOError as ex:
		print(ex)

