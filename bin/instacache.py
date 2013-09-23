#!/usr/bin/env python

import argparse, json, urllib, urlparse, sys, os, errno, sqlite3, re
import oauth2 as oauth
import ConfigParser as cp
import subprocess as sp
import unicodedata
import logging
from collections import namedtuple

Bookmark = namedtuple('Bookmark', ['id', 'url', 'title', 'description'])

instapaper_URL = "https://www.instapaper.com/api/1"

log = None

def make_sure_path_exists(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise

def login(args):
    instacache_dir = os.path.expanduser(args.file)
    client = get_client(instacache_dir)
    
    user = args.u
    password = args.p

    if not user:
        user = raw_input('Instapaper account username: ')
    if not password:
        password = raw_input('Instapaper account password: ')

    payload = {'x_auth_username': user,
               'x_auth_password': password,
               'x_auth_mode': "client_auth"}

    resp, token = client.request("%s/oauth/access_token" % (instapaper_URL),
                                 method="POST",
                                 body=urllib.urlencode(payload))

    if resp['status'] != '200':
        log.error('Did not successfully generate an oauth token. Check credentials')
        log.debug(token)
        sys.exit(1)

    access_token = dict(urlparse.parse_qsl(token))
    make_sure_path_exists(instacache_dir)

    config = cp.RawConfigParser()
    config.read("%s/.credentials" % (instacache_dir))
    if not config.has_section('credentials'):
        config.add_section('credentials')
    config.set('credentials', 'oauth_token', access_token['oauth_token'])
    config.set('credentials', 'oauth_token_secret', access_token['oauth_token_secret'])

    with open("%s/.credentials" % (instacache_dir), 'w') as configfile:
        config.write(configfile)

def sqlite_connection(folder, directory):
    backup_dir = "%s/%s" % (directory, folder)
    make_sure_path_exists(backup_dir)

    conn = sqlite3.connect(os.path.expanduser("%s/db.sqlite" % (backup_dir)))

    conn.execute("create table if not exists bookmarks (id integer, url text, title text, description text, text_backup_complete integer, html_backup_complete integer)")
    conn.commit()

    return conn

def add_to_db(conn, bookmarks):
    for b in bookmarks:
        sql = '''insert into bookmarks
                    (id, url, title, description, text_backup_complete, html_backup_complete)
                 values
                    (?, ?, ?, ?, 0, 0)'''
        conn.execute(sql, (b.id, b.url, b.title, b.description))
        conn.commit()

def bookmarks_wo_text_backup(conn):
    sql = "select id, url, title, description from bookmarks where text_backup_complete=0"
    return [Bookmark(r[0], r[1], r[2], r[3]) for r in conn.execute(sql)]

def bm_text_done(conn, bookmark):
    sql = "update bookmarks set text_backup_complete=1 where id=?"
    conn.execute(sql, (bookmark.id,))
    conn.commit()

def bookmarks_wo_html_backup(conn):
    sql = "select id, url, title, description from bookmarks where html_backup_complete=0"
    return [Bookmark(r[0], r[1], r[2], r[3]) for r in conn.execute(sql)]

def bm_html_done(conn, bookmark):
    sql = "update bookmarks set html_backup_complete=1 where id=?"
    conn.execute(sql, (bookmark.id,))
    conn.commit()

def seen_bookmark_ids(conn):
    ids = [str(row[0]) for row in conn.execute("select id from bookmarks")]
    return ids

def filenameize(string):
    string = string.replace(' ', '_')
    pattern = re.compile('[\W+]', re.UNICODE)
    return pattern.sub('', string)

def backup_bm_text(bookmark, conn, client, target_dir):
    log.info(u'Backing up text of article %s' % (bookmark.url))
    payload = {'bookmark_id': bookmark.id }

    rhead, rbody = client.request("%s/bookmarks/get_text" % (instapaper_URL),
                                  method="POST",
                                  body=urllib.urlencode(payload))

    if rhead["status"] == '200':
        fn = filenameize(bookmark.title)
        with open("%s/%s-text.html" % (target_dir, fn), 'w') as f:
            f.write(rbody)
        bm_text_done(conn, bookmark)
        return True

    else:
        log.warning('Could not retrieve text of article %s' % (bookmark.url))
        log.debug(rhead)
        return False

def backup_bm_html(bookmark, conn, client, target_dir):
    log.info(u'Backing up html of article %s' % (bookmark.url))
    call = ["wget",
            "--level=10",
            "--no-parent",
            "--directory-prefix=%s" % (target_dir),
            "--page-requisites",
            "--adjust-extension",
            "--convert-links",
            bookmark.url.encode("utf8")]

    devnull = open('/dev/null', 'w')
    #print sp.check_output(call)
    try:
        sp.check_call(call, stdout=devnull, stderr=devnull)
        bm_html_done(conn, bookmark)
        return True
    except sp.CalledProcessError, e:
        log.error('Could not retrieve html of article %s' % bookmark.url)
        log.debug(e)
        if e.returncode <= 4:
            raise
        return False
    
def backup_from_db(conn, target_dir, client):
    all_good = True

    todo_text_bu = bookmarks_wo_text_backup(conn)

    log.info(u"Backuping up %i bookmarks to text" % (len(todo_text_bu)))

    for b in todo_text_bu:
        all_good = backup_bm_text(b, conn, client, target_dir) and all_good

    todo_html_bu = bookmarks_wo_html_backup(conn)
    log.info(u"Backing up %i bookmarks to html" % (len(todo_html_bu)))

    for b in todo_html_bu:
        all_good = backup_bm_html(b, conn, client, target_dir) and all_good

    if not all_good:
        log.warning(u"Not all backups completed successfully")

def backup(args):
    client = authed_client(args)
    conn = sqlite_connection(args.f, args.d)

    ids = seen_bookmark_ids(conn)

    payload = {'limit': 500,
               'folder_id': args.f,
               'have': ','.join(ids) }

    rhead, rbody = client.request("%s/bookmarks/list" % (instapaper_URL),
                                  method="POST",
                                  body=urllib.urlencode(payload))

    rbody = json.loads(rbody)
    if rhead['status'] == '200':
        bookmarks = [Bookmark(i["bookmark_id"],
                              i["url"],
                              i["title"],
                              i["description"]) for i in rbody if i["type"] == "bookmark"]

        log.info(u"New bookmarks count: %s" % (len(bookmarks)))

        add_to_db(conn, bookmarks)
    else:
        log.error(u"Could not retrieve booksmarks list")
        sys.exit(1)

    backup_from_db(conn, "%s/%s" % (args.d, args.f), client)

def get_client(config_dir, access_token = None):
    config = cp.RawConfigParser()
    config.read("%s/.credentials" % (config_dir))
    consumer_key = config.get('keys', 'consumer_key')
    consumer_secret = config.get('keys', 'consumer_secret')

    consumer = oauth.Consumer(consumer_key, consumer_secret)
    client = oauth.Client(consumer, access_token) if access_token else oauth.Client(consumer)
    client.set_signature_method = oauth.SignatureMethod_HMAC_SHA1()
    return client

def authed_client(args):
    config = cp.RawConfigParser()
    instacache_dir = os.path.expanduser(args.file)
    config.read("%s/.credentials" % (instacache_dir))

    access_token = oauth.Token(config.get('credentials', 'oauth_token'),
                               config.get('credentials', 'oauth_token_secret'))

    client = get_client(instacache_dir, access_token)
    check_auth = client.request("%s/account/verify_credentials" % (instapaper_URL),
                                method="POST")
    if check_auth[0]['status'] != '200':
        log.error("Could not retrieve authed client. Did you run `login'?")
        log.debug(check_auth)
        sys.exit(1)

    return client


def get_user(args):
    client = authed_client(args)
    
    resp = client.request("%s/account/verify_credentials" % (instapaper_URL),
                          method="POST")

    print(resp)

if __name__=='__main__':
    parser = argparse.ArgumentParser(prog='instacache', description='Cache Instapaper articles')
    parser.add_argument('-f', '--file', action='store', default='~/.instacache',
        help='File in which to store instacache information')
    parser.add_argument('-l', '--log', action='store', default=1, type=int,
        help='Log level. 0=critical, 1=error, 2=warning, 3=info, 4=debug.')
    subparsers = parser.add_subparsers(title='command', help='command to issue')

    login_parser = subparsers.add_parser('login', help='login and create an oauth token')
    login_parser.add_argument('-u', action='store',
            help='Instapaper account email')
    login_parser.add_argument('-p', action='store',
            help='Instapaper account password')
    login_parser.set_defaults(func=login)

    user_parser = subparsers.add_parser('user', help='show the currently authed user')
    user_parser.set_defaults(func=get_user)

    backup_parser = subparsers.add_parser('backup', help='back up instapaper articles')
    backup_parser.add_argument('-f', action='store', default='starred',
            help='Back up a specific instapaper folder instead of starred')
    backup_parser.add_argument('-d', action='store', default='.',
            help='Location to store the backed up files and database of backups')
    backup_parser.set_defaults(func=backup)

    args = parser.parse_args()

    # Set logging
    log_levels = {4: logging.DEBUG, 3: logging.INFO, 2: logging.WARNING, 1: logging.ERROR,
            0: logging.CRITICAL}
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)

    # Use debug level for file logging
    ic_dir = os.path.expanduser(args.file)
    log_file = "%s/log" % ic_dir
    l_file_handler = logging.FileHandler(log_file)
    l_file_handler.setLevel(logging.DEBUG)
    log.addHandler(l_file_handler)

    # User level for stream handling
    l_stream_handler = logging.StreamHandler()
    l_stream_handler.setLevel(log_levels[args.log])
    log.addHandler(l_stream_handler)

    args.func(args)
