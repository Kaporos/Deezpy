#!/usr/bin/env python

#Copyright (C) 2018  Deezpy contributors

#This program is free software: you can redistribute it and/or modify it
#under the terms of the GNU General Public License as published by the Free
#Software Foundation, either version 3 of the License, or (at your option)
#any later version.

#This program is distributed in the hope that it will be useful, but WITHOUT
#ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
#FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
#more details.

#You should have received a copy of the GNU General Public License along
#with this program. If not, see <http://www.gnu.org/licenses/>

# standard library:
import configparser
import getpass
import hashlib
import json
import os
import re
import sys

# not in standard library:
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import mutagen
from mutagen.easyid3 import EasyID3
from mutagen.mp3 import MP3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def initDeezerApi(email, pswd):
    ''' Inits the Deezer API and handles user login. Four POST requests have to be made.
        The first three are to log in, the last one is to obtain a CSRF token. This function
        is only called once, at the start of the script. '''
    global s
    s = requests.Session()
    global httpHeaders
    httpHeaders = {
        'User-Agent'       : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36',
        'Content-Language' : 'en-US',
        'Cache-Control'    : 'max-age=0',
        'Accept'           : '*/*',
        'Accept-Charset'   : 'utf-8,ISO-8859-1;q=0.7,*;q=0.3',
        'Accept-Language'  : 'en-US;q=0.6,en;q=0.4',
        'Content-Type'     : 'application/json'
                    }

    unofficialApiQueries = {
        'api_version' : '1.0',
        'api_token'   : 'null',
        'input'       : '3',
        'method'      : 'deezer.getUserData'
                            }

    req = requests_retry_session(session=s).post(
        url     = 'https://www.deezer.com/ajax/gw-light.php',
        headers = httpHeaders,
        params  = unofficialApiQueries
                    )
    res = json.loads(req.text)

    login = requests_retry_session(session=s).post(
        url = "https://www.deezer.com/ajax/action.php",
        # Note that these headers differ from httpHeaders
        headers = {
            'User-Agent'       : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36',
            'Accept'           : 'application/json, text/javascript, */*; q=0.01',
            'Content-Type'     : 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With' : 'XMLHttpRequest'
                },
        data = {
            'type'          : 'login',
            'mail'          : email,
            'password'      : pswd,
            'checkFormLogin': res['results']['checkFormLogin']
            }
        )

    # Login returns 'success' if it was a successful login, login is not successful if it returns 200 and credentials is called again
    if login.text == "success":
        print("Login successful")
    elif login.status_code == 200:
        print("\nLogin failed, wrong Deezer credentials.\nFacebook and family accounts are not supported. If you use one, please create a new account.\n")
        return False
    else:
        print("Error logging in. Error code: "+login.status_code)
        exit()

    req = requests_retry_session(session=s).post(
        url     = 'https://www.deezer.com/ajax/gw-light.php',
        headers = httpHeaders,
        params  = unofficialApiQueries
        )

    # A cross-site request forgery token is needed. It is used as api token in privateApi(id)
    req = requests_retry_session(session=s).post(
        url     = 'https://www.deezer.com/ajax/gw-light.php',
        headers = httpHeaders,
        params  = unofficialApiQueries
        )

    res = json.loads(req.text)
    global CSRFToken
    CSRFToken = res['results']['checkForm']
    return True


def privateApi(id):
    ''' Get the required info from the unofficial API to decrypt the files '''
    unofficialApiQueries = {
        'api_version' : '1.0',
        'api_token'   : CSRFToken,
        'input'       : '3',
        'method'      : 'deezer.pageTrack'
            }

    req = requests_retry_session(session=s).post(
        url     = 'https://www.deezer.com/ajax/gw-light.php',
        headers = httpHeaders,
        params  = unofficialApiQueries,
        json    = {'SNG_ID':id} # the SNG_ID must be encoded in JSON
            )

    res = json.loads(req.text)
    return res['results']['DATA']

# https://www.peterbe.com/plog/best-practice-with-retries-with-requests
def requests_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504), session=None):
    session = session or requests.Session()
    retry = Retry(
        total = retries,
        read = retries,
        connect = retries,
        backoff_factor = backoff_factor,
        status_forcelist = status_forcelist,
        method_whitelist = frozenset(['GET', 'POST'])
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def getJSON(type, id, subtype=None):
    ''' Official API. This function is used to download the ID3 tags. Subtype can be 'albums' or 'tracks' '''
    if subtype:
        url = 'https://api.deezer.com/%s/%s/%s?limit=-1' % (type, id, subtype)
    else:
        url = 'https://api.deezer.com/%s/%s/?limit=-1' % (type, id)
    r = requests_retry_session(session=s).get(url)
    return json.loads(r.text)


def getInfo(id):
    privateInfo = privateApi(id)
    if "FALLBACK" in privateInfo:
        id = privateInfo["FALLBACK"]['SNG_ID'] # Some songs in a playlist have other IDs than the same song in an album/artist page. These ids from songs in a playlist do not return albInfo properly. The FALLBACK id works, however.
        privateInfo = privateApi(id) # basically, we need to replace the track with the FALLBACK one
    trackInfo = getJSON('track', id)
    albInfo = getJSON(*deezerTypeId(trackInfo['album']['link']))

    # if the preferred quality is not available, get the one below etc.
    quality = ''
    while not quality:
        qualitySetting = getSetting("quality")
        if qualitySetting == '1':
            if privateInfo['FILESIZE_FLAC'] != '0':
                quality = '9'
            else:
                qualitySetting = '2'
        if qualitySetting == '2':
            if privateInfo['FILESIZE_MP3_320'] != '0':
                quality = '3'
            else:
                qualitySetting = '3'
        if qualitySetting == '3':
            if privateInfo['FILESIZE_MP3_256'] != '0':
                quality = '5'
            else:
                qualitySetting = '4'
        if qualitySetting == '4':
            if privateInfo['FILESIZE_MP3_128'] != '0':
                quality = '1'
            else:
                raise
    return trackInfo, albInfo, privateInfo, quality


def getCoverArt(url, filename):
    ''' Retrieves the cover art from the official API,
        downloads it to the download folder '''
    path = os.path.dirname(filename)
    imageFile = path + '/cover' + '.png'
    if not os.path.isdir(path):
        os.makedirs(path)
    if not os.path.isfile(imageFile):
        with open(imageFile, 'wb') as f:
            r = requests_retry_session(session=s).get(url)
            f.write(r.content)
            return r.content
    else:
        with open(imageFile, 'rb') as f:
            return f.read()


def writeTags(filenameFull, trackInfo, albInfo):
    ''' Function to write tags to the file, be it FLAC or MP3 '''
    # retrieve tags
    try: genre = albInfo['genres']['data'][0]['name']
    except: genre = ''
    tags = {
            'title'       : trackInfo['title'],
            'discnumber'  : trackInfo['disk_number'],
            'tracknumber' : trackInfo['track_position'],
            'album'       : trackInfo['album']['title'],
            'date'        : trackInfo['album']['release_date'],
            'artist'      : trackInfo['artist']['name'],
            'bpm'         : trackInfo['bpm'],
            'albumartist' : albInfo['artist']['name'],
            'totaltracks' : albInfo['nb_tracks'],
            'label'       : albInfo['label'],
            'genre'       : genre,
            }
    filename, file_extension = os.path.splitext(filenameFull)
    image = getCoverArt(trackInfo['album']['cover_xl'], filename) # downloads the image in the folder and loads it
    if file_extension == '.flac':
        handle = mutagen.File(filenameFull)
        handle.delete() # delete pre-existing tags
        if getSetting('embed covers') == 'True':
            pic = mutagen.flac.Picture()
            pic.data = image
            handle.clear_pictures()
            handle.add_picture(pic)

    elif file_extension == '.mp3':
        handle = MP3(filenameFull, ID3=EasyID3)
        handle.delete()
        EasyID3.RegisterTextKey("label", "TPUB") # label is not supported by easyID3, so we add it
        EasyID3.RegisterTextKey("albumart", "APIC")
        tags['tracknumber'] = str(tags['tracknumber']) + '/' + str(tags['totaltracks']) # tracknumber and total tracks is one tag for ID3
        del tags['totaltracks']
        if getSetting('embed covers') == 'True':
            handle["albumart"] = mutagen.id3.APIC(data=image)
    else:
        print("Could not write tags. File extension not supported.")
        return False

    for key, val in tags.items():
        handle[key] = str(val)
    handle.save()


# https://gist.github.com/bgusach/a967e0587d6e01e889fd1d776c5f3729
def multireplace(string, replacements):
    ''' Given a string and a replacement map, it returns the replaced string. '''
    # Sorts the dict so that longer ones first to keep shorter substrings from matching where the longer ones should take place
    substrs = sorted(replacements, key=len, reverse=True)
    # Create a big OR regex that matches any of the substrings to replace
    regexp = re.compile('|'.join(map(re.escape, substrs)))
    # For each match, look up the new string in the replacements
    return regexp.sub(lambda match: replacements[match.group(0)], string)


def nameFile(trackInfo, albInfo, playlistInfo=False):
    # replacedict is the dictionary to replace pathspec with
    if playlistInfo:
        pathspec = getSetting('playlist naming template')
        replacedict = {
            '<Playlist Title>' : playlistInfo[0]['title'],
            '<Track#>'         : '%d' % playlistInfo[1],
            '<Title>'          : trackInfo['title']
            }
    else:
        pathspec = getSetting('naming template')
        replacedict = {
            '<Album Artist>' : albInfo['artist']['name'],
            '<Album>'        : trackInfo['album']['title'],
            '<Year>'         : trackInfo['album']['release_date'],
            '<Track#>'       : '%02d' % trackInfo['track_position'],
            '<Disc#>'        : '%d' % trackInfo['disk_number'],
            '<Title>'        : trackInfo['title']
            }
    for key,val in replacedict.items():
        val = re.sub(r'(?u)[^-\w.( )]', '', val) # Regex that removes anything that is not an alphanumeric (+non-latin chars), space, dash, underscore, dot or parentheses for every tag.
        val = val.encode('utf-8')[:250].decode('utf-8', 'ignore') # folder dirs and the filename are now max 250 bytes long
        replacedict[key] = val

    filename = multireplace(pathspec, replacedict) # replace pathspec with desired tags
    return filename


def getTrackDownloadUrl(data, quality):
    ''' Calculates the deezer download URL from
    a given MD5_origin, song_id and media_version '''
    step1 = '¤'.join((data['MD5_ORIGIN'],
                      quality, data['SNG_ID'],
                      data['MEDIA_VERSION']))
    m = hashlib.md5()
    m.update(bytes([ord(x) for x in step1]))
    step2 = m.hexdigest() + '¤' + step1 + '¤'
    step2 = step2.ljust(80, ' ')

    cipher = Cipher(algorithms.AES(bytes('jo6aey6haid2Teih','ascii')), modes.ECB(), default_backend())
    encryptor = cipher.encryptor()

    step3 = encryptor.update(bytes([ord(x) for x in step2])).hex()
    cdn = data['MD5_ORIGIN'][0]
    url = 'https://e-cdns-proxy-' + cdn + '.dzcdn.net/mobile/1/' + step3
    return url


def deezerTypeId(url):
    ''' Returns type ID from a URL'''
    return url.split('/')[-2:]


def resumeDownload(url, filesize):
    resume_header = {'Range': 'bytes=%d-' % filesize}
    return requests_retry_session(session=s).get(url, headers=resume_header, stream=True)


def downloadTrack(filenameFull, privateInfo, quality):
    filename, file_extension = os.path.splitext(filenameFull)
    bfKey = getBlowfishKey(privateInfo['SNG_ID'])
    url = getTrackDownloadUrl(privateInfo, quality)

    if os.path.isfile(filename + '.tmp'):
        print("Resuming download: " + filenameFull + "...")
        filesize = os.stat(filename + '.tmp').st_size # get the size of file already written to disk
        filesize = filesize - (filesize%2048) # make sure that filesize is a multiple of 2048, it can be seamlessly decrypted now
        i = filesize/2048
        r = resumeDownload(url, filesize)
    else:
        print("Downloading: " + filenameFull + "...")
        filesize = 0
        i = 0
        r = requests_retry_session(session=s).get(url, stream = True)

    # Decrypt content and write to file
    with open(filename + '.tmp', 'ab') as fd: #tmp file to prevent incomplete music files if the users exits while writing
        fd.seek(filesize) # jump to end of the file in order to append to it
        # Only every third 2048 byte block is encrypted.
        for chunk in r.iter_content(2048):
            if i % 3 > 0:
                fd.write(chunk)
            elif len(chunk) < 2048:
                fd.write(chunk)
                break
            else:
                cipher = Cipher(algorithms.Blowfish((bfKey)), modes.CBC(bytes([i for i in range(8)])), default_backend())
                decryptor = cipher.decryptor()
                decdata = decryptor.update(chunk) + decryptor.finalize()
                fd.write(decdata)
            i += 1
    os.rename(filename+'.tmp', filenameFull)


def getBlowfishKey(id):
    ''' Calculates the Blowfish decrypt key for a given SNG_ID '''
    secret = 'g4el58wc0zvf9na1'
    m = hashlib.md5()
    m.update(bytes([ord(x) for x in id]))
    idMd5 = m.hexdigest()
    bfKey = bytes([(ord(idMd5[i]) ^ ord(idMd5[i+16]) ^ ord(secret[i])) for i in range(16)])
    return bfKey


def makePath(filenameFull):
    ''' Makes sure that file does not yet exists '''
    dir = os.path.dirname(filenameFull)
    if os.path.isfile(filenameFull):
        return False
    if not os.path.isdir(dir):
        os.makedirs(dir)


def getTrack(id,playlist=False):
    ''' Calls the necessary functions to download and tag the tracks.
        Playlist must be a tuple of (playlistInfo, playlistTrack) '''
    trackInfo, albInfo, privateInfo, quality = getInfo(id)
    if trackInfo['readable'] == False:
        print("Song", trackInfo['title'], "not available, skipping...") # TODO find a way to try to find an alternative (available) song
        return False

    if quality == '9':
        ext = '.flac'
    else:
        ext = '.mp3'

    if playlist: # edit some info to get playlist suitable tags
        albInfo['artist']['name'] = 'Various Artists'
        albInfo['nb_tracks'] = playlist[0]['nb_tracks']
        trackInfo['album']['title'] = playlist[0]['title']
        trackInfo['track_position'] = playlist[1]
        trackInfo['disk_number'] = ''
        trackInfo['album']['release_date'] = ''
        trackInfo['album']['cover_xl'] = playlist[0]['picture_xl']
    filenameFull = nameFile(trackInfo,albInfo,playlist) + ext

    if makePath(filenameFull) == False:
        print(filenameFull + " already exists!")
    else:
        downloadTrack(filenameFull, privateInfo, quality)
        writeTags(filenameFull, trackInfo, albInfo)
        print("Done!")


def downloadDeezer(url):
    ''' Extract individual song links from albums and artist pages and invokes getTrack().
        If it is just a track link, only invoke getTrack() '''
    type, id = deezerTypeId(url)
    if type == 'track':
        getTrack(id)
    elif type == 'playlist': # we can't invoke downloadDeezer() again, as used in the else block because playlists have a different tracklisting, not available in JSON format
        info = getJSON(type, id, 'tracks')
        ids = [x["id"] for x in info['data']]

        playlistInfo = getJSON(type, id)
        playlistTrack = 1
        for id in ids:
            playlist = (playlistInfo, playlistTrack)
            getTrack(id, playlist)
            playlistTrack = playlistTrack + 1
    else:
        subtype = 'albums' if type == 'artist' else 'tracks'
        info = getJSON(type, id)
        if type == 'album':
            print('')
            print(info['artist']['name'], '-', info['title'])
        info = getJSON(type, id, subtype)
        urls = [x["link"] for x in info['data']]
        [downloadDeezer(url) for url in urls]


def getSetting(option, section='DEFAULT'):
    ''' Returns a setting from settings.ini. '''
    config = configparser.ConfigParser()
    config.read('settings.ini')
    if config.has_option(section,option):
        return config[section][option]
    else:
        return False


def credentials(retry=False):
    ''' Handles credentials for settings file, for initial setup.
        If retry is True: the credentials contained a typo and
        newly entered credentials are written to settings file'''
    email = input("Deezer email: ")
    pswd = getpass.getpass('Deezer password: ')
    pswd_enc = pswd.encode().hex() # encode pswd in hex as a small security measure, not really safe.
    if retry:
        config = configparser.ConfigParser()
        config.read('settings.ini')
        config.set('DEFAULT', 'email', email)
        config.set('DEFAULT', 'password', pswd_enc)
        with open('settings.ini', 'w') as configfile:
            config.write(configfile)
        return email, pswd
    else:
        return email, pswd_enc


def genSettingsconf():
    ''' Generates a settings file containing the download path, playlist download path,
        song quality, username and password, among other things.  '''
    print("Settings file not found. Generating the file...")
    quality = 0
    while 1 > quality or 4 < quality:
        try:
            print("Select download quality:\n1) Flac 1411 kbps\n2) MP3 320 kbps\n3) Mp3 256 kbps\n4) MP3 128 kbps")
            quality = int(input("Choice: "))
        except ValueError:
            print("Please enter a quality setting\n")
    email, pswd = credentials()
    config = configparser.ConfigParser()
    config['DEFAULT'] = {
            'naming template':'downloads/<Album Artist>/(<Year>) - <Album>/<Disc#>-<Track#> - <Title>',
            'playlist naming template':'downloads/playlists/<Playlist Title>/<Track#> - <Title>',
            'quality':quality,
            'email': email,
            'password':pswd
        }
    while True:
        embedCovers = input("Embed album art to songs? This will increase the filesize significantly (y/n): ").lower().strip()
        if embedCovers[0] == 'y':
            config['DEFAULT']['embed album art'] = 'True'
            break
        if embedCovers[0] == 'n':
            config['DEFAULT']['embed album art'] = 'False'
            break

    with open('settings.ini', 'w') as configfile:
        config.write(configfile)
    print("If you wish to edit any of these settings, you can do so in settings.ini. See the README for more details.")


def singleDownload(link):
    if re.fullmatch(r'(http(|s):\/\/)?(www\.)?(deezer\.com\/(.*?)?)(playlist|artist|album|track|)\/[0-9]*', link) is None:
        print("Not a valid link")
    else:
        downloadDeezer(link)


def batchDownload(queueFile):
    ''' Fetches links from a txt file '''
    try:
        batchFile = open(queueFile, 'r')
    except IOError:
        print("No", queueFile, "file found\n")
    else:
        links = [line.rstrip() for line in batchFile]
        links = list(filter(None, links)) # filters any empty lines
        [downloadDeezer(link) for link in links]


def menu():
    if not os.path.isfile("settings.ini"):
        genSettingsconf()
    if not initDeezerApi(getSetting('email'), bytearray.fromhex(getSetting('password')).decode()): #decode because pswd is encoded in hex in the settings file
        bool = False
        while not bool:
            bool = initDeezerApi(*credentials(retry=True))

    while True:
        print("\nSelect download mode\n1) Single link\n2) All links (Download all links from downloads.txt, one link per line)")
        selectDownloadMode = input("Choice: ")

        if selectDownloadMode == '1':
            while True:
                link = input("Download link: ")
                singleDownload(link)

        elif selectDownloadMode == '2':
            batchDownload('downloads.txt')
        else:
            print("Invalid option.\n")

if __name__ == '__main__':
    print("Thank you for using Deezpy.\nPlease consider supporting the artists!")
    menu()

