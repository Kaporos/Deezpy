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
import hashlib
import json
import random
import re
import os
import sys
import getpass
import base64
import time

# not in standard library:
import requests
import mutagen
from mutagen.easyid3 import EasyID3
from mutagen.mp3 import MP3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def initDeezerApi(email, pswd):
    ''' Inits the Deezer API and handles user login. Four POST requests have to be made.
        The first three are to log in, the last one is to obtain a CSRF token. This function
        is only called once, at the start of the script. '''
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

    req = session.post(
        url     = 'https://www.deezer.com/ajax/gw-light.php',
        headers = httpHeaders,
        params  = unofficialApiQueries
                    )
    res = json.loads(req.text)

    login = session.post(
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

    # Login returns 'success' if it was a successful login, login is not successful if it returns 200
    if login.text == "success":
        print("Login successful"), print("")
    else:
        print("Login failed, wrong Deezer credentials.")
        print("Facebook and family accounts are not supported. If you use one, please create a new account."), print("")
        initDeezerApi(*autoLogin())

    req = session.post(
        url     = 'https://www.deezer.com/ajax/gw-light.php',
        headers = httpHeaders,
        params  = unofficialApiQueries
        )

    # A cross-site request forgery token is needed. It is used as api token in privateApi(id)
    req = session.post(
        url     = 'https://www.deezer.com/ajax/gw-light.php',
        headers = httpHeaders,
        params  = unofficialApiQueries
        )

    res = json.loads(req.text)
    global CSRFToken
    CSRFToken = res['results']['checkForm']


def privateApi(id):
    ''' Get the required info from the unofficial API to decrypt the files '''
    unofficialApiQueries = {
        'api_version' : '1.0',
        'api_token'   : CSRFToken,
        'input'       : '3',
        'method'      : 'deezer.pageTrack'
            }

    req = session.post(
        url     = 'https://www.deezer.com/ajax/gw-light.php',
        headers = httpHeaders,
        params  = unofficialApiQueries,
        json    = {'SNG_ID':id} # the SNG_ID must be encoded in JSON
            )

    res = json.loads(req.text)
    return res['results']['DATA']


def getJSON(type, id, subtype=None):
    ''' Official API. This function is used to download the ID3 tags. Subtype can be 'albums' or 'tracks' '''
    if subtype:
        url = 'https://api.deezer.com/%s/%s/%s?limit=-1' % (type, id, subtype)
    else:
        url = 'https://api.deezer.com/%s/%s/?limit=-1' % (type, id)
    r = session.get(url)
    return json.loads(r.text)


def getInfo(id):
    privateInfo = privateApi(id)
    if "FALLBACK" in privateInfo:
        id = privateInfo["FALLBACK"]['SNG_ID'] # Some songs in a playlist have other IDs than the same song in a album/artist page. These ids from songs in a playlist do not return albInfo properly. The FALLBACK id works, however.
        privateInfo = privateApi(id) # basically, we need to replace the track with the FALLBACK one
    trackInfo = getJSON('track', id)
    albInfo = getJSON(*deezerTypeId(trackInfo['album']['link']))
    #print(albInfo)

    #if the preferred quality is not available, get the one below etc.
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
            r = session.get(url)
            f.write(r.content)
            return r.content
    else:
        with open(imageFile, 'rb') as f:
            return f.read()


def writeTags(filenameFull, trackInfo, albInfo):
    ''' Function to write tags to the file, be it FLAC or MP3 '''
    # retrieve tags
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
            'genre'       : albInfo['genres']['data'][0]['name']
            }
  
    filename, file_extension = os.path.splitext(filenameFull)
    image = getCoverArt(trackInfo['album']['cover_xl'], filename) # downloads the image in the folder
    handle = mutagen.File(filenameFull)
    if type(handle) is mutagen.flac.FLAC:
        for key, val in list(handle.tags.items()):
            del handle[key]
        for key, val in tags.items():
            handle[key] = str(val)
        if getSetting('embed covers'):
            pic = mutagen.flac.Picture()
            pic.data = image
            handle.clear_pictures()
            handle.add_picture(pic)

    elif type(handle) is mutagen.mp3.MP3:
        handle = MP3(filenameFull, ID3=EasyID3)
        EasyID3.RegisterTextKey("totaltracks", "TRCK") # total tracks and label are not supported by easyID3, so we add them
        EasyID3.RegisterTextKey("label", "TPUB")
        tags['tracknumber'] = str(tags['tracknumber']) + '/' + str(tags['totaltracks']) # tracknumber and total tracks is one tag for ID3
        del tags['totaltracks']
        for key, val in tags.items():
            handle[key] = str(val)
        if getSetting('embed covers'):
            handle.tags.add(mutagen.id3.APIC(data=image))
    else:
        print("Could not write tags. File extension not supported.")
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
    pathspec = getSetting('path specification')
    # Dictionary to replace pathspec with
    replacedict = {
                '%ALBUM ARTIST%' : albInfo['artist']['name'],
                '%ALBUM%'        : trackInfo['album']['title'],
                '%YEAR%'         : trackInfo['album']['release_date'],
                '%TRACK%'        : '%02d' % trackInfo['track_position'],
                '%DISC%'         : '%d' % trackInfo['disk_number'],
                '%TITLE%'        : trackInfo['title']
                }

    if playlistInfo:
        pathspec = getSetting('playlist path specification')
        replacedict = {
                '%PLAYLIST TITLE%' : playlistInfo[0]['title'],
                '%TRACK%'          : playlistInfo[1],
                '%TITLE%'          : trackInfo['title']
                }
    # Regex that removes anything that is not an alphanumeric, space, dash, underscore, dot or parentheses for every tag. It is now a valid filename
    for key,val in replacedict.items():
        replacedict[key] = re.sub(r'(?u)[^-\w.( )]', '', val)

    # Replace pathspec with desired tags
    filename = multireplace(pathspec, replacedict)
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
    cdn = "%x" % random.randint(0, 15)
    url = 'https://e-cdns-proxy-' + cdn + '.dzcdn.net/mobile/1/' + step3
    return url


def deezerTypeId(url):
    ''' Returns type ID from a URL'''
    return url.split('/')[-2:]


def downloadTrack(filenameFull, privateInfo, quality):
    filename, file_extension = os.path.splitext(filenameFull)
    # Stream file
    print("Dowloading " + filenameFull + "...")
    url = getTrackDownloadUrl(privateInfo, quality)
    r = session.get(url, stream = True)
    bfKey = getBlowfishKey(privateInfo['SNG_ID'])

    # Decrypt content and write to file
    with open(filename + '.tmp', 'wb') as fd: #tmp file to prevent incomplete music files if the users exits while writing
        i = 0
        # Only every third 2048 byte block is encrypted.
        for chunk in r.iter_content(2048):
            if i % 3 > 0 or len(chunk) < 2048:
                fd.write(chunk)
            else:
                cipher = Cipher(algorithms.Blowfish((bfKey)), modes.CBC(bytes([i for i in range(8)])), default_backend())
                decryptor = cipher.decryptor()

                decdata = decryptor.update(chunk) + decryptor.finalize()
                fd.write(decdata)
            if len(chunk) < 2048:
                break
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
    ''' Calls the necessary functions to download and tag the tracks. playlist must be a tuple of (playlistInfo, playlistTrack) '''
    trackInfo, albInfo, privateInfo, quality = getInfo(id)
    if trackInfo['readable'] == False:
        print("Song", trackInfo['title'], "not available, skipping...") # TODO find a way to try to find an alternative (available) song
        return False

    if playlist: # puts some playlist info into existing info, it's a bit of a hack, I know.
        albInfo['nb_tracks'] = playlist[0]['nb_tracks']
        trackInfo['album']['cover_xl'] = playlist[0]['picture_xl']

    if quality == '9':
        ext = '.flac'
    else:
        ext = '.mp3'
    filenameFull = nameFile(trackInfo,albInfo,playlist) + ext

    if makePath(filenameFull) == False:
        print(filenameFull + " already exists!")
        return False

    downloadTrack(filenameFull, privateInfo, quality)
    writeTags(filenameFull, trackInfo, albInfo)
    print("Done!")
    time.sleep(1)


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
            playlist = (playlistInfo, str(playlistTrack))
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


def getSetting(option):
    ''' Returns a setting from settings.conf. If the setting is not found, return False '''
    with open('settings.json', 'r') as conf:
        conf = json.load(conf)
        try:
            value = conf[option]
        except:
            return False
    return value


def setSetting(option, value):
    ''' Writes an option to the config file '''
    with open('settings.json', 'r') as conf:
        confEdit = json.load(conf)

    confEdit[option] = value

    with open('settings.json', 'w') as conf:
        json.dump(confEdit, conf, indent=4)


def autoLogin():
    ''' Creates autologin setting in settings.conf '''
    email = input("Deezer email: ")
    pswd = getpass.getpass('Deezer password (input is hidden): ')
    pswd_encoded = base64.b64encode(pswd.encode('utf-8')) # not really secure, but it is recommended to use a throwaway account anyway
    pswd_encoded = pswd_encoded.decode('utf-8')
    setSetting('email', email)
    setSetting('password', pswd_encoded)
    return email, pswd


def genSettingsconf():
    print("Settings file not found. Generating the file...")
    with open("settings.json", 'w') as conf:
        dict = {}
        json.dump(json.loads('{}'), conf)

    print("Setting up download path...")
    pathspec = 'downloads/%ALBUM ARTIST%/(%YEAR%) - %ALBUM%/%DISC%-%TRACK% - %TITLE%'
    setSetting('path specification', pathspec)
    print("Setting up playlist download path...")
    pathspec = 'downloads/playlists/%PLAYLIST TITLE%/%TRACK% - %TITLE%'
    setSetting('playlist path specification', pathspec)

    print("Select download quality:")
    print("1) Flac 1411 kbps")
    print("2) MP3 320 kbps")
    print("3) Mp3 256 kbps")
    print("4) MP3 128 kbps")
    quality = input("Choice: ")

    setSetting('quality', quality)
    autoLogin()
    print("If you wish to edit any of these settings, you can do so now in settings.json. See the README for more details.")


def menu():
    if not os.path.isfile("settings.json"):
        genSettingsconf()

    email = getSetting('email')
    pswd = getSetting('password')
    if not email or not pswd:
        print('No email or password entry found.')
        email, pswd = autoLogin()
    else:
        try:
            pswd = base64.b64decode(pswd).decode('utf-8')
        except:
            print('Could not decode password.')
            autoLogin()
    initDeezerApi(email, pswd) # if the login fails with these credentials, autoLogin() is called again

    while True:
        print("Select download mode")
        print("1) Single link")
        print("2) All links (Download all links from downloads.txt, one link per line)")
        selectDownloadMode = input("Choice: ")

        if selectDownloadMode == '1':
            while True:
                link = input("Download link: ")
                if re.fullmatch(r'(http(|s):\/\/)?(www\.)?(deezer\.com\/(.*?)?)(playlist|artist|album|track|)\/[0-9]*', link) is None:
                    print("Not a valid link")
                else:
                    downloadDeezer(link)

        elif selectDownloadMode == '2':
            try:
                batchFile = open('downloads.txt', 'r')
            except IOError:
                print("No downloads.txt file found")               
            else:
                links = [line.rstrip() for line in batchFile]
                links = list(filter(None, links)) # filters any empty lines
                [downloadDeezer(link) for link in links]
        else:
            print("Invalid option!")
        print('')

session = requests.session()
print("Thank you for using Deezpy!")
print("Please consider supporting the artists!")
print('')
menu()
